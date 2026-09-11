//! Per-app transparent redirection into the filter-bypass proxy.
//!
//! The HTTP-proxy form of the bypass only helps apps that have a proxy
//! setting (browsers). To cover *any* app, the app's outbound HTTPS is
//! redirected into the local fragmenting proxy by an nftables rule matching
//! the app's cgroup — the same per-app mechanism the WireGuard tunnel uses,
//! so "which apps" is decided the same way in both.
//!
//! Only TCP port 443 from that cgroup is touched. Everything else on the
//! machine, and every other port of the same app, is left alone. The proxy
//! recovers the real destination via `SO_ORIGINAL_DST`.
//!
//! State lives entirely in the kernel: teardown is idempotent and a reboot
//! clears it.

use crate::tunnel::{slice_cgroup, Step, SLICE};

pub const NFT_TABLE: &str = "detour_filter";

/// Destinations never redirected: loopback (the proxy itself lives there, and
/// redirecting it would loop), plus private ranges, which no external filter
/// sees anyway.
const BYPASS_V4: &[&str] = &[
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
];

/// nftables ruleset redirecting the tunnel slice's HTTPS to `port`.
pub fn nft_ruleset(uid: u32, port: u16) -> String {
    let (cgroup, level) = slice_cgroup(uid);
    format!(
        "table ip {NFT_TABLE} {{\n\
         \tchain output {{\n\
         \t\ttype nat hook output priority dstnat; policy accept;\n\
         \t\tip daddr {{ {v4} }} return\n\
         \t\tmeta l4proto tcp socket cgroupv2 level {level} \"{cgroup}\" \
         tcp dport 443 redirect to :{port}\n\
         \t}}\n\
         }}\n",
        v4 = BYPASS_V4.join(", "),
    )
}

/// Commands installing the redirect. `nft_path` is a file already written
/// with [`nft_ruleset`].
pub fn up_steps(nft_path: &str) -> Vec<Step> {
    vec![Step { argv: vec!["nft".into(), "-f".into(), nft_path.into()], optional: false }]
}

/// Commands removing it. Tolerates "already gone".
pub fn down_steps() -> Vec<Step> {
    vec![Step {
        argv: ["nft", "delete", "table", "ip", NFT_TABLE]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        optional: true,
    }]
}

/// Whether the redirect table is currently installed. Needs root to check, so
/// the GUI infers state from its own start/stop instead.
pub fn table_name() -> &'static str {
    NFT_TABLE
}

/// The slice whose apps are redirected — the same one the tunnel uses.
pub fn slice() -> &'static str {
    SLICE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects_only_the_slice_and_only_https() {
        let r = nft_ruleset(1000, 8088);
        assert!(r.contains("socket cgroupv2 level 4 \"user.slice/user-1000.slice/user@1000.service/detourtunnel.slice\""));
        assert!(r.contains("tcp dport 443"));
        assert!(r.contains("redirect to :8088"));
    }

    #[test]
    fn loopback_is_exempt_before_the_redirect_rule() {
        // Redirecting loopback would send the proxy's own traffic back into
        // itself; the exemption must be evaluated first.
        let r = nft_ruleset(1000, 8088);
        let exempt = r.find("ip daddr").expect("exemption present");
        let redirect = r.find("redirect to").expect("redirect present");
        assert!(exempt < redirect);
        assert!(r.contains("127.0.0.0/8"));
    }

    #[test]
    fn uses_a_separate_table_from_the_tunnel() {
        // The tunnel and the filter bypass must be independently removable.
        assert_ne!(NFT_TABLE, crate::tunnel::NFT_TABLE);
    }

    #[test]
    fn teardown_is_best_effort() {
        assert!(down_steps().iter().all(|s| s.optional));
    }

    #[test]
    fn install_is_required_not_optional() {
        assert!(up_steps("/tmp/x.nft").iter().all(|s| !s.optional));
    }
}
