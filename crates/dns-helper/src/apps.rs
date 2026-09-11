//! Launching apps into the tunnel slice, including Flatpak apps.
//!
//! Native apps are simple: start them in a scope inside the slice and their
//! children inherit it. Flatpak is not: `flatpak run` moves itself into its
//! own `app-flatpak-<id>-<n>.scope` under `app.slice` before starting the app,
//! which would take it straight back out of the tunnel.
//!
//! The fix needs no root. The whole `user@<uid>.service` cgroup subtree is
//! delegated to the user, so right after launch we move every process in the
//! Flatpak's scope into a delegated holding scope inside the tunnel slice.
//! Processes forked afterwards inherit the new cgroup.
//!
//! One limit: a socket keeps the cgroup it was created in. Flatpak moves
//! itself before it starts the app, and we sweep within milliseconds of the
//! scope appearing, so the app has normally opened nothing by then — but the
//! exit-IP check is the thing to trust, not this comment.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::tunnel::SLICE;

/// `/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service`
pub fn user_service_cgroup(uid: u32) -> PathBuf {
    PathBuf::from(format!(
        "/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service"
    ))
}

/// If `command args` is a `flatpak run` invocation, the application ID.
pub fn flatpak_app_id(command: &str, args: &[String]) -> Option<String> {
    let program = command.rsplit('/').next().unwrap_or(command);
    if program != "flatpak" {
        return None;
    }
    let mut it = args.iter().skip_while(|a| a.as_str() != "run").skip(1);
    // First non-option argument after `run` is the app ID. Options that take
    // a separate value are rare in launch commands; `--opt=value` is handled.
    it.find(|a| !a.starts_with('-')).cloned()
}

/// Systemd unit name of the holding scope for an app. Only characters that
/// are safe in unit names are kept.
pub fn hold_unit(app_name: &str) -> String {
    let slug: String = app_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' })
        .collect();
    format!("detour-hold-{slug}.scope")
}

pub fn hold_cgroup(base: &Path, app_name: &str) -> PathBuf {
    base.join(SLICE).join(hold_unit(app_name))
}

/// All `app-flatpak-<id>-*.scope` cgroups currently under `app.slice`.
pub fn flatpak_scopes(base: &Path, app_id: &str) -> Vec<PathBuf> {
    let prefix = format!("app-flatpak-{app_id}-");
    std::fs::read_dir(base.join("app.slice"))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n.starts_with(&prefix) && n.ends_with(".scope")
        })
        .map(|e| e.path())
        .collect()
}

pub fn procs(cgroup: &Path) -> Vec<u32> {
    std::fs::read_to_string(cgroup.join("cgroup.procs"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}

/// Move every process in `from` into `to`. Returns how many moved. A process
/// that exits mid-move is not an error.
pub fn migrate(from: &Path, to: &Path) -> std::io::Result<usize> {
    let target = to.join("cgroup.procs");
    let mut moved = 0;
    for pid in procs(from) {
        match std::fs::write(&target, pid.to_string()) {
            Ok(()) => moved += 1,
            // ESRCH: the process is already gone.
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(moved)
}

/// Sweep Flatpak scopes for `app_id` into `hold` until the app's processes
/// have been captured and nothing new has appeared for `settle`. Returns the
/// number of processes moved.
pub fn capture_flatpak(
    base: &Path,
    app_id: &str,
    hold: &Path,
    timeout: Duration,
    settle: Duration,
) -> std::io::Result<usize> {
    let start = Instant::now();
    let mut moved = 0;
    let mut last_move: Option<Instant> = None;

    while start.elapsed() < timeout {
        let mut this_round = 0;
        for scope in flatpak_scopes(base, app_id) {
            this_round += migrate(&scope, hold)?;
        }
        if this_round > 0 {
            moved += this_round;
            last_move = Some(Instant::now());
        }
        if last_move.is_some_and(|t| t.elapsed() >= settle) {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(moved)
}

/// Where an app currently runs, for the GUI.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Presence {
    pub inside: bool,
    pub outside: bool,
}

/// Flatpak presence: outside = any of its own scopes still holds processes;
/// inside = the holding scope holds more than its placeholder process.
pub fn flatpak_presence(base: &Path, app_name: &str, app_id: &str) -> Presence {
    let outside = flatpak_scopes(base, app_id).iter().any(|s| !procs(s).is_empty());
    let hold = hold_cgroup(base, app_name);
    let inside = procs(&hold)
        .iter()
        .any(|pid| comm(*pid).as_deref() != Some("sleep"));
    Presence { inside, outside }
}

fn comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Holding scopes whose only process is the placeholder: the app has exited,
/// so the scope can be stopped without killing anything.
pub fn idle_holds(base: &Path) -> Vec<String> {
    std::fs::read_dir(base.join(SLICE))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.starts_with("detour-hold-") {
                return None;
            }
            let p = procs(&e.path());
            let only_placeholder =
                p.iter().all(|pid| comm(*pid).as_deref() == Some("sleep"));
            only_placeholder.then_some(name)
        })
        .collect()
}

/* ------------------------------------------------ moving a running app */

/// Parent PID from the contents of `/proc/<pid>/stat`. The command name is
/// parenthesised and may itself contain spaces or parentheses, so parse from
/// the last `)`.
pub fn parse_ppid(stat: &str) -> Option<u32> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?;
    fields.next()?.parse().ok()
}

/// `roots` plus every descendant, from a snapshot of (pid, ppid) pairs.
pub fn descendants(roots: &[u32], table: &[(u32, u32)]) -> Vec<u32> {
    let mut out: Vec<u32> = roots.to_vec();
    let mut i = 0;
    while i < out.len() {
        let parent = out[i];
        for &(pid, ppid) in table {
            if ppid == parent && !out.contains(&pid) {
                out.push(pid);
            }
        }
        i += 1;
    }
    out
}

/// Snapshot of every process's parent, read from `/proc`.
pub fn process_table() -> Vec<(u32, u32)> {
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let pid: u32 = e.file_name().to_str()?.parse().ok()?;
            let stat = std::fs::read_to_string(e.path().join("stat")).ok()?;
            Some((pid, parse_ppid(&stat)?))
        })
        .collect()
}

/// Real UID of a process, from `/proc/<pid>/status`.
pub fn process_uid(pid: u32) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// One socket from `ss -tunpH` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEntry {
    /// `tcp` or `udp`.
    pub proto: String,
    pub local: std::net::SocketAddr,
    pub peer: std::net::SocketAddr,
    pub pids: Vec<u32>,
}

fn parse_sockaddr(s: &str) -> Option<std::net::SocketAddr> {
    // ss prints IPv6 as [addr]:port and may append %iface to the address.
    let (addr, port) = s.rsplit_once(':')?;
    let addr = addr.trim_start_matches('[').trim_end_matches(']');
    let addr = addr.split('%').next()?;
    Some(std::net::SocketAddr::new(addr.parse().ok()?, port.parse().ok()?))
}

/// Parse a line of `ss -tunpH`. Unconnected sockets (peer `*`) yield `None`.
pub fn parse_ss_line(line: &str) -> Option<SocketEntry> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 7 {
        return None;
    }
    let proto = cols[0].to_string();
    if proto != "tcp" && proto != "udp" {
        return None;
    }
    let local = parse_sockaddr(cols[4])?;
    let peer = parse_sockaddr(cols[5])?;
    let users = cols[6..].join(" ");
    let pids = users
        .split("pid=")
        .skip(1)
        .filter_map(|p| p.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok())
        .collect();
    Some(SocketEntry { proto, local, peer, pids })
}

/// Whether a destination is local or private, i.e. never tunnelled and so
/// not worth resetting.
pub fn is_local_destination(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// `ss` filter selecting exactly one socket.
pub fn ss_kill_filter(sock: &SocketEntry) -> String {
    let fmt = |a: &std::net::SocketAddr| match a {
        std::net::SocketAddr::V4(v) => format!("{}:{}", v.ip(), v.port()),
        std::net::SocketAddr::V6(v) => format!("[{}]:{}", v.ip(), v.port()),
    };
    format!("src {} and dst {}", fmt(&sock.local), fmt(&sock.peer))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn detects_flatpak_app_id() {
        assert_eq!(
            flatpak_app_id("flatpak", &s(&["run", "com.heroicgameslauncher.hgl"])).as_deref(),
            Some("com.heroicgameslauncher.hgl")
        );
        assert_eq!(
            flatpak_app_id("/usr/bin/flatpak", &s(&["run", "--branch=stable", "org.x.App", "--arg"]))
                .as_deref(),
            Some("org.x.App")
        );
    }

    #[test]
    fn native_commands_are_not_flatpak() {
        assert!(flatpak_app_id("brave", &[]).is_none());
        assert!(flatpak_app_id("flatpak", &s(&["list"])).is_none());
    }

    #[test]
    fn hold_unit_names_are_safe() {
        assert_eq!(hold_unit("Heroic Games"), "detour-hold-heroic_games.scope");
        assert!(!hold_unit("a/b..c").contains('/'));
    }

    /// A fake cgroup tree: cgroup.procs is a plain file, so writes append.
    fn fake_tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("app.slice");
        std::fs::create_dir_all(app.join("app-flatpak-org.x.App-123.scope")).unwrap();
        std::fs::create_dir_all(app.join("app-flatpak-org.other-9.scope")).unwrap();
        std::fs::create_dir_all(app.join("app-org.x.App-1.scope")).unwrap();
        dir
    }

    #[test]
    fn finds_only_the_matching_flatpak_scopes() {
        let t = fake_tree();
        let found = flatpak_scopes(t.path(), "org.x.App");
        assert_eq!(found.len(), 1);
        assert!(found[0].ends_with("app-flatpak-org.x.App-123.scope"));
    }

    #[test]
    fn missing_app_slice_yields_nothing() {
        let t = tempfile::tempdir().unwrap();
        assert!(flatpak_scopes(t.path(), "org.x.App").is_empty());
    }

    #[test]
    fn procs_parses_cgroup_procs() {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join("cgroup.procs"), "10\n20\n\n").unwrap();
        assert_eq!(procs(t.path()), vec![10, 20]);
        assert!(procs(&t.path().join("absent")).is_empty());
    }

    #[test]
    fn ppid_survives_awkward_command_names() {
        assert_eq!(parse_ppid("123 (brave) S 45 123 123 0"), Some(45));
        assert_eq!(parse_ppid("9 (a (b) c) R 7 9 9"), Some(7));
        assert_eq!(parse_ppid("garbage"), None);
    }

    #[test]
    fn descendants_walks_the_whole_tree_only() {
        let table = [(1, 0), (10, 1), (11, 10), (12, 11), (20, 1), (13, 10)];
        let mut got = descendants(&[10], &table);
        got.sort();
        assert_eq!(got, vec![10, 11, 12, 13]);
    }

    #[test]
    fn parses_ss_tcp_line_with_multiple_owners() {
        let line = r#"tcp   ESTAB 0      0      10.100.33.202:43210   142.251.151.4:443   users:(("brave",pid=4778,fd=33),("brave",pid=4800,fd=12))"#;
        let s = parse_ss_line(line).unwrap();
        assert_eq!(s.proto, "tcp");
        assert_eq!(s.peer.to_string(), "142.251.151.4:443");
        assert_eq!(s.pids, vec![4778, 4800]);
    }

    #[test]
    fn parses_ss_ipv6_line() {
        let line = r#"udp   ESTAB 0 0 [2001:db8::1]:5000 [2404:6800:4007::200e]:443 users:(("brave",pid=7,fd=3))"#;
        let s = parse_ss_line(line).unwrap();
        assert_eq!(s.peer.port(), 443);
        assert!(s.local.is_ipv6());
    }

    #[test]
    fn unconnected_sockets_are_skipped() {
        let line = r#"udp   UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:(("brave",pid=7,fd=3))"#;
        assert!(parse_ss_line(line).is_none());
    }

    #[test]
    fn local_destinations_are_recognised() {
        for ip in ["127.0.0.53", "10.100.32.1", "192.168.1.5", "100.64.0.1", "fe80::1", "fd00::1", "::1"] {
            assert!(is_local_destination(&ip.parse().unwrap()), "{ip}");
        }
        for ip in ["142.251.151.4", "2404:6800:4007::200e"] {
            assert!(!is_local_destination(&ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn kill_filter_targets_one_socket() {
        let s = parse_ss_line(r#"tcp ESTAB 0 0 10.0.0.2:5000 1.2.3.4:443 users:(("x",pid=1,fd=3))"#).unwrap();
        assert_eq!(ss_kill_filter(&s), "src 10.0.0.2:5000 and dst 1.2.3.4:443");
        let s = parse_ss_line(r#"tcp ESTAB 0 0 [fd00::2]:5000 [2001:db8::9]:443 users:(("x",pid=1,fd=3))"#).unwrap();
        assert_eq!(ss_kill_filter(&s), "src [fd00::2]:5000 and dst [2001:db8::9]:443");
    }
}
