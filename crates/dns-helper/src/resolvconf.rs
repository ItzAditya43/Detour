//! Crash-safe takeover of `/etc/resolv.conf`.
//!
//! Invariants, in priority order:
//!
//! 1. The system is never left without a working resolver. Every write is
//!    atomic (temp file + `rename`), so a crash mid-write leaves the previous
//!    file fully intact rather than a truncated one.
//! 2. Original contents are backed up *and fsynced* before `/etc/resolv.conf`
//!    is touched at all.
//! 3. A crashed run is detected and undone on next startup, by recording our
//!    PID in a state file and checking whether that process still lives.
//!
//! On this system NetworkManager owns `resolv.conf` and will rewrite it on any
//! connection change, so takeover also drops in a `dns=none` config fragment
//! and removes it on restore.

use std::fs;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const RESOLV_CONF: &str = "/etc/resolv.conf";
pub const STATE_DIR: &str = "/var/lib/detour";
pub const NM_DROPIN: &str = "/etc/NetworkManager/conf.d/00-detour.conf";

const NM_DROPIN_BODY: &str = "# Written by Detour while Detour DNS protection is active.\n\
                              # Removed automatically when protection is turned off.\n\
                              [main]\n\
                              dns=none\n\
                              rc-manager=unmanaged\n";

#[derive(Debug, thiserror::Error)]
pub enum ResolvError {
    #[error("insufficient privileges to modify {path} (need root)")]
    Denied { path: String },
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("state file at {0} is corrupt and cannot be parsed; refusing to guess")]
    CorruptState(String),
    #[error("DNS is already under our control (pid {0} is still running)")]
    AlreadyActive(u32),
    #[error("no backup found; nothing to restore")]
    NoBackup,
}

fn io_err(path: impl AsRef<Path>, source: std::io::Error) -> ResolvError {
    let path = path.as_ref().display().to_string();
    if source.kind() == std::io::ErrorKind::PermissionDenied {
        ResolvError::Denied { path }
    } else {
        ResolvError::Io { path, source }
    }
}

/// What we recorded when taking over, used to restore and to detect crashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverState {
    /// PID of the helper that performed the takeover.
    pub pid: u32,
    /// Unix timestamp of the takeover.
    pub taken_over_at: u64,
    /// Nameservers read from the original file, used for local-name forwarding.
    pub original_nameservers: Vec<IpAddr>,
    /// If the original `resolv.conf` was a symlink, its target, so restore
    /// recreates the link rather than leaving a regular file behind.
    pub original_symlink_target: Option<PathBuf>,
    /// Whether we created the NetworkManager drop-in (so restore only removes
    /// a file we actually put there).
    pub wrote_nm_dropin: bool,
}

pub struct ResolvManager {
    resolv_path: PathBuf,
    state_dir: PathBuf,
    nm_dropin: PathBuf,
}

impl Default for ResolvManager {
    fn default() -> Self {
        Self::new(RESOLV_CONF, STATE_DIR, NM_DROPIN)
    }
}

impl ResolvManager {
    pub fn new(
        resolv: impl Into<PathBuf>,
        state_dir: impl Into<PathBuf>,
        nm_dropin: impl Into<PathBuf>,
    ) -> Self {
        Self {
            resolv_path: resolv.into(),
            state_dir: state_dir.into(),
            nm_dropin: nm_dropin.into(),
        }
    }

    fn backup_path(&self) -> PathBuf {
        self.state_dir.join("resolv.conf.backup")
    }

    fn state_path(&self) -> PathBuf {
        self.state_dir.join("state.json")
    }

    pub fn read_state(&self) -> Result<Option<TakeoverState>, ResolvError> {
        let path = self.state_path();
        match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)
                .map(Some)
                .map_err(|_| ResolvError::CorruptState(path.display().to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err(&path, e)),
        }
    }

    /// True when a takeover is recorded *and* the recording process is alive.
    pub fn is_active(&self) -> Result<bool, ResolvError> {
        Ok(self
            .read_state()?
            .is_some_and(|s| process_is_alive(s.pid)))
    }

    /// Undo a takeover left behind by a process that died without cleaning up.
    ///
    /// Call this at startup, before anything else. Returns the recovered state
    /// if a crash was found and undone.
    pub fn reconcile_after_crash(&self) -> Result<Option<TakeoverState>, ResolvError> {
        let Some(state) = self.read_state()? else {
            return Ok(None);
        };

        if process_is_alive(state.pid) {
            return Err(ResolvError::AlreadyActive(state.pid));
        }

        tracing::warn!(
            pid = state.pid,
            "found DNS takeover from a process that is no longer running; restoring"
        );
        self.restore()?;
        Ok(Some(state))
    }

    /// Parse the nameservers currently listed in `resolv.conf`.
    pub fn current_nameservers(&self) -> Result<Vec<IpAddr>, ResolvError> {
        let text = fs::read_to_string(&self.resolv_path)
            .map_err(|e| io_err(&self.resolv_path, e))?;
        Ok(parse_nameservers(&text))
    }

    /// Point `/etc/resolv.conf` at `listen_addr`, backing up the original first.
    pub fn take_over(&self, listen_addr: IpAddr) -> Result<TakeoverState, ResolvError> {
        if let Some(existing) = self.read_state()? {
            if process_is_alive(existing.pid) {
                return Err(ResolvError::AlreadyActive(existing.pid));
            }
            // Stale state from a crash; undo it before taking over afresh.
            self.restore()?;
        }

        fs::create_dir_all(&self.state_dir).map_err(|e| io_err(&self.state_dir, e))?;

        let symlink_target = fs::symlink_metadata(&self.resolv_path)
            .ok()
            .filter(|m| m.file_type().is_symlink())
            .and_then(|_| fs::read_link(&self.resolv_path).ok());

        let original = fs::read_to_string(&self.resolv_path)
            .map_err(|e| io_err(&self.resolv_path, e))?;
        let nameservers = parse_nameservers(&original);

        // Back up and fsync BEFORE modifying anything, so the original is
        // durable on disk even if we lose power in the next instruction.
        write_atomic(&self.backup_path(), original.as_bytes(), 0o600)?;

        let wrote_nm_dropin = self.write_nm_dropin()?;

        let state = TakeoverState {
            pid: std::process::id(),
            taken_over_at: now_secs(),
            original_nameservers: nameservers,
            original_symlink_target: symlink_target,
            wrote_nm_dropin,
        };
        let encoded = serde_json::to_vec_pretty(&state).expect("state serialises");
        write_atomic(&self.state_path(), &encoded, 0o600)?;

        // Only now is it safe to redirect resolution.
        let body = format!(
            "# Managed by Detour. The original file is backed up at\n\
             # {}\n\
             # and is restored automatically when DNS protection is turned off.\n\
             nameserver {listen_addr}\n\
             options edns0 trust-ad\n",
            self.backup_path().display()
        );
        write_atomic(&self.resolv_path, body.as_bytes(), 0o644)?;

        tracing::info!(%listen_addr, "resolv.conf now points at the local proxy");
        Ok(state)
    }

    /// Put the original `resolv.conf` back and clear our state.
    ///
    /// Safe to call when no takeover is active, and safe to call twice.
    pub fn restore(&self) -> Result<(), ResolvError> {
        let backup = self.backup_path();
        if !backup.exists() {
            // Nothing was ever taken over; make sure no stale state lingers.
            let _ = fs::remove_file(self.state_path());
            return Err(ResolvError::NoBackup);
        }

        let state = self.read_state().ok().flatten();
        let contents = fs::read(&backup).map_err(|e| io_err(&backup, e))?;

        if let Some(target) = state.as_ref().and_then(|s| s.original_symlink_target.clone()) {
            // Recreate the symlink exactly as it was.
            let _ = fs::remove_file(&self.resolv_path);
            std::os::unix::fs::symlink(&target, &self.resolv_path)
                .map_err(|e| io_err(&self.resolv_path, e))?;
        } else {
            write_atomic(&self.resolv_path, &contents, 0o644)?;
        }

        if state.as_ref().is_none_or(|s| s.wrote_nm_dropin) {
            if let Err(e) = fs::remove_file(&self.nm_dropin) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(path = %self.nm_dropin.display(), error = %e,
                        "could not remove NetworkManager drop-in");
                }
            }
        }

        let _ = fs::remove_file(self.state_path());
        let _ = fs::remove_file(&backup);

        tracing::info!("resolv.conf restored to its original contents");
        Ok(())
    }

    /// Stop NetworkManager rewriting `resolv.conf` underneath us. Returns
    /// whether a file was created (false if one was already there, which we
    /// must not delete on restore).
    fn write_nm_dropin(&self) -> Result<bool, ResolvError> {
        let Some(parent) = self.nm_dropin.parent() else {
            return Ok(false);
        };
        if !parent.is_dir() {
            // No NetworkManager on this system; nothing to suppress.
            return Ok(false);
        }
        if self.nm_dropin.exists() {
            return Ok(false);
        }
        write_atomic(&self.nm_dropin, NM_DROPIN_BODY.as_bytes(), 0o644)?;
        Ok(true)
    }
}

/// Write `contents` to `path` atomically: full write and fsync to a temporary
/// file in the same directory, then `rename` over the target. A reader either
/// sees the old file or the new one, never a partial write.
fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<(), ResolvError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    let tmp = parent.join(format!(
        ".{}.detour.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("tmp")
    ));

    {
        let mut file = fs::File::create(&tmp).map_err(|e| io_err(&tmp, e))?;
        file.write_all(contents).map_err(|e| io_err(&tmp, e))?;
        file.sync_all().map_err(|e| io_err(&tmp, e))?;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|e| io_err(&tmp, e))?;
    }

    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io_err(path, e)
    })?;

    // Also sync the directory, so the rename itself survives a power loss.
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Extract `nameserver` entries, skipping any that point back at our own proxy
/// (which would be an infinite loop if a stale file were ever read as original).
pub fn parse_nameservers(text: &str) -> Vec<IpAddr> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && !l.starts_with(';'))
        .filter_map(|l| l.strip_prefix("nameserver"))
        .filter_map(|rest| rest.trim().split_whitespace().next())
        .filter_map(|addr| addr.split('%').next().unwrap_or(addr).parse::<IpAddr>().ok())
        .filter(|ip| !is_our_proxy(ip))
        .collect()
}

/// The loopback alias the proxy binds. Excluded from upstream lists so we can
/// never forward a query to ourselves.
pub const PROXY_ADDR: &str = "127.0.0.53";

fn is_our_proxy(ip: &IpAddr) -> bool {
    ip.to_string() == PROXY_ADDR
}

/// Pair nameservers with port 53.
pub fn to_socket_addrs(servers: &[IpAddr]) -> Vec<SocketAddr> {
    servers.iter().map(|ip| SocketAddr::new(*ip, 53)).collect()
}

fn process_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // Signal 0 performs error checking without delivering anything.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nameservers() {
        let text = "# comment\nnameserver 8.8.8.8\nnameserver 8.8.4.4\noptions edns0\n";
        assert_eq!(
            parse_nameservers(text),
            vec![
                "8.8.8.8".parse::<IpAddr>().unwrap(),
                "8.8.4.4".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn ignores_comments_and_junk() {
        let text = "; semicolon comment\n#nameserver 1.2.3.4\nsearch example.com\nnameserver bogus\nnameserver 9.9.9.9\n";
        assert_eq!(parse_nameservers(text), vec!["9.9.9.9".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn parses_ipv6_and_strips_zone_index() {
        let text = "nameserver 2001:4860:4860::8888\nnameserver fe80::1%wlan0\n";
        let got = parse_nameservers(text);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].to_string(), "2001:4860:4860::8888");
        assert_eq!(got[1].to_string(), "fe80::1");
    }

    #[test]
    fn never_returns_our_own_proxy_as_upstream() {
        // Guards the loop: reading a file we wrote must not yield ourselves.
        let text = "nameserver 127.0.0.53\nnameserver 8.8.8.8\n";
        assert_eq!(parse_nameservers(text), vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn socket_addrs_use_port_53() {
        let addrs = to_socket_addrs(&["1.1.1.1".parse().unwrap()]);
        assert_eq!(addrs[0].to_string(), "1.1.1.1:53");
    }

    #[test]
    fn current_pid_is_alive_and_pid_zero_is_not() {
        assert!(process_is_alive(std::process::id()));
        assert!(!process_is_alive(0));
    }
}
