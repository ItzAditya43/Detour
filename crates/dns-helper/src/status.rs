//! Live status snapshot shared with the unprivileged GUI.
//!
//! The helper runs as root and the GUI does not, so rather than inventing an
//! IPC protocol and its permission model, the helper periodically writes a
//! world-readable JSON snapshot. The GUI only ever reads it, which keeps the
//! privilege boundary one-directional: nothing the GUI does can drive the
//! privileged process through this file.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::proxy::{QueryLog, QueryLogEntry};

pub const STATUS_PATH: &str = "/var/lib/detour/status.json";
const WRITE_INTERVAL: Duration = Duration::from_millis(750);
/// Entries included per snapshot. Enough to fill the UI's log panel without
/// rewriting a large file twice a second.
const LOG_SLICE: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub active: bool,
    pub listen: String,
    pub pid: u32,
    /// Whether `/etc/resolv.conf` is currently pointed at us.
    pub took_over_resolv_conf: bool,
    pub profile: Option<String>,
    pub providers: Vec<String>,
    pub forced_domains: Vec<String>,
    pub upstreams: Vec<String>,
    pub cache_entries: usize,
    pub queries_total: u64,
    pub recent: Vec<QueryLogEntry>,
    pub updated_at: u64,
}

impl Snapshot {
    /// What the GUI shows when the helper is not running at all.
    pub fn inactive() -> Self {
        Self {
            active: false,
            listen: String::new(),
            pid: 0,
            took_over_resolv_conf: false,
            profile: None,
            providers: Vec::new(),
            forced_domains: Vec::new(),
            upstreams: Vec::new(),
            cache_entries: 0,
            queries_total: 0,
            recent: Vec::new(),
            updated_at: 0,
        }
    }
}

/// Immutable facts about this run, combined with live counters at write time.
pub struct StatusWriter {
    path: PathBuf,
    base: Snapshot,
    log: Arc<QueryLog>,
    cache: Arc<std::sync::Mutex<dns_core::cache::Cache>>,
}

impl StatusWriter {
    pub fn new(
        path: impl Into<PathBuf>,
        base: Snapshot,
        log: Arc<QueryLog>,
        cache: Arc<std::sync::Mutex<dns_core::cache::Cache>>,
    ) -> Self {
        Self { path: path.into(), base, log, cache }
    }

    pub fn snapshot(&self) -> Snapshot {
        let mut snap = self.base.clone();
        snap.recent = self.log.recent(LOG_SLICE);
        snap.queries_total = self.log.total();
        snap.cache_entries = self.cache.lock().map(|c| c.len()).unwrap_or(0);
        snap.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        snap
    }

    pub fn write_once(&self) -> std::io::Result<()> {
        write_snapshot(&self.path, &self.snapshot())
    }

    /// Refresh the snapshot on a timer until the task is dropped.
    pub async fn run(self) {
        loop {
            if let Err(e) = self.write_once() {
                tracing::debug!(path = %self.path.display(), error = %e, "status write failed");
            }
            tokio::time::sleep(WRITE_INTERVAL).await;
        }
    }
}

fn write_snapshot(path: &Path, snapshot: &Snapshot) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&serde_json::to_vec(snapshot)?)?;
        // World-readable: the GUI runs as the desktop user, not root.
        file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    std::fs::rename(&tmp, path)
}

/// Read the snapshot, treating a missing or stale file as "not running".
///
/// Staleness matters: if the helper is killed with SIGKILL the file survives,
/// and reporting protection as active when it is not would be the worst
/// possible lie for this UI to tell.
pub fn read_snapshot(path: &Path, max_age: Duration) -> Snapshot {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Snapshot::inactive();
    };
    let Ok(snapshot) = serde_json::from_str::<Snapshot>(&text) else {
        return Snapshot::inactive();
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.saturating_sub(snapshot.updated_at) > max_age.as_secs() {
        return Snapshot::inactive();
    }
    snapshot
}

/// Remove the snapshot on clean shutdown.
pub fn clear(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(updated_at: u64) -> Snapshot {
        let mut s = Snapshot::inactive();
        s.active = true;
        s.listen = "127.0.0.53:53".into();
        s.updated_at = updated_at;
        s
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn round_trips_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("status.json");
        write_snapshot(&path, &sample(now())).unwrap();

        let read = read_snapshot(&path, Duration::from_secs(5));
        assert!(read.active);
        assert_eq!(read.listen, "127.0.0.53:53");
    }

    #[test]
    fn missing_file_reads_as_inactive() {
        let snap = read_snapshot(Path::new("/nonexistent/status.json"), Duration::from_secs(5));
        assert!(!snap.active);
    }

    #[test]
    fn corrupt_file_reads_as_inactive_rather_than_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("status.json");
        std::fs::write(&path, "{ not json").unwrap();
        assert!(!read_snapshot(&path, Duration::from_secs(5)).active);
    }

    #[test]
    fn stale_snapshot_reads_as_inactive() {
        // A SIGKILLed helper leaves its last snapshot behind; reporting that as
        // active would tell the user they are protected when they are not.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("status.json");
        write_snapshot(&path, &sample(now() - 60)).unwrap();

        assert!(!read_snapshot(&path, Duration::from_secs(5)).active);
    }

    #[test]
    fn snapshot_is_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("status.json");
        write_snapshot(&path, &sample(now())).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o004, 0o004, "the unprivileged GUI must be able to read it");
    }

    #[test]
    fn clear_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("status.json");
        write_snapshot(&path, &sample(now())).unwrap();
        clear(&path);
        assert!(!path.exists());
    }
}
