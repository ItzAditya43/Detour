// Hide the console window on Windows release builds. Harmless on Linux.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Unprivileged control panel.
//!
//! This process never touches `/etc/resolv.conf` and never binds port 53. It
//! starts the privileged helper through `pkexec` (so the user sees a real
//! authentication prompt rather than a silent escalation), and otherwise only
//! reads the helper's world-readable status snapshot.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use dns_core::config::AppProfile;
use dns_core::{Config, DohResolver};
use dns_helper::diagnose::{Diagnostics, Verdict};
use dns_helper::status::{self, Snapshot};
use dns_helper::upstream::Forwarder;
use serde::Serialize;

/// A snapshot older than this means the helper died without cleaning up.
const STATUS_MAX_AGE: Duration = Duration::from_secs(5);

#[derive(Debug, Serialize)]
struct StartOutcome {
    started: bool,
    message: String,
}

/// Locate the helper binary: next to this executable first (installed layout),
/// then the cargo target dir (development), then `PATH`.
fn helper_path() -> Result<PathBuf, String> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("dns-helper");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    for relative in ["target/debug/dns-helper", "target/release/dns-helper"] {
        let candidate = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|root| root.join(relative));
        if let Some(c) = candidate {
            if c.is_file() {
                return Ok(c);
            }
        }
    }

    if let Ok(output) = Command::new("which").arg("dns-helper").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }

    Err("could not find the dns-helper binary. Build it with `cargo build -p dns-helper`.".into())
}

fn config_path() -> Result<PathBuf, String> {
    Config::default_path().map_err(|e| e.to_string())
}

#[tauri::command]
fn get_config() -> Result<Config, String> {
    let path = config_path()?;
    Config::load(&path).map_err(|e| e.to_string())
}

#[tauri::command]
fn save_config(config: Config) -> Result<(), String> {
    config.validate()?;
    let path = config_path()?;
    config.save(&path).map_err(|e| e.to_string())
}

/* ------------------------------------------------------------ settings */

#[tauri::command]
fn provider_presets() -> Vec<dns_core::Provider> {
    dns_core::provider::presets()
}

#[derive(Debug, Serialize)]
struct ProviderTest {
    ok: bool,
    ms: u64,
    detail: String,
}

/// Resolve a known name through one provider alone, pinned to its bootstrap
/// addresses exactly as the proxy would use it.
#[tauri::command]
async fn test_provider(provider: dns_core::Provider) -> Result<ProviderTest, String> {
    let resolver = DohResolver::new(vec![provider]).map_err(|e| e.to_string())?;
    let name = hickory_proto::rr::Name::from_ascii("example.com.").map_err(|e| e.to_string())?;
    let started = std::time::Instant::now();
    match resolver.resolve(&name, hickory_proto::rr::RecordType::A).await {
        Ok(msg) => {
            let first = msg
                .answers()
                .iter()
                .find_map(|r| r.data().map(|d| d.to_string()))
                .unwrap_or_else(|| "no address".into());
            Ok(ProviderTest {
                ok: !msg.answers().is_empty(),
                ms: started.elapsed().as_millis() as u64,
                detail: format!("example.com → {first}"),
            })
        }
        Err(e) => Ok(ProviderTest {
            ok: false,
            ms: started.elapsed().as_millis() as u64,
            detail: e.to_string(),
        }),
    }
}

/* -------------------------------------------------------- self-update */

/// The source checkout this binary was built from, if it is still there.
fn source_dir() -> Option<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent()?.to_path_buf();
    root.join("packaging/install-user.sh").is_file().then_some(root)
}

/// PATH with rustup's `~/.cargo/bin` added. An app started from the desktop
/// launcher does not inherit a shell's PATH, where cargo usually comes from.
fn build_path() -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        parts.push(PathBuf::from(home).join(".cargo/bin").display().to_string());
    }
    if let Ok(p) = std::env::var("PATH") {
        parts.push(p);
    }
    parts.join(":")
}

fn cargo_available() -> bool {
    Command::new("cargo")
        .arg("--version")
        .env("PATH", build_path())
        .output()
        .is_ok_and(|o| o.status.success())
}

#[derive(Debug, Serialize)]
struct UpdateInfo {
    available: bool,
    source: Option<String>,
    installed: bool,
}

#[tauri::command]
fn update_info() -> UpdateInfo {
    let installed = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.ends_with(".local/bin")))
        .unwrap_or(false);
    let src = source_dir();
    UpdateInfo {
        available: src.is_some() && cargo_available(),
        source: src.map(|p| p.display().to_string()),
        installed,
    }
}

/// Rebuild from the source checkout and reinstall into ~/.local. Takes a
/// couple of minutes; the running app is replaced on disk and picks up the
/// new build on restart.
#[tauri::command]
async fn rebuild_and_install() -> Result<String, String> {
    tokio::task::spawn_blocking(|| {
        let root = source_dir().ok_or("the source folder is not available")?;
        let out = Command::new(root.join("packaging/install-user.sh"))
            .current_dir(&root)
            .env("PATH", build_path())
            .output()
            .map_err(|e| format!("could not run the installer: {e}"))?;
        if out.status.success() {
            Ok("Rebuilt and installed. Restart Detour to use the new version.".to_string())
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            let tail: Vec<&str> = err.lines().rev().take(12).collect();
            Err(format!(
                "Build failed:\n{}",
                tail.into_iter().rev().collect::<Vec<_>>().join("\n")
            ))
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn restart_app(app: tauri::AppHandle) {
    app.restart();
}

#[tauri::command]
fn get_config_path() -> Result<String, String> {
    Ok(config_path()?.display().to_string())
}

#[tauri::command]
fn get_status() -> Snapshot {
    status::read_snapshot(Path::new(status::STATUS_PATH), STATUS_MAX_AGE)
}

/// Start the privileged helper. `pkexec` shows the system authentication
/// dialog; if the user cancels it, that is reported plainly rather than retried.
#[tauri::command]
fn start_protection(profile: Option<String>) -> Result<StartOutcome, String> {
    let current = get_status();
    if current.active {
        return Ok(StartOutcome {
            started: false,
            message: format!("Already running (pid {}).", current.pid),
        });
    }

    let helper = helper_path()?;
    let config = config_path()?;

    let mut command = Command::new("pkexec");
    command.arg(&helper).arg("--config").arg(&config).arg("run");
    if let Some(id) = profile.as_deref().filter(|s| !s.is_empty()) {
        command.arg("--profile").arg(id);
    }

    let mut child = command
        .spawn()
        .map_err(|e| format!("could not launch pkexec: {e}. Is polkit installed?"))?;

    // Wait for the helper to publish a snapshot, so the UI reflects reality
    // instead of optimistically claiming success.
    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(100));

        if get_status().active {
            return Ok(StartOutcome {
                started: true,
                message: "DNS protection is active.".into(),
            });
        }

        // pkexec exits 126 when the user dismisses the authentication dialog.
        if let Ok(Some(exit)) = child.try_wait() {
            let message = match exit.code() {
                Some(126) => "Authentication was cancelled, so nothing was changed.".to_string(),
                Some(127) => "Authorisation was denied by polkit.".to_string(),
                Some(code) => format!("The helper exited with code {code} before starting. Check its output in the terminal."),
                None => "The helper was terminated before it started.".to_string(),
            };
            return Ok(StartOutcome { started: false, message });
        }
    }

    Ok(StartOutcome {
        started: false,
        message: "Timed out waiting for the helper to start.".into(),
    })
}

#[tauri::command]
fn stop_protection() -> Result<StartOutcome, String> {
    if !get_status().active {
        return Ok(StartOutcome {
            started: false,
            message: "DNS protection was not running.".into(),
        });
    }

    let helper = helper_path()?;
    let output = Command::new("pkexec")
        .arg(&helper)
        .arg("stop")
        .output()
        .map_err(|e| format!("could not launch pkexec: {e}"))?;

    if output.status.success() {
        Ok(StartOutcome {
            started: false,
            message: "DNS protection stopped and the original resolvers restored.".into(),
        })
    } else {
        Err(format!(
            "stop failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// Compare ISP DNS against DoH. Runs entirely in this unprivileged process, so
/// it needs no authentication prompt.
#[tauri::command]
async fn run_diagnostic(domains: Vec<String>) -> Result<Vec<Verdict>, String> {
    let config = get_config()?;

    // Prefer the resolvers recorded before takeover; otherwise read the live
    // file, which is world-readable.
    let snapshot = get_status();
    let upstreams: Vec<std::net::IpAddr> = if snapshot.active && !snapshot.upstreams.is_empty() {
        snapshot.upstreams.iter().filter_map(|s| s.parse().ok()).collect()
    } else {
        std::fs::read_to_string("/etc/resolv.conf")
            .map(|text| dns_helper::resolvconf::parse_nameservers(&text))
            .unwrap_or_default()
    };

    let resolver = DohResolver::new(config.providers.clone()).map_err(|e| e.to_string())?;
    let diagnostics = Diagnostics::new(
        resolver,
        Forwarder::new(dns_helper::resolvconf::to_socket_addrs(&upstreams)),
    );

    let mut verdicts = Vec::new();
    for domain in domains.iter().filter(|d| !d.trim().is_empty()) {
        verdicts.push(diagnostics.check(domain.trim()).await);
    }
    Ok(verdicts)
}

/// Launch a profile's game. Deliberately fire-and-forget: Steam forks and
/// returns immediately, so there is no child to wait on and no game lifetime to
/// tie DNS protection to.
#[tauri::command]
fn launch_game(profile: String) -> Result<String, String> {
    let config = get_config()?;
    let profile: &AppProfile = config
        .profile(&profile)
        .ok_or_else(|| format!("no profile named {profile:?}"))?;

    let command = profile
        .launch_command
        .as_deref()
        .filter(|c| !c.trim().is_empty())
        .ok_or("this profile has no launch command configured")?;

    if profile.launch_args.iter().any(|a| a.contains("<APPID>")) {
        return Err(
            "the launch arguments still contain the <APPID> placeholder. Replace it with the \
             game's real Steam app id first."
                .into(),
        );
    }

    Command::new(command)
        .args(&profile.launch_args)
        .spawn()
        .map_err(|e| format!("could not launch {command:?}: {e}"))?;

    Ok(format!("Launched {} via {command}.", profile.name))
}

/* -------------------------------------------------------- filter bypass */

use std::sync::Mutex as StdMutex;

/// HTTP CONNECT port, for browsers pointed at it with --proxy-server.
const FILTER_PORT: u16 = 8088;
/// Transparent port, for connections redirected here by the per-app rule.
const FILTER_TPROXY_PORT: u16 = 8089;

#[derive(Default)]
struct FilterState {
    task: StdMutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    stats: std::sync::Arc<dns_helper::dpi_proxy::Stats>,
}

#[derive(Debug, Serialize)]
struct FilterStatus {
    running: bool,
    port: u16,
    connections: u64,
    fragmented: u64,
}

#[tauri::command]
fn filter_status(state: tauri::State<'_, FilterState>) -> FilterStatus {
    use std::sync::atomic::Ordering;
    FilterStatus {
        running: state.running.load(Ordering::Relaxed),
        port: FILTER_PORT,
        connections: state.stats.connections.load(Ordering::Relaxed),
        fragmented: state.stats.fragmented.load(Ordering::Relaxed),
    }
}

#[tauri::command]
fn filter_start(state: tauri::State<'_, FilterState>) -> Result<String, String> {
    use std::sync::atomic::Ordering;
    let mut guard = state.task.lock().unwrap();
    if state.running.load(Ordering::Relaxed) {
        return Ok("Filter bypass is already running.".into());
    }
    let connect_addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, FILTER_PORT));
    let tproxy_addr =
        std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, FILTER_TPROXY_PORT));
    let proxy = std::sync::Arc::new(dns_helper::dpi_proxy::DpiProxy {
        stats: std::sync::Arc::clone(&state.stats),
    });
    let transparent = std::sync::Arc::clone(&proxy);
    let running = std::sync::Arc::clone(&state.running);
    running.store(true, Ordering::Relaxed);
    // Both listeners share one fragmenter and one set of counters. Runs in
    // Tauri's tokio runtime; no elevation, loopback only.
    let handle = tauri::async_runtime::spawn(async move {
        let connect = proxy.serve(connect_addr);
        let redirected = transparent.serve_transparent(tproxy_addr);
        tokio::select! {
            r = connect => if let Err(e) = r { tracing::error!(error=%e, "CONNECT proxy stopped") },
            r = redirected => if let Err(e) = r { tracing::error!(error=%e, "transparent proxy stopped") },
        }
        running.store(false, Ordering::Relaxed);
    });
    *guard = Some(handle);
    Ok(format!("Filter bypass running on 127.0.0.1:{FILTER_PORT}."))
}

#[tauri::command]
fn filter_stop(state: tauri::State<'_, FilterState>) -> Result<String, String> {
    if let Some(h) = state.task.lock().unwrap().take() {
        h.abort();
    }
    state.running.store(false, std::sync::atomic::Ordering::Relaxed);
    Ok("Filter bypass stopped.".into())
}

/// Cover every app in the tunnel slice, not just browsers, by redirecting
/// their HTTPS into the fragmenting proxy. Needs root for the firewall rule,
/// so it goes through the helper.
#[tauri::command]
async fn filter_route_on(state: tauri::State<'_, FilterState>) -> Result<String, String> {
    if !state.running.load(std::sync::atomic::Ordering::Relaxed) {
        return Err("Start the filter bypass first.".into());
    }
    tokio::task::spawn_blocking(|| {
        ensure_anchor()?;
        pkexec_helper(&[
            "filter-route".into(),
            "up".into(),
            "--uid".into(),
            current_uid().to_string(),
            "--port".into(),
            FILTER_TPROXY_PORT.to_string(),
        ])
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn filter_route_off() -> Result<String, String> {
    tokio::task::spawn_blocking(|| {
        pkexec_helper(&["filter-route".into(), "down".into()])
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Launch a Chromium-family browser pointed at the filter-bypass proxy. Only
/// browsers that honour --proxy-server are offered; the app list marks which.
#[tauri::command]
fn launch_with_filter(state: tauri::State<'_, FilterState>, app: String) -> Result<String, String> {
    if !state.running.load(std::sync::atomic::Ordering::Relaxed) {
        return Err("Start the filter bypass first.".into());
    }
    let config = get_config()?;
    let entry = config.tunnel_app(&app).ok_or_else(|| format!("no app named {app:?}"))?.clone();

    let program = entry.command.rsplit('/').next().unwrap_or(&entry.command).to_string();
    if !matches!(program.as_str(),
        "brave" | "brave-browser" | "chromium" | "google-chrome-stable"
        | "google-chrome" | "vivaldi" | "vivaldi-stable" | "microsoft-edge") {
        return Err(format!(
            "{} isn't a Chromium-family browser, so it can't take a --proxy-server flag. \
             Filter bypass works with Brave, Chromium, Chrome, Vivaldi or Edge.",
            entry.name
        ));
    }

    let (_, outside) = running_split(&program);
    if !outside.is_empty() {
        return Err(format!(
            "{} is already running, so a new launch would just reuse it without the proxy. \
             Quit it completely first, then launch again.",
            entry.name
        ));
    }

    Command::new(&entry.command)
        .arg(format!("--proxy-server=http://127.0.0.1:{FILTER_PORT}"))
        .args(&entry.args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("could not launch {}: {e}", entry.name))?;
    Ok(format!("Launched {} through the filter bypass.", entry.name))
}

/* ------------------------------------------------------------ tunnel */

use dns_helper::tunnel;

const ANCHOR_UNIT: &str = "detourtunnel-anchor";

fn tunnel_dir() -> Result<PathBuf, String> {
    Ok(config_path()?
        .parent()
        .ok_or("config path has no parent")?
        .join("tunnel"))
}

fn wg_config_path() -> Result<PathBuf, String> {
    Ok(tunnel_dir()?.join("wg.conf"))
}

fn have(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

#[derive(Debug, Serialize)]
struct TunnelStatus {
    config_present: bool,
    config_path: String,
    endpoint: Option<String>,
    wgcf_installed: bool,
    up: bool,
    rx_bytes: u64,
    tx_bytes: u64,
}

#[tauri::command]
fn tunnel_status() -> Result<TunnelStatus, String> {
    let path = wg_config_path()?;
    let parsed = tunnel::WgConfig::load(&path).ok();
    let (rx, tx) = tunnel::traffic().unwrap_or((0, 0));
    Ok(TunnelStatus {
        config_present: parsed.is_some(),
        config_path: path.display().to_string(),
        endpoint: parsed.and_then(|c| c.endpoint),
        wgcf_installed: have("wgcf"),
        up: tunnel::is_up(),
        rx_bytes: rx,
        tx_bytes: tx,
    })
}

/// Validate and store a WireGuard config as the tunnel's config (0600).
fn install_config(text: &str) -> Result<(), String> {
    tunnel::WgConfig::parse(text).map_err(|e| e.to_string())?;
    let dir = tunnel_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("wg.conf");
    std::fs::write(&path, text).map_err(|e| e.to_string())?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())
}

/// Import a config chosen with the file picker. The webview hands over the
/// file's contents, not its path.
#[tauri::command]
fn tunnel_import_text(text: String) -> Result<String, String> {
    install_config(&text)?;
    Ok("WireGuard config imported.".into())
}

#[tauri::command]
fn tunnel_import_config(path: String) -> Result<String, String> {
    let path = PathBuf::from(path.trim());
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("could not read {}: {e}", path.display()))?;
    install_config(&text)?;
    Ok("WireGuard config imported.".into())
}

/// Create a free Cloudflare WARP account and turn it into a WireGuard config.
/// The UI asks the user to confirm first, since this registers an account with
/// Cloudflare and accepts its terms of service.
#[tauri::command]
async fn tunnel_generate_warp() -> Result<String, String> {
    tokio::task::spawn_blocking(|| {
        if !have("wgcf") {
            return Err("wgcf is not installed. Install it with: yay -S wgcf".to_string());
        }
        let dir = tunnel_dir()?;
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

        let run = |args: &[&str]| -> Result<(), String> {
            let out = Command::new("wgcf")
                .args(args)
                .current_dir(&dir)
                .output()
                .map_err(|e| format!("could not run wgcf: {e}"))?;
            if out.status.success() {
                Ok(())
            } else {
                Err(format!(
                    "wgcf {} failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&out.stderr).trim()
                ))
            }
        };

        // Reuse an existing account rather than registering a new one each time.
        if !dir.join("wgcf-account.toml").exists() {
            run(&["register", "--accept-tos"])?;
        }
        run(&["generate"])?;

        let text = std::fs::read_to_string(dir.join("wgcf-profile.conf"))
            .map_err(|e| format!("wgcf did not produce a profile: {e}"))?;
        install_config(&text)?;
        Ok("Cloudflare WARP config generated.".to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Keep one long-lived unit in the tunnel slice, so its cgroup exists when
/// the nftables rule is loaded and does not vanish between app launches.
fn ensure_anchor() -> Result<(), String> {
    let active = Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", ANCHOR_UNIT])
        .status()
        .is_ok_and(|s| s.success());
    if active {
        return Ok(());
    }
    let out = Command::new("systemd-run")
        .args([
            "--user",
            "--quiet",
            &format!("--unit={ANCHOR_UNIT}"),
            &format!("--slice={}", tunnel::SLICE),
            "sleep",
            "infinity",
        ])
        .output()
        .map_err(|e| format!("could not run systemd-run: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "could not create the tunnel slice: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

fn pkexec_helper(args: &[String]) -> Result<String, String> {
    let helper = helper_path()?;
    let out = Command::new("pkexec")
        .arg(&helper)
        .args(args)
        .output()
        .map_err(|e| format!("could not launch pkexec: {e}"))?;
    match out.status.code() {
        Some(0) => Ok(String::from_utf8_lossy(&out.stdout).trim().to_string()),
        Some(126) => Err("Authentication was cancelled, so nothing was changed.".into()),
        Some(127) => Err("Authorisation was denied by polkit.".into()),
        _ => Err(String::from_utf8_lossy(&out.stderr).trim().to_string()),
    }
}

#[tauri::command]
async fn tunnel_up() -> Result<String, String> {
    tokio::task::spawn_blocking(|| {
        let config = wg_config_path()?;
        if !config.exists() {
            return Err("No WireGuard config yet. Generate or import one first.".into());
        }
        ensure_anchor()?;
        pkexec_helper(&[
            "tunnel".into(),
            "up".into(),
            "--wg-config".into(),
            config.display().to_string(),
            "--uid".into(),
            current_uid().to_string(),
        ])
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn tunnel_down() -> Result<String, String> {
    tokio::task::spawn_blocking(|| {
        let msg = pkexec_helper(&["tunnel".into(), "down".into()])?;
        let _ = Command::new("systemctl")
            .args(["--user", "stop", ANCHOR_UNIT])
            .status();
        prune_idle_holds();
        Ok(msg)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// PIDs of processes named `name`, split by whether they already run inside
/// the tunnel slice.
fn running_split(name: &str) -> (Vec<u32>, Vec<u32>) {
    let mut inside = Vec::new();
    let mut outside = Vec::new();
    let Ok(out) = Command::new("pgrep").args(["-x", name]).output() else {
        return (inside, outside);
    };
    for pid in String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
    {
        let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
        if cgroup.contains(tunnel::SLICE) {
            inside.push(pid);
        } else {
            outside.push(pid);
        }
    }
    (inside, outside)
}

use dns_helper::apps;

/// Start the holding scope a Flatpak app is moved into, if it isn't running.
/// `Delegate=yes` tells systemd the processes inside are ours to manage.
fn ensure_hold(app_name: &str) -> Result<PathBuf, String> {
    let base = apps::user_service_cgroup(current_uid());
    let hold = apps::hold_cgroup(&base, app_name);
    if hold.exists() {
        return Ok(hold);
    }
    Command::new("systemd-run")
        .args([
            "--user",
            "--scope",
            "--quiet",
            "-p",
            "Delegate=yes",
            &format!("--slice={}", tunnel::SLICE),
            &format!("--unit={}", apps::hold_unit(app_name)),
            "--",
            "sleep",
            "infinity",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("could not create the holding scope: {e}"))?;
    for _ in 0..100 {
        if hold.exists() {
            return Ok(hold);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err("the holding scope did not appear".into())
}

/// Stop holding scopes whose app has exited. Never touches one that still
/// holds a real process.
fn prune_idle_holds() {
    let base = apps::user_service_cgroup(current_uid());
    for unit in apps::idle_holds(&base) {
        let _ = Command::new("systemctl").args(["--user", "stop", &unit]).status();
    }
}

fn presence(entry: &dns_core::TunnelApp) -> apps::Presence {
    match apps::flatpak_app_id(&entry.command, &entry.args) {
        Some(id) => {
            apps::flatpak_presence(&apps::user_service_cgroup(current_uid()), &entry.name, &id)
        }
        None => {
            let (inside, outside) = running_split(entry.process_name());
            apps::Presence { inside: !inside.is_empty(), outside: !outside.is_empty() }
        }
    }
}

/// Launch a configured app inside the tunnel slice.
#[tauri::command]
async fn launch_in_tunnel(app: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || launch_in_tunnel_blocking(&app))
        .await
        .map_err(|e| e.to_string())?
}

fn launch_in_tunnel_blocking(app: &str) -> Result<String, String> {
    let config = get_config()?;
    let entry = config
        .tunnel_app(app)
        .ok_or_else(|| format!("no tunnel app named {app:?}"))?
        .clone();
    let label = entry.name.as_str();

    // Without the tunnel up there is no marking rule, so the app would just
    // run on the normal connection while looking protected.
    if !tunnel::is_up() {
        return Err("Start the tunnel first.".into());
    }

    let here = presence(&entry);
    if here.outside {
        return Err(format!(
            "{label} is already running outside the tunnel. Use \"Move into tunnel\" to \
             bring it in without closing it."
        ));
    }
    if here.inside {
        return Ok(format!("{label} is already running inside the tunnel."));
    }

    ensure_anchor()?;
    prune_idle_holds();

    if let Some(app_id) = apps::flatpak_app_id(&entry.command, &entry.args) {
        let hold = ensure_hold(label)?;
        Command::new(&entry.command)
            .args(&entry.args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("could not launch {label}: {e}"))?;

        let base = apps::user_service_cgroup(current_uid());
        let moved = apps::capture_flatpak(
            &base,
            &app_id,
            &hold,
            Duration::from_secs(20),
            Duration::from_secs(2),
        )
        .map_err(|e| format!("could not move {label} into the tunnel: {e}"))?;
        if moved == 0 {
            return Err(format!(
                "{label} started but could not be moved into the tunnel. Close it and \
                 check it is not running elsewhere."
            ));
        }
        return Ok(format!("Launched {label} (Flatpak) inside the tunnel."));
    }

    Command::new("systemd-run")
        .args(["--user", "--scope", "--quiet", &format!("--slice={}", tunnel::SLICE), "--"])
        .arg(&entry.command)
        .args(&entry.args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("could not launch {label}: {e}"))?;

    Ok(format!("Launched {label} inside the tunnel."))
}

/// Move an app that is already running into the tunnel, without restarting
/// it. Goes through the root helper: apps started from a terminal or the
/// session live outside the user's own cgroup subtree, and resetting the
/// app's open connections needs root either way.
#[tauri::command]
async fn attach_to_tunnel(app: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        if !tunnel::is_up() {
            return Err("Start the tunnel first.".to_string());
        }
        let config = get_config()?;
        let entry = config
            .tunnel_app(&app)
            .ok_or_else(|| format!("no tunnel app named {app:?}"))?
            .clone();

        let pids: Vec<u32> = match apps::flatpak_app_id(&entry.command, &entry.args) {
            Some(id) => apps::flatpak_scopes(&apps::user_service_cgroup(current_uid()), &id)
                .iter()
                .flat_map(|scope| apps::procs(scope))
                .collect(),
            None => running_split(entry.process_name()).1,
        };
        if pids.is_empty() {
            return Err(format!("{} is not running outside the tunnel.", entry.name));
        }

        ensure_anchor()?;
        let hold = ensure_hold(&entry.name)?;
        let mut args: Vec<String> = vec![
            "tunnel".into(),
            "attach".into(),
            "--uid".into(),
            current_uid().to_string(),
            "--hold".into(),
            hold.display().to_string(),
            "--reset".into(),
        ];
        for pid in pids {
            args.push("--pid".into());
            args.push(pid.to_string());
        }
        pkexec_helper(&args)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Which configured tunnel apps are currently running, and where.
#[derive(Debug, Serialize)]
struct AppState {
    name: String,
    command: String,
    flatpak: bool,
    installed: bool,
    running_inside: bool,
    running_outside: bool,
}

fn flatpak_installed(id: &str) -> bool {
    Command::new("flatpak")
        .args(["info", id])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[tauri::command]
fn tunnel_apps() -> Result<Vec<AppState>, String> {
    let config = get_config()?;
    Ok(config
        .tunnel_apps
        .iter()
        .map(|a| {
            let fp = apps::flatpak_app_id(&a.command, &a.args);
            let here = presence(a);
            AppState {
                name: a.name.clone(),
                command: std::iter::once(a.command.as_str())
                    .chain(a.args.iter().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join(" "),
                flatpak: fp.is_some(),
                installed: match &fp {
                    Some(id) => flatpak_installed(id),
                    None => {
                        (a.command.starts_with('/') && Path::new(&a.command).exists())
                            || have(&a.command)
                    }
                },
                running_inside: here.inside,
                running_outside: here.outside,
            }
        })
        .collect())
}

#[derive(Debug, Serialize)]
struct Suggestion {
    name: String,
    command: String,
}

/// Installed apps worth offering as one-click additions: common native
/// browsers and launchers, plus every installed Flatpak app.
#[tauri::command]
fn suggest_apps() -> Result<Vec<Suggestion>, String> {
    let config = get_config()?;
    let configured: Vec<String> = config
        .tunnel_apps
        .iter()
        .map(|a| {
            std::iter::once(a.command.as_str())
                .chain(a.args.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();

    let mut out: Vec<Suggestion> = [
        ("Brave", "brave"),
        ("Firefox", "firefox"),
        ("Chromium", "chromium"),
        ("Google Chrome", "google-chrome-stable"),
        ("Zen", "zen-browser"),
        ("Steam", "steam"),
        ("Lutris", "lutris"),
        ("Heroic", "heroic"),
        ("Discord", "discord"),
    ]
    .iter()
    .filter(|(_, cmd)| have(cmd))
    .map(|(name, cmd)| Suggestion { name: name.to_string(), command: cmd.to_string() })
    .collect();

    if let Ok(o) = Command::new("flatpak")
        .args(["list", "--app", "--columns=name,application"])
        .output()
    {
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            let mut cols = line.split('\t');
            if let (Some(name), Some(id)) = (cols.next(), cols.next()) {
                out.push(Suggestion {
                    name: name.trim().to_string(),
                    command: format!("flatpak run {}", id.trim()),
                });
            }
        }
    }

    out.retain(|s| !configured.contains(&s.command));
    Ok(out)
}

#[derive(Debug, Serialize)]
struct ExitCheck {
    direct_ip: Option<String>,
    direct_loc: Option<String>,
    tunnel_ip: Option<String>,
    tunnel_loc: Option<String>,
    tunnel_warp: Option<String>,
    tunnel_error: Option<String>,
}

fn parse_trace(text: &str, key: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .map(str::to_string)
}

/// Compare the public IP seen directly with the one seen from inside the
/// tunnel slice. Proves the routing works end to end, not just that the
/// interface exists.
#[tauri::command]
async fn tunnel_check_exit() -> Result<ExitCheck, String> {
    tokio::task::spawn_blocking(|| {
        const TRACE: &str = "https://www.cloudflare.com/cdn-cgi/trace";
        let direct = Command::new("curl")
            .args(["-s", "--max-time", "8", TRACE])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        ensure_anchor()?;
        let tunnelled = Command::new("systemd-run")
            .args([
                "--user",
                "--scope",
                "--quiet",
                &format!("--slice={}", tunnel::SLICE),
                "--",
                "curl",
                "-s",
                "--max-time",
                "8",
                TRACE,
            ])
            .output()
            .map_err(|e| e.to_string())?;
        let t = String::from_utf8_lossy(&tunnelled.stdout).to_string();

        Ok(ExitCheck {
            direct_ip: parse_trace(&direct, "ip"),
            direct_loc: parse_trace(&direct, "loc"),
            tunnel_ip: parse_trace(&t, "ip"),
            tunnel_loc: parse_trace(&t, "loc"),
            tunnel_warp: parse_trace(&t, "warp"),
            tunnel_error: if t.trim().is_empty() {
                Some(if tunnel::is_up() {
                    "No response through the tunnel. The WireGuard endpoint may be \
                     unreachable from this network."
                        .into()
                } else {
                    "Tunnel is down. Tunnelled apps have no connectivity (fail-closed) \
                     only while the tunnel is up; start it first."
                        .into()
                })
            } else {
                None
            },
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn helper_available() -> bool {
    helper_path().is_ok()
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "detour=info".into()),
        )
        .init();

    tauri::Builder::default()
        .manage(FilterState::default())
        .invoke_handler(tauri::generate_handler![
            get_config,
            save_config,
            get_config_path,
            get_status,
            start_protection,
            stop_protection,
            run_diagnostic,
            launch_game,
            helper_available,
            tunnel_status,
            tunnel_import_config,
            tunnel_generate_warp,
            tunnel_up,
            tunnel_down,
            launch_in_tunnel,
            tunnel_apps,
            suggest_apps,
            attach_to_tunnel,
            provider_presets,
            test_provider,
            tunnel_import_text,
            update_info,
            rebuild_and_install,
            restart_app,
            filter_status,
            filter_start,
            filter_stop,
            launch_with_filter,
            filter_route_on,
            filter_route_off,
            tunnel_check_exit,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
