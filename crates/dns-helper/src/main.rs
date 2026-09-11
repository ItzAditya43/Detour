//! Privileged helper for Detour.
//!
//! Runs as root (via pkexec from the GUI, or directly from a terminal) and owns
//! the two things that need privilege: binding port 53 and rewriting
//! `/etc/resolv.conf`. The GUI itself stays unprivileged.


use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use dns_core::{Config, DohResolver};

use dns_helper::diagnose::Diagnostics;
use dns_helper::proxy::Proxy;
use dns_helper::resolvconf::{self, ResolvManager};
use dns_helper::status::{self, Snapshot, StatusWriter};
use dns_helper::upstream::Forwarder;

#[derive(Parser)]
#[command(name = "dns-helper", about = "Privileged DNS proxy and tunnel helper for Detour")]
struct Cli {
    /// Path to config.toml. Defaults to the invoking user's XDG config dir.
    #[arg(long, global = true)]
    config: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the proxy and point the system at it. Restores on exit.
    Run {
        /// Game profile whose domains are forced over DoH.
        #[arg(long)]
        profile: Option<String>,
        /// Run the proxy without touching /etc/resolv.conf. Useful for testing:
        /// query it directly with `dig @127.0.0.53 example.com`.
        #[arg(long)]
        no_takeover: bool,
        /// Override where the status snapshot is written. Lets the proxy run
        /// unprivileged for testing, since the default lives under /var/lib.
        #[arg(long)]
        status_path: Option<std::path::PathBuf>,
    },
    /// Restore /etc/resolv.conf from backup. Safe to run any time.
    Restore,
    /// Report whether a takeover is currently active.
    Status,
    /// Signal a running helper to shut down cleanly and restore DNS.
    Stop,
    /// Run the DPI-bypass HTTP proxy (no root). Point a browser at it.
    FilterProxy {
        #[arg(long, default_value = "127.0.0.1:8088")]
        listen: std::net::SocketAddr,
        /// Transparent mode: take redirected connections and read their real
        /// destination from the kernel instead of an HTTP CONNECT request.
        #[arg(long)]
        transparent: bool,
    },
    /// Redirect the tunnel slice's HTTPS into the filter-bypass proxy, so any
    /// app launched there is covered without a proxy setting (root).
    FilterRoute {
        #[command(subcommand)]
        action: FilterRouteAction,
    },
    /// Per-application WireGuard tunnel.
    Tunnel {
        #[command(subcommand)]
        action: TunnelAction,
    },
    /// Compare ISP DNS against DoH for one or more domains.
    Diagnose {
        /// Domains to test.
        #[arg(required = true)]
        domains: Vec<String>,
        /// Emit JSON instead of a human-readable report.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum TunnelAction {
    /// Bring the tunnel up (root).
    Up {
        /// WireGuard config file (wg-quick format).
        #[arg(long)]
        wg_config: std::path::PathBuf,
        /// Desktop user whose tunnel slice is routed. Defaults to the user
        /// who invoked pkexec or sudo.
        #[arg(long)]
        uid: Option<u32>,
    },
    /// Tear the tunnel down (root). Safe to run any time.
    Down,
    /// Move an already-running app into the tunnel (root), and optionally
    /// reset its open connections so they reconnect through the tunnel.
    Attach {
        #[arg(long)]
        uid: Option<u32>,
        /// Holding scope cgroup to move the processes into. Must lie inside
        /// the user's tunnel slice.
        #[arg(long)]
        hold: std::path::PathBuf,
        /// Root process(es) of the app; descendants are included.
        #[arg(long = "pid", required = true)]
        pids: Vec<u32>,
        #[arg(long)]
        reset: bool,
    },
    /// Print the nftables ruleset that `up` would install.
    Rules {
        #[arg(long)]
        uid: Option<u32>,
    },
}

/// Move a running app's process tree into the tunnel slice. Runs as root, so
/// it only ever touches processes owned by `uid` and only ever writes into
/// that user's tunnel slice.
fn attach(uid: u32, hold: &std::path::Path, roots: &[u32], reset: bool) -> anyhow::Result<()> {
    use dns_helper::apps;
    if uid == 0 {
        anyhow::bail!("refusing to act on root's processes");
    }

    let slice = apps::user_service_cgroup(uid).join(dns_helper::tunnel::SLICE);
    let hold = hold
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("holding scope {}: {e}", hold.display()))?;
    if !hold.starts_with(&slice) || hold == slice {
        anyhow::bail!("{} is not inside {}", hold.display(), slice.display());
    }

    for &pid in roots {
        match apps::process_uid(pid) {
            Some(owner) if owner == uid => {}
            Some(owner) => anyhow::bail!("pid {pid} belongs to uid {owner}, not {uid}"),
            None => anyhow::bail!("pid {pid} is not running"),
        }
    }

    // Repeat until the tree stops growing, to catch children forked mid-move.
    let procs_file = hold.join("cgroup.procs");
    let mut moved: Vec<u32> = Vec::new();
    for _ in 0..5 {
        let tree = apps::descendants(roots, &apps::process_table());
        let fresh: Vec<u32> = tree
            .into_iter()
            .filter(|p| !moved.contains(p) && apps::process_uid(*p) == Some(uid))
            .collect();
        if fresh.is_empty() {
            break;
        }
        for pid in fresh {
            match std::fs::write(&procs_file, pid.to_string()) {
                Ok(()) => moved.push(pid),
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
                Err(e) => return Err(anyhow::anyhow!("moving pid {pid}: {e}")),
            }
        }
    }
    println!("Moved {} process(es) into the tunnel.", moved.len());

    if !reset {
        return Ok(());
    }

    // Sockets keep the cgroup they were created in, so the app's existing
    // connections would stay on the normal path. Reset exactly those; the app
    // reconnects, and the new sockets are marked for the tunnel.
    let listing = std::process::Command::new("ss").args(["-tunpH"]).output()?;
    let mut reset_count = 0;
    for line in String::from_utf8_lossy(&listing.stdout).lines() {
        let Some(sock) = apps::parse_ss_line(line) else { continue };
        if !sock.pids.iter().any(|p| moved.contains(p)) {
            continue;
        }
        if apps::is_local_destination(&sock.peer.ip()) {
            continue;
        }
        let proto = if sock.proto == "udp" { "-u" } else { "-t" };
        let ok = std::process::Command::new("ss")
            .args(["-K", proto, &apps::ss_kill_filter(&sock)])
            .output()
            .is_ok_and(|o| o.status.success());
        if ok {
            reset_count += 1;
        }
    }
    println!("Reset {reset_count} open connection(s); they will reconnect through the tunnel.");
    Ok(())
}

#[derive(Subcommand)]
enum FilterRouteAction {
    /// Install the redirect (root).
    Up {
        #[arg(long)]
        uid: Option<u32>,
        #[arg(long, default_value_t = 8088)]
        port: u16,
    },
    /// Remove it (root). Safe any time.
    Down,
    /// Print the nftables ruleset `up` would install.
    Rules {
        #[arg(long)]
        uid: Option<u32>,
        #[arg(long, default_value_t = 8088)]
        port: u16,
    },
}

fn filter_route_cmd(action: FilterRouteAction) -> anyhow::Result<()> {
    use dns_helper::filter_route as fr;
    use dns_helper::tunnel;
    match action {
        FilterRouteAction::Rules { uid, port } => {
            print!("{}", fr::nft_ruleset(invoking_uid(uid), port));
            Ok(())
        }
        FilterRouteAction::Down => {
            for s in fr::down_steps() {
                let _ = std::process::Command::new(&s.argv[0]).args(&s.argv[1..]).output();
            }
            println!("Filter redirect removed.");
            Ok(())
        }
        FilterRouteAction::Up { uid, port } => {
            let uid = invoking_uid(uid);
            if uid == 0 {
                anyhow::bail!("refusing to redirect root's slice; pass --uid for the desktop user");
            }
            // Replace any previous rule set rather than stacking.
            for s in fr::down_steps() {
                let _ = std::process::Command::new(&s.argv[0]).args(&s.argv[1..]).output();
            }
            let dir = std::path::Path::new("/run/detour");
            std::fs::create_dir_all(dir)?;
            let path = dir.join("filter.nft");
            std::fs::write(&path, fr::nft_ruleset(uid, port))?;

            for s in fr::up_steps(&path.to_string_lossy()) {
                let out = std::process::Command::new(&s.argv[0]).args(&s.argv[1..]).output()?;
                if !out.status.success() {
                    // Never leave a half-installed rule set behind.
                    for d in fr::down_steps() {
                        let _ = std::process::Command::new(&d.argv[0]).args(&d.argv[1..]).output();
                    }
                    anyhow::bail!(
                        "{} failed: {}",
                        s.argv.join(" "),
                        String::from_utf8_lossy(&out.stderr).trim()
                    );
                }
            }
            println!(
                "Apps in {} now have their HTTPS routed through the filter bypass on port {port}.",
                tunnel::SLICE
            );
            Ok(())
        }
    }
}

/// The user behind pkexec/sudo, falling back to the current uid.
fn invoking_uid(explicit: Option<u32>) -> u32 {
    explicit
        .or_else(|| std::env::var("PKEXEC_UID").ok()?.parse().ok())
        .or_else(|| std::env::var("SUDO_UID").ok()?.parse().ok())
        .unwrap_or_else(|| unsafe { libc::getuid() })
}

fn tunnel_cmd(action: TunnelAction) -> anyhow::Result<()> {
    use dns_helper::tunnel;
    match action {
        TunnelAction::Up { wg_config, uid } => {
            let uid = invoking_uid(uid);
            if uid == 0 {
                anyhow::bail!("refusing to tunnel root's slice; pass --uid for the desktop user");
            }
            let config = tunnel::WgConfig::load(&wg_config)?;
            tunnel::up(&config, uid, std::path::Path::new("/run/detour"))?;
            println!("Tunnel up on {} for uid {uid}.", tunnel::IFACE);
            if let Some(ep) = &config.endpoint {
                println!("  endpoint: {ep}");
            }
            Ok(())
        }
        TunnelAction::Down => {
            tunnel::down();
            println!("Tunnel down.");
            Ok(())
        }
        TunnelAction::Attach { uid, hold, pids, reset } => attach(invoking_uid(uid), &hold, &pids, reset),
        TunnelAction::Rules { uid } => {
            print!("{}", tunnel::nft_ruleset(invoking_uid(uid)));
            Ok(())
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Logs go to stderr, and only in colour on a real terminal: the GUI
    // shows the helper's stdout to the user, which must stay plain text.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dns_helper=info,dns_core=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config_path = match cli.config {
        Some(p) => p,
        None => Config::default_path().context("locating config file")?,
    };
    let config = Config::load(&config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    match cli.command {
        Command::Run { profile, no_takeover, status_path } => {
            run(config, profile, no_takeover, status_path).await
        }
        Command::Restore => restore(),
        Command::Status => status(),
        Command::Stop => stop(),
        Command::FilterProxy { listen, transparent } => {
            use std::sync::Arc;
            let proxy = Arc::new(dns_helper::dpi_proxy::DpiProxy::default());
            if transparent {
                proxy.serve_transparent(listen).await.map_err(Into::into)
            } else {
                proxy.serve(listen).await.map_err(Into::into)
            }
        }
        Command::FilterRoute { action } => filter_route_cmd(action),
        Command::Tunnel { action } => tunnel_cmd(action),
        Command::Diagnose { domains, json } => diagnose_cmd(config, domains, json).await,
    }
}

async fn run(
    config: Config,
    profile: Option<String>,
    no_takeover: bool,
    status_path: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    let status_path =
        status_path.unwrap_or_else(|| std::path::PathBuf::from(status::STATUS_PATH));
    let listen: SocketAddr = config
        .listen
        .parse()
        .with_context(|| format!("invalid listen address {:?}", config.listen))?;

    let manager = ResolvManager::default();

    // Before anything else: undo a takeover left behind by a crashed run.
    match manager.reconcile_after_crash() {
        Ok(Some(state)) => {
            tracing::warn!(pid = state.pid, "recovered from a previous unclean shutdown")
        }
        Ok(None) => {}
        Err(resolvconf::ResolvError::AlreadyActive(pid)) => {
            anyhow::bail!("another helper (pid {pid}) already holds DNS. Stop it first.");
        }
        Err(e) => return Err(e).context("reconciling previous state"),
    }

    // Read the system's real resolvers *before* takeover; afterwards the file
    // points at us and reading it would just find our own address.
    let original = manager
        .current_nameservers()
        .context("reading current nameservers")?;
    if original.is_empty() {
        tracing::warn!("no system resolvers found; local names will not resolve");
    } else {
        tracing::info!(?original, "system resolvers recorded for local-name forwarding");
    }

    let forwarder = Arc::new(Forwarder::new(resolvconf::to_socket_addrs(&original)));
    let resolver = Arc::new(
        DohResolver::new(config.providers.clone()).context("building DoH resolver")?,
    );
    tracing::info!(providers = ?resolver.provider_names(), "DoH providers");

    let policy = config.policy_for(profile.as_deref());
    if let Some(id) = &profile {
        tracing::info!(profile = %id, forced = ?policy.force_doh, "profile active");
    }

    let cache = resolver.cache();
    let provider_names: Vec<String> =
        resolver.provider_names().iter().map(|s| s.to_string()).collect();
    let forced = policy.force_doh.clone();

    let proxy = Arc::new(Proxy::new(resolver, forwarder, policy));
    let server = tokio::spawn(Arc::clone(&proxy).serve(listen));

    // Bind first, take over second. If the bind fails there is nothing to undo.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    if server.is_finished() {
        return server.await.context("proxy task panicked")?;
    }

    let took_over = if no_takeover {
        tracing::info!("--no-takeover: system DNS left untouched. Query {listen} directly.");
        false
    } else {
        manager
            .take_over(listen.ip())
            .context("taking over /etc/resolv.conf")?;
        true
    };

    // Publish live state for the unprivileged GUI to read.
    let base = Snapshot {
        active: true,
        listen: listen.to_string(),
        pid: std::process::id(),
        took_over_resolv_conf: took_over,
        profile: profile.clone(),
        providers: provider_names,
        forced_domains: forced,
        upstreams: original.iter().map(ToString::to_string).collect(),
        cache_entries: 0,
        queries_total: 0,
        recent: Vec::new(),
        updated_at: 0,
    };
    let status_writer = StatusWriter::new(
        &status_path,
        base,
        Arc::clone(&proxy.log),
        cache,
    );
    // Write once up front so the GUI sees "active" immediately rather than
    // after the first tick.
    if let Err(e) = status_writer.write_once() {
        tracing::warn!(error = %e, "could not write initial status snapshot");
    }
    let status_task = tokio::spawn(status_writer.run());

    // Restore on any orderly exit path, including SIGTERM from the GUI.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("interrupted, shutting down"),
        _ = sigterm.recv() => tracing::info!("terminated, shutting down"),
        result = server => {
            if let Err(e) = result.context("proxy task panicked")? {
                tracing::error!(error = %e, "proxy stopped with an error");
                status_task.abort();
                status::clear(&status_path);
                if took_over {
                    let _ = manager.restore();
                }
                return Err(e);
            }
        }
    }

    status_task.abort();
    status::clear(&status_path);

    if took_over {
        manager.restore().context("restoring /etc/resolv.conf")?;
    }
    Ok(())
}

fn restore() -> anyhow::Result<()> {
    let manager = ResolvManager::default();
    match manager.restore() {
        Ok(()) => {
            println!("Restored /etc/resolv.conf from backup.");
            Ok(())
        }
        Err(resolvconf::ResolvError::NoBackup) => {
            println!("No backup present; /etc/resolv.conf was not modified by this tool.");
            Ok(())
        }
        Err(e) => Err(e).context("restoring /etc/resolv.conf"),
    }
}

/// Ask a running helper to exit. SIGTERM rather than SIGKILL, so its shutdown
/// path runs and `/etc/resolv.conf` is restored.
fn stop() -> anyhow::Result<()> {
    let snapshot = dns_helper::status::read_snapshot(
        std::path::Path::new(dns_helper::status::STATUS_PATH),
        std::time::Duration::from_secs(10),
    );

    if !snapshot.active || snapshot.pid == 0 {
        // Nothing running, but a crashed run may still have DNS redirected.
        println!("No helper is running.");
        let manager = ResolvManager::default();
        if manager.read_state()?.is_some() {
            println!("Found leftover state; restoring DNS.");
            let _ = manager.restore();
        }
        return Ok(());
    }

    let pid = snapshot.pid as i32;
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("could not signal helper pid {pid}: {err}");
    }
    println!("Sent shutdown signal to helper pid {pid}.");

    // Wait for it to actually go away, so the GUI does not report "stopped"
    // while DNS is still redirected.
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if unsafe { libc::kill(pid, 0) } != 0 {
            println!("Helper stopped and DNS restored.");
            return Ok(());
        }
    }
    anyhow::bail!("helper pid {pid} did not exit within 5s; run `dns-helper restore` if DNS is still redirected")
}

fn status() -> anyhow::Result<()> {
    let manager = ResolvManager::default();
    let state = match manager.read_state() {
        Ok(state) => state,
        // state.json is root-only; unprivileged callers read the public
        // snapshot instead of failing outright.
        Err(resolvconf::ResolvError::Denied { .. }) => {
            let snap = dns_helper::status::read_snapshot(
                std::path::Path::new(dns_helper::status::STATUS_PATH),
                std::time::Duration::from_secs(10),
            );
            if snap.active {
                println!("ACTIVE  - held by pid {}", snap.pid);
                println!("  original nameservers: {:?}", snap.upstreams);
                println!("  queries served: {}", snap.queries_total);
            } else {
                println!("UNKNOWN - takeover state exists but is root-only and no live helper");
                println!("  is publishing status. Run `sudo dns-helper status` for details.");
            }
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    match state {
        Some(state) if manager.is_active()? => {
            println!("ACTIVE  - held by pid {}", state.pid);
            println!("  original nameservers: {:?}", state.original_nameservers);
        }
        Some(state) => {
            println!("STALE   - pid {} is gone; run `dns-helper restore`.", state.pid);
        }
        None => println!("INACTIVE - system DNS is untouched."),
    }
    Ok(())
}

async fn diagnose_cmd(config: Config, domains: Vec<String>, json: bool) -> anyhow::Result<()> {
    let manager = ResolvManager::default();

    // If we currently hold resolv.conf, the file lists us, not the ISP. Use the
    // recorded originals so the comparison is meaningful either way.
    let upstreams = match manager.read_state()? {
        Some(state) if !state.original_nameservers.is_empty() => state.original_nameservers,
        _ => manager.current_nameservers().unwrap_or_default(),
    };

    let resolver = DohResolver::new(config.providers.clone()).context("building DoH resolver")?;
    let diagnostics = Diagnostics::new(
        resolver,
        Forwarder::new(resolvconf::to_socket_addrs(&upstreams)),
    );

    let mut verdicts = Vec::new();
    for domain in &domains {
        verdicts.push(diagnostics.check(domain).await);
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&verdicts)?);
        return Ok(());
    }

    for v in &verdicts {
        println!("\n=== {} ===", v.domain);
        match &v.isp_error {
            Some(e) => println!("  ISP DNS  : FAILED ({e})"),
            None => println!("  ISP DNS  : {}", join(&v.isp_addresses)),
        }
        match &v.doh_error {
            Some(e) => println!("  DoH      : FAILED ({e})"),
            None => println!("  DoH      : {}", join(&v.doh_addresses)),
        }
        println!("  reachable: {}", join(&v.reachable));
        if !v.unreachable.is_empty() {
            println!("  DEAD     : {}", join(&v.unreachable));
        }
        if let Some(restriction) = &v.restriction {
            println!("  RESTRICT : {restriction}");
        }
        println!("  verdict  : {:?}", v.conclusion);
        println!("  {}", v.conclusion.explain());
    }
    println!();
    Ok(())
}

fn join(items: &[String]) -> String {
    if items.is_empty() {
        "(none)".to_string()
    } else {
        items.join(", ")
    }
}
