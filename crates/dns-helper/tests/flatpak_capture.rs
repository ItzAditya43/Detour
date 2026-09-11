//! Real-system test of moving a Flatpak app into the tunnel slice.
//!
//! Needs a user systemd session and an installed Flatpak app. Ignored by
//! default; run with:
//!
//! ```text
//! DETOUR_TEST_FLATPAK=com.heroicgameslauncher.hgl \
//!   cargo test -p dns-helper --test flatpak_capture -- --ignored --nocapture
//! ```

use std::process::{Command, Stdio};
use std::time::Duration;

use dns_helper::apps;

#[test]
#[ignore = "needs a user systemd session and an installed Flatpak"]
fn flatpak_processes_end_up_in_the_tunnel_slice() {
    let app_id = std::env::var("DETOUR_TEST_FLATPAK").expect("set DETOUR_TEST_FLATPAK");
    let uid = unsafe { libc::getuid() };
    let base = apps::user_service_cgroup(uid);
    let name = "capture test";
    let unit = apps::hold_unit(name);
    let hold = apps::hold_cgroup(&base, name);

    Command::new("systemd-run")
        .args(["--user", "--scope", "--quiet", "-p", "Delegate=yes"])
        .arg(format!("--slice={}", dns_helper::tunnel::SLICE))
        .arg(format!("--unit={unit}"))
        .args(["--", "sleep", "60"])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if hold.exists() { break }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(hold.exists(), "holding scope was not created");

    // A harmless command inside the app's sandbox, standing in for the app.
    let mut child = Command::new("flatpak")
        .args(["run", "--command=sleep", &app_id, "30"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let moved = apps::capture_flatpak(&base, &app_id, &hold, Duration::from_secs(15), Duration::from_millis(800))
        .expect("capture runs");

    let leftover: usize = apps::flatpak_scopes(&base, &app_id).iter().map(|s| apps::procs(s).len()).sum();
    let in_hold = apps::procs(&hold);
    println!("moved {moved}, now in hold: {in_hold:?}, left in flatpak scopes: {leftover}");

    let _ = child.kill();
    let _ = Command::new("systemctl").args(["--user", "stop", &unit]).status();

    assert!(moved > 0, "nothing was captured");
    assert_eq!(leftover, 0, "processes were left outside the tunnel slice");
    assert!(in_hold.len() > 1, "only the placeholder is in the holding scope");
}
