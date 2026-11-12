// daemon/src/main.rs — v1.1.0 — Thursday 12 November 2026
// ghost-sentri-daemon — resident, headless intercept daemon.
//
// Runs as a ROOT systemd SYSTEM service (ghost-sentri-daemon.service). Privileged
// operations requested over the control socket are authorised per-call via polkit
// (see polkit.rs) — there is no pkexec. The daemon binds its sockets under
// /run/ghost-sentri (systemd RuntimeDirectory).
//
// Personalities:
//   (default)        run the resident daemon (backends, sockets, def-check; tray
//                    only if a session bus is present)
//   --apt-hook       apt.conf.d pre-install hook — connect, get decision, exit code
//   --wrapper-hook   shell wrapper hook (terminal builds) — placeholder, exit 0
//   --apply          manual/offline root commit: write /etc config, apt hook,
//                    .deb MIME, optional freshclam — then exit. The LIVE path is
//                    apply::apply_config() called in-process by the daemon.
//   --quarantine-move <dir> <file> <threat> <defs> <sha256>
//   --quarantine-relocate <old-dir> <new-dir>
//                    Downloads-watch helpers. The daemon runs these as the USER
//                    (uid/gid switched, never root), so a planted symlink can't
//                    trick root into moving or chmod-ing a file. Refuse uid 0.
//
// Runtime: multi-thread tokio (2 workers). The daemon's work is socket I/O plus
// the occasional spawned subprocess; blocking work goes to the blocking pool.

mod apply;
mod backends;
mod daemon;
mod notice;
mod polkit;
mod scan_slot;
mod session;
mod tray;

use ghost_sentri_core::config::Config;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();

    // Manual/offline root commit. Live changes go through the daemon's polkit-gated
    // ApplyChanges handler; this CLI stays for scripted/offline use.
    //   --apply [--enable a,b] [--disable c,d] [--update-defs]
    if args.get(1).map(|s| s == "--apply").unwrap_or(false) {
        let mut enable: Vec<String> = Vec::new();
        let mut disable: Vec<String> = Vec::new();
        let mut update_defs = false;
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--enable"  => { i += 1; if i < args.len() { enable  = split_ids(&args[i]); } }
                "--disable" => { i += 1; if i < args.len() { disable = split_ids(&args[i]); } }
                "--update-defs" => update_defs = true,
                _ => {}
            }
            i += 1;
        }
        std::process::exit(apply::run_apply(enable, disable, update_defs));
    }

    // Quarantine helpers — run as the file's owner by the Downloads watch.
    if let Some(mode) = args.get(1).filter(|s| *s == "--quarantine-move" || *s == "--quarantine-relocate") {
        std::process::exit(quarantine_helper(mode, &args[2..]));
    }

    // apt.conf.d pre-install hook.
    if args.get(1).map(|s| s == "--apt-hook").unwrap_or(false) {
        let config = Config::load().unwrap_or_default();
        let code = backends::apt::apt_hook_main(&config.sentry.hook_socket_path).await;
        std::process::exit(code);
    }

    // Shell wrapper hook (terminal builds). Placeholder — approves, as before.
    if args.get(1).map(|s| s == "--wrapper-hook").unwrap_or(false) {
        std::process::exit(0);
    }

    // Resident daemon.
    let config = Config::load().unwrap_or_else(|e| {
        log::error!("config load failed: {e} — using defaults");
        Config::default()
    });

    // Single-instance guard: if a daemon is already listening on the control
    // socket, this start is a duplicate (re-login, manual `&`, autostart race).
    // Exit cleanly rather than stomping the existing socket and stacking daemons.
    let ctl = config.sentry.control_socket_path.clone();
    if std::os::unix::net::UnixStream::connect(&ctl).is_ok() {
        log::warn!("[guard] daemon already running at {} — exiting", ctl.display());
        std::process::exit(0);
    }

    if let Err(e) = daemon::GhostDaemon::new(config).run().await {
        log::error!("daemon exited with error: {e}");
        std::process::exit(1);
    }
}

/// `--quarantine-move` / `--quarantine-relocate`. Prints the new record as JSON
/// (move) and exits 0, or prints the error and exits 1.
fn quarantine_helper(mode: &str, a: &[String]) -> i32 {
    use ghost_sentri_core::quarantine;
    use std::path::Path;
    // SAFETY: getuid has no preconditions and cannot fail.
    if unsafe { libc::getuid() } == 0 {
        eprintln!("refusing to run the quarantine helper as root");
        return 1;
    }
    let res = match (mode, a) {
        ("--quarantine-move", [dir, file, threat, defs, sha]) => {
            quarantine::quarantine_file(Path::new(file), Path::new(dir), threat, defs, sha).and_then(|rec| {
                serde_json::to_string(&rec)
                    .map(|j| println!("{j}"))
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })
        }
        ("--quarantine-relocate", [old, new]) => quarantine::relocate(Path::new(old), Path::new(new)),
        _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad arguments")),
    };
    match res {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

/// Split a comma-separated id list ("apt,flatpak"), dropping empties.
fn split_ids(s: &str) -> Vec<String> {
    s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect()
}
