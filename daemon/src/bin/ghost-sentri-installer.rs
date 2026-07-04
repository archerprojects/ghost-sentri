// daemon/src/bin/ghost-sentri-installer.rs — v1.0
// Privileged install worker. Headless, no GTK, no tokio — a short-lived state
// machine that holds root (it is pkexec'd ONCE by the unprivileged installer GUI
// at the up-front authorization) and drives scan + install + audit logging.
//
// Invocation:   ghost-sentri-installer <evaluate-only|evaluate-and-install> <path>
//
//   evaluate-only        apt-hook path: apt already holds the transaction, so the
//                        worker SCANS and DECIDES only — it must not run apt
//                        (re-entrancy / dpkg lock). Exit 0 = approve, 1 = block.
//   evaluate-and-install Nemo/standalone path: no apt transaction in flight, so
//                        the worker performs `apt install` itself.
//
// IPC: line-delimited JSON. Reads WorkerInbound on stdin, writes WorkerOutbound on
// stdout, flushing each line so the GUI sees progress live.
//
// Audit: every terminal outcome is appended to /var/log/ghost-sentri/events.jsonl
// (root-owned — this is the one process that holds root during an install, which
// is exactly why the audit write lives here and not in the unprivileged daemon).
//
// Fail-closed: a scan ERROR (package could not be scanned — extraction failure,
// bomb fault, clamscan unavailable) BLOCKS the install, matching the apt-hook
// path's `unscannable` hard-block. Only an explicit Install-Without-Scan choice
// bypasses the scan, and it is recorded as such.

use std::io::{BufRead, Write};
use std::process::{Command, Stdio};

use ghost_sentri_core::clam::{ScanResult, SystemClamBackend};
use ghost_sentri_core::config::Config;
use ghost_sentri_core::events::{self, Action, AuditEvent, ScanOutcome};
use ghost_sentri_core::protocol::{
    from_line, to_line, Avenue, InterceptChoice, WorkerInbound, WorkerMode, WorkerOutbound,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = match args.get(1).map(String::as_str) {
        Some("evaluate-only")        => WorkerMode::EvaluateOnly,
        Some("evaluate-and-install") => WorkerMode::EvaluateAndInstall,
        _ => {
            eprintln!("usage: ghost-sentri-installer <evaluate-only|evaluate-and-install> <path>");
            std::process::exit(2);
        }
    };
    let path = match args.get(2) {
        Some(p) => p.clone(),
        None => {
            eprintln!("error: missing package path");
            std::process::exit(2);
        }
    };

    let exit = run(mode, &path);
    std::process::exit(exit);
}

fn run(mode: WorkerMode, path: &str) -> i32 {
    let avenue = match mode {
        WorkerMode::EvaluateOnly        => Avenue::Apt,
        WorkerMode::EvaluateAndInstall  => Avenue::Nemo,
    };
    let user = invoking_user();
    let package = package_name(path);

    emit(&WorkerOutbound::Ready);

    // Await the user's choice.
    let choice = match read_inbound() {
        Some(WorkerInbound::Choice { choice }) => choice,
        _ => {
            // No choice / GUI closed — treat as cancel.
            audit(&user, avenue, Action::Cancelled, path, package.as_deref(), None, Some("no choice received"));
            return 1;
        }
    };

    match choice {
        InterceptChoice::Cancel => {
            audit(&user, avenue, Action::Cancelled, path, package.as_deref(), None, None);
            emit(&WorkerOutbound::Done { approved: false, installed: false, message: "Cancelled".into() });
            1
        }

        InterceptChoice::InstallWithoutScan => {
            finish(mode, avenue, &user, path, package.as_deref(), ScanOutcome::NotScanned)
        }

        InterceptChoice::ScanThenInstall => {
            emit(&WorkerOutbound::ScanStarted);
            let config = Config::load().unwrap_or_default();
            let clam = SystemClamBackend::new(config.resolve_clamscan(), config.resolve_definition_path());
            emit(&WorkerOutbound::ScanProgress { message: format!("Scanning {}…", short(path)) });

            match clam.scan_file(std::path::Path::new(path)) {
                ScanResult::Clean => {
                    emit(&WorkerOutbound::ScanClean);
                    finish(mode, avenue, &user, path, package.as_deref(), ScanOutcome::Clean)
                }
                ScanResult::Threat(detail) => {
                    emit(&WorkerOutbound::ScanThreat {
                        name: detail.name.clone(),
                        plain_english: detail.plain_english.clone(),
                    });
                    // Await the threat decision.
                    let install_anyway = matches!(
                        read_inbound(),
                        Some(WorkerInbound::ThreatDecision { install_anyway: true })
                    );
                    if install_anyway {
                        finish(mode, avenue, &user, path, package.as_deref(),
                               ScanOutcome::Threat { name: detail.name })
                    } else {
                        audit(&user, avenue, Action::Cancelled, path, package.as_deref(),
                              Some(ScanOutcome::Threat { name: detail.name }), Some("blocked by user"));
                        emit(&WorkerOutbound::Done { approved: false, installed: false, message: "Blocked — threat".into() });
                        1
                    }
                }
                ScanResult::Error(e) => {
                    // Fail CLOSED. A scan error means ClamAV could not vouch for this
                    // package (e.g. it could not be extracted to scan, or a bomb
                    // faulted the fence) — that is NOT clean and must not install. This
                    // matches the apt-hook path, which hard-blocks `unscannable`.
                    // Blocking here rather than a silent pass closes the gap where the
                    // same package installed via double-click but was blocked via apt.
                    // A user who still wants it can re-run and choose Install Without
                    // Scan explicitly — an informed override, never an automatic one.
                    emit(&WorkerOutbound::ScanError { message: e.clone() });
                    audit(&user, avenue, Action::Cancelled, path, package.as_deref(),
                          Some(ScanOutcome::Error { message: e }), Some("blocked — unscannable (fail-closed)"));
                    emit(&WorkerOutbound::Done {
                        approved: false,
                        installed: false,
                        message: "Blocked — package could not be scanned".into(),
                    });
                    1
                }
            }
        }
    }
}

/// Proceed past the decision: approve (EvaluateOnly) or install (EvaluateAndInstall),
/// then audit the terminal outcome.
fn finish(
    mode:    WorkerMode,
    avenue:  Avenue,
    user:    &str,
    path:    &str,
    package: Option<&str>,
    scan:    ScanOutcome,
) -> i32 {
    match mode {
        WorkerMode::EvaluateOnly => {
            // apt performs the install; we only approve the held transaction.
            audit(user, avenue, Action::Installed, path, package, Some(scan), Some("approved (apt-hook)"));
            emit(&WorkerOutbound::Done { approved: true, installed: false, message: "Approved".into() });
            0
        }
        WorkerMode::EvaluateAndInstall => {
            let ok = apt_install(path);
            let action = if ok { Action::Installed } else { Action::InstallFailed };
            audit(user, avenue, action, path, package, Some(scan), None);
            emit(&WorkerOutbound::Done {
                approved: true,
                installed: ok,
                message: if ok { "Installation complete".into() } else { "Installation failed".into() },
            });
            if ok { 0 } else { 1 }
        }
    }
}

/// Run `apt install -y <path>` as root (we already hold root), streaming status.
fn apt_install(path: &str) -> bool {
    let mut child = match Command::new("/usr/bin/apt")
        .args(["install", "-y", path])
        // Mark THIS apt transaction as Ghost Sentri's own. The apt.conf.d hook runs
        // as a child of this process and inherits the env; apt_hook_main sees the
        // flag and returns immediately, so the worker's install does not re-trigger
        // the intercept (which caused the duplicate dialog + second polkit + hang).
        .env("GS_HOOK_BYPASS", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            emit(&WorkerOutbound::Error { message: format!("apt launch failed: {e}") });
            return false;
        }
    };

    // Drain stderr so a full pipe can't wedge the child.
    if let Some(err) = child.stderr.take() {
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(err).lines().map_while(Result::ok) {
                eprintln!("[apt stderr] {line}");
            }
        });
    }
    if let Some(out) = child.stdout.take() {
        for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
            let t = line.trim();
            if !t.is_empty() && is_apt_status_line(t) {
                emit(&WorkerOutbound::InstallProgress { message: t.to_string() });
            }
        }
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

// ── IPC helpers ──────────────────────────────────────────────────────────────

fn emit(msg: &WorkerOutbound) {
    if let Ok(line) = to_line(msg) {
        let mut out = std::io::stdout();
        let _ = out.write_all(line.as_bytes());
        let _ = out.flush();
    }
}

fn read_inbound() -> Option<WorkerInbound> {
    let mut line = String::new();
    let n = std::io::stdin().lock().read_line(&mut line).ok()?;
    if n == 0 { return None; } // EOF
    from_line(&line).ok()
}

// ── Audit ────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn audit(
    user:    &str,
    avenue:  Avenue,
    action:  Action,
    path:    &str,
    package: Option<&str>,
    scan:    Option<ScanOutcome>,
    detail:  Option<&str>,
) {
    let mut ev = AuditEvent::new(user, avenue, action, path);
    if let Some(p) = package { ev = ev.with_package(p); }
    if let Some(s) = scan { ev = ev.with_scan(s); }
    if let Some(d) = detail { ev = ev.with_detail(d); }
    if let Err(e) = events::append(&ev) {
        eprintln!("[worker] audit write failed: {e}");
    }
}

// ── Misc ───────────────────────────────────────────────────────────────────--

/// The user who triggered the install. pkexec exports PKEXEC_UID; resolve it to a
/// name, falling back to SUDO_USER, then the raw uid, then "unknown".
fn invoking_user() -> String {
    if let Ok(uid) = std::env::var("PKEXEC_UID") {
        if let Ok(out) = Command::new("id").args(["-nu", &uid]).output() {
            if out.status.success() {
                let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !name.is_empty() { return name; }
            }
        }
        return format!("uid:{uid}");
    }
    std::env::var("SUDO_USER").unwrap_or_else(|_| "unknown".to_string())
}

fn package_name(path: &str) -> Option<String> {
    let out = Command::new("dpkg-deb").args(["-f", path, "Package"]).output().ok()?;
    if !out.status.success() { return None; }
    let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

fn short(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
        .to_string()
}

fn is_apt_status_line(line: &str) -> bool {
    line.starts_with("Get:")
        || line.starts_with("Unpack")
        || line.starts_with("Setting up")
        || line.starts_with("Processing")
        || line.starts_with("Preparing")
        || line.starts_with("Selecting")
}
