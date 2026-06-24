// src/backends/apt.rs — v2.5
// APT hook socket server — pre-install intercept via dpkg hook
// InstallRequest from installer.rs passes through without intercept dialog —
// Ghost Sentri owns that install, daemon runs it directly via pkexec
// Protocol:
//   Hook/Installer → Daemon: {"type":"intercept","paths":[...],"backend":"apt"}
//                         or {"type":"install_request","path":"..."}
//   Daemon → Hook:  {"type":"decision","action":"proceed"} | "cancel"

use super::{BackendKind, InterceptBackend, InterceptEvent, PackageVerdict, ScanVerdict};
use crate::session;
use anyhow::Result;
use async_trait::async_trait;
use std::io::{BufRead, IsTerminal, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::UnixListener;
use tokio::sync::mpsc;

pub struct AptBackend {
    socket_path: PathBuf,
}

impl AptBackend {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    async fn run_socket_server(&self, sender: mpsc::Sender<InterceptEvent>) -> Result<()> {
        if let Some(parent) = self.socket_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        if self.socket_path.exists() {
            tokio::fs::remove_file(&self.socket_path).await?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        log::info!("[AptBackend] hook socket at {:?}", self.socket_path);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let s = sender.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, s).await {
                            log::error!("[AptBackend] connection error: {}", e);
                        }
                    });
                }
                Err(e) => log::error!("[AptBackend] accept error: {}", e),
            }
        }
    }
}

#[async_trait]
impl InterceptBackend for AptBackend {
    fn kind(&self) -> BackendKind { BackendKind::Apt }

    fn is_available(&self) -> bool {
        std::path::Path::new("/usr/bin/dpkg").exists()
            || std::path::Path::new("/bin/dpkg").exists()
    }

    async fn run(&self, sender: mpsc::Sender<InterceptEvent>) -> Result<()> {
        self.run_socket_server(sender).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connection handler — handles both APT hook intercepts and install requests
// ─────────────────────────────────────────────────────────────────────────────

async fn handle_connection(
    stream: tokio::net::UnixStream,
    sender: mpsc::Sender<InterceptEvent>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = TokioBufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let msg: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v)  => v,
            Err(_) => continue,
        };

        match msg["type"].as_str() {
            // ── APT hook intercept ────────────────────────────────────────────
            Some("intercept") => {
                let paths: Vec<PathBuf> = msg["paths"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|v| v.as_str().map(PathBuf::from))
                    .collect();

                if paths.is_empty() {
                    write_verdict(&mut writer, &ScanVerdict { suspended: false, packages: vec![] }).await?;
                    continue;
                }

                let (resp_tx, resp_rx) = tokio::sync::oneshot::channel::<ScanVerdict>();

                let mut pkg_paths = paths;
                let primary       = pkg_paths.remove(0);
                let mut evt       = InterceptEvent::new(primary, BackendKind::Apt);
                evt.bulk_paths    = pkg_paths;
                evt.hook_respond  = Some(resp_tx);

                if sender.send(evt).await.is_err() {
                    // Daemon loop gone — fail open (empty verdict = nothing to act on).
                    write_verdict(&mut writer, &ScanVerdict { suspended: false, packages: vec![] }).await?;
                    continue;
                }

                let verdict = resp_rx.await.unwrap_or(ScanVerdict { suspended: false, packages: vec![] });
                write_verdict(&mut writer, &verdict).await?;
            }

            // install_request is gone in the split — the privileged worker performs
            // installs directly (it holds root from the up-front polkit prompt), so
            // the daemon no longer routes installs over this socket.

            _ => {}
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Verdict writer (daemon → hook over the socket)
// ─────────────────────────────────────────────────────────────────────────────

async fn write_verdict<W>(w: &mut W, v: &ScanVerdict) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let json = serde_json::to_string(v)
        .unwrap_or_else(|_| "{\"suspended\":false,\"packages\":[]}".to_string());
    w.write_all(json.as_bytes()).await?;
    w.write_all(b"\n").await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Hook entry point — ghost-sentri-daemon --apt-hook
// Called by apt's DPkg::Pre-Install-Pkgs hook before dpkg installs. Reads package
// paths from stdin, asks the daemon to SCAN (headless), then PRESENTS the verdict
// wherever the user is and returns the apt decision.
//   Exit 0 = proceed, Exit 1 = block (apt aborts the transaction).
// The daemon scans; the hook presents. The hook runs as root in the apt context,
// so it (not the session-less daemon) is the thing that can reach a display or a
// terminal.
// ─────────────────────────────────────────────────────────────────────────────

pub async fn apt_hook_main(socket_path: &PathBuf) -> i32 {
    use std::io::BufReader;
    let stdin  = std::io::stdin();
    let reader = BufReader::new(stdin.lock());

    // Ghost Sentri's own worker sets this on its apt transaction — never intercept
    // our own install. Check FIRST, before stdin.
    if std::env::var("GS_HOOK_BYPASS").is_ok() {
        return 0;
    }

    let mut paths: Vec<String> = vec![];
    for line in reader.lines() {
        match line {
            Ok(l) if !l.trim().is_empty() => paths.push(l.trim().to_string()),
            _ => break,
        }
    }

    if paths.is_empty() {
        return 0;
    }

    // Belt-and-braces: auto-approve a transaction that is Ghost Sentri itself.
    if paths.iter().all(|p| p.contains("ghost-sentri")) {
        return 0;
    }

    match tokio::net::UnixStream::connect(socket_path).await {
        Ok(mut stream) => {
            let payload = serde_json::json!({
                "type":    "intercept",
                "paths":   paths,
                "backend": "apt"
            });
            if stream.write_all(format!("{}\n", payload).as_bytes()).await.is_err() {
                return 0; // fail open
            }

            let mut reader   = TokioBufReader::new(stream);
            let mut response = String::new();

            // The daemon holds the response until the scan finishes (seconds on a
            // multi-package transaction). Show an indeterminate spinner on the
            // terminal so the user knows work is happening, not stalled. Cosmetic
            // only — gated to a real TTY, wiped before any further output.
            let spinner = ScanSpinner::start(paths.len());
            let read = reader.read_line(&mut response).await;
            spinner.stop().await;

            if read.is_err() {
                return 0; // fail open
            }

            let verdict: ScanVerdict = match serde_json::from_str(response.trim()) {
                Ok(v) => v,
                Err(_) => return 0, // unparseable → fail open, never break apt
            };

            present_and_decide(&verdict)
        }
        Err(_) => {
            // Daemon not running — nothing is being monitored. Allow + log.
            log::info!("[apt-hook] Ghost Sentri not running — install allowed without scan");
            0
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan activity spinner (cosmetic)
// ─────────────────────────────────────────────────────────────────────────────

/// Indeterminate terminal spinner shown on stderr while the daemon scans. It
/// signals that work is in progress, nothing more — there is no per-file progress
/// to report. Animates a single line and wipes it on stop. Does NOTHING when
/// stderr is not a terminal (piped or unattended apt), so it never writes control
/// codes into a log; over SSH the tty IS a terminal, so the indicator still shows.
struct ScanSpinner {
    stop:   Arc<AtomicBool>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl ScanSpinner {
    fn start(count: usize) -> Self {
        let label = format!(
            "Ghost Sentri: scanning {} package{}…",
            count,
            if count == 1 { "" } else { "s" }
        );
        // Not a terminal (piped/unattended) → no indicator at all.
        if !std::io::stderr().is_terminal() {
            return Self { stop: Arc::new(AtomicBool::new(true)), handle: None };
        }
        // Invoked under a frontend that draws its own live UI — the dpkg shim sets
        // GS_NO_SPINNER because nala animates its own progress bar. A rewriting
        // spinner fights that frontend's cursor and stacks up, so print ONE static
        // line instead: it scrolls normally and still shows work is happening.
        if std::env::var_os("GS_NO_SPINNER").is_some() {
            let _ = writeln!(std::io::stderr(), "{label}");
            return Self { stop: Arc::new(AtomicBool::new(true)), handle: None };
        }
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let handle = tokio::spawn(async move {
            const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let mut i = 0usize;
            let mut err = std::io::stderr();
            while !flag.load(Ordering::Relaxed) {
                let _ = write!(err, "\r{} {}", FRAMES[i % FRAMES.len()], label);
                let _ = err.flush();
                i = i.wrapping_add(1);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            // Wipe the spinner line so the next output starts clean.
            let _ = write!(err, "\r\x1b[K");
            let _ = err.flush();
        });
        Self { stop, handle: Some(handle) }
    }

    /// Stop the animation and wait for it to clear its line, so nothing prints over
    /// a half-drawn frame. A no-op spinner (non-TTY) returns immediately.
    async fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
    }
}

impl Drop for ScanSpinner {
    // Belt: if the guard is ever dropped without `stop().await` (e.g. a future
    // early return), still signal the task to exit rather than animate forever.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Presentation + decision (hook side)
// ─────────────────────────────────────────────────────────────────────────────

/// Map a scan verdict to the apt decision, presenting where the user is:
///   • THREAT (ClamAV hit)  → hard block, always, no display needed.
///   • CLEAN                → proceed silently.
///   • RECOMMEND (flagged)  → GUI into the live session, else TTY review, else
///                            policy (proceed-with-warning).
fn present_and_decide(v: &ScanVerdict) -> i32 {
    if v.suspended {
        return 0;
    }

    // Hard stop: a signature hit is acted on regardless of context.
    let threats = v.threats();
    if !threats.is_empty() {
        eprintln!("\nGhost Sentri BLOCKED this install — malware signature detected:");
        for p in &threats {
            eprintln!("    {} {}  →  {}", p.name, p.version, p.threat.as_deref().unwrap_or("threat"));
        }
        eprintln!("Nothing was installed. See the Ghost Sentri dashboard.\n");
        return 1;
    }

    // Hard stop: ClamAV could not vouch for a package (e.g. insufficient disk to
    // extract it for scanning). Fail closed — an unscannable package is never
    // allowed through on the assumption it is clean.
    let unscannable = v.unscannable();
    if !unscannable.is_empty() {
        eprintln!("\nGhost Sentri BLOCKED this install — a package could not be scanned:");
        for p in &unscannable {
            eprintln!("    {} {}  →  {}", p.name, p.version, p.unscannable.as_deref().unwrap_or("scan could not complete"));
        }
        eprintln!("Nothing was installed.\n");
        return 1;
    }

    let flagged = v.flagged();
    if flagged.is_empty() {
        return 0; // clean — proceed
    }

    // RECOMMEND-REVIEW — ask the user wherever they are.
    if let Some(sess) = session::resolve_active_graphical() {
        return present_gui(&flagged, &sess);
    }
    if let Some(tty) = open_tty() {
        return present_tty(&flagged, tty);
    }

    // No session, no terminal — unattended. Policy: proceed with warning, logged.
    // (THREAT already hard-blocked above; the heuristic has deliberate false
    // positives and must not break unattended apt.)
    eprintln!(
        "Ghost Sentri: {} package(s) flagged for review, but no interactive session — \
         proceeding per policy. See the Ghost Sentri dashboard.",
        flagged.len()
    );
    0
}

/// Launch the full P4 review GUI into the resolved session, once per flagged
/// package (after triage this is typically 0–2). Any cancel blocks the whole
/// transaction (apt is all-or-nothing). If the GUI cannot launch despite a
/// resolved session, fall back to the TTY, then to warn-and-proceed.
fn present_gui(flagged: &[&PackageVerdict], sess: &session::Session) -> i32 {
    for p in flagged {
        let status = Command::new("ghost-sentri")
            .arg("--install")
            .arg(&p.path)
            .arg("--apt-hook")
            .uid(sess.uid)
            .gid(sess.gid)
            .env_clear()
            .env("HOME", &sess.home)
            .env("USER", &sess.user)
            .env("LOGNAME", &sess.user)
            .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
            .envs(sess.env.iter().cloned())
            .status();
        match status {
            Ok(s) if s.success() => {}        // approved this package
            Ok(_) => return 1,                // user cancelled → block transaction
            Err(_) => {
                // Resolved a session but couldn't launch the GUI — degrade, don't block.
                if let Some(tty) = open_tty() {
                    return present_tty(flagged, tty);
                }
                eprintln!(
                    "Ghost Sentri: review GUI could not launch; {} flagged package(s) \
                     proceeding per policy. See the dashboard.",
                    flagged.len()
                );
                return 0;
            }
        }
    }
    0
}

fn open_tty() -> Option<std::fs::File> {
    std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").ok()
}

/// Compact terminal review (SSH / console): per-package band + flags + top
/// findings, then a single y/N prompt on the controlling terminal.
fn present_tty(flagged: &[&PackageVerdict], tty: std::fs::File) -> i32 {
    use std::io::{BufRead, BufReader, Write};

    let mut out = String::new();
    out.push_str("\n── Ghost Sentri — package review ───────────────────────────────\n");
    for p in flagged {
        out.push_str(&format!("  {} {}   [risk: {}]\n", p.name, p.version, p.band));
        if p.inspect_failed {
            out.push_str("      • inspection failed — could not read this package\n");
        }
        if p.setuid {
            out.push_str("      • installs a setuid/setgid executable\n");
        }
        if p.adds_apt_source {
            out.push_str("      • adds an APT source or signing key\n");
        }
        for f in p.findings.iter().take(4) {
            out.push_str(&format!("      • {}\n", f));
        }
        if p.findings.len() > 4 {
            out.push_str(&format!("      • … {} more finding(s)\n", p.findings.len() - 4));
        }
    }
    out.push_str("────────────────────────────────────────────────────────────────\n");
    out.push_str(&format!(
        "Proceed with installation of {} flagged package(s)? [y/N] ",
        flagged.len()
    ));

    let mut w = &tty;
    if w.write_all(out.as_bytes()).is_err() || w.flush().is_err() {
        return 1; // can't present → don't auto-install a flagged package
    }

    let reader = match tty.try_clone() {
        Ok(f) => f,
        Err(_) => return 1,
    };
    let mut line = String::new();
    if BufReader::new(reader).read_line(&mut line).is_err() {
        return 1;
    }
    let ans = line.trim().to_lowercase();
    if ans == "y" || ans == "yes" {
        0
    } else {
        1
    }
}
