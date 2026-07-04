// daemon/src/daemon.rs — v5.0
// Resident, headless daemon. Single source of truth for the dashboard.
//
// Architecture (root system service):
//   - No GTK, no relm4. Runs as a ROOT systemd SYSTEM service
//     (ghost-sentri-daemon.service) — NOT in a user session. Privileged
//     control-socket requests are authorised per-call via polkit's
//     CheckAuthorization (polkit.rs); polkit routes the prompt into the caller's
//     own graphical session via logind, so the daemon needs no session and there
//     is no pkexec on this path.
//   - Owns the state: monitor task handles, mode, definition status, and a
//     bounded in-memory log ring for the dashboard.
//   - Serves the control socket under /run/ghost-sentri (0666, per-request polkit
//     gates the writes) — the on-demand dashboard connects, gets a snapshot, and
//     streams live events.
//   - Monitor toggles are REAL: the daemon owns the JoinHandles, so a toggle
//     starts/aborts the actual backend task; config is written by the in-process
//     root apply (apply.rs) after a polkit authorisation.
//   - Definition staleness check runs as a lightweight in-process daily interval
//     (no systemd timer). Definition UPDATES run freshclam directly (daemon is
//     root) after a polkit authorisation — never silent.
//   - Installs are NOT performed here — the privileged worker does that. For the
//     apt-hook path the hook process presents the daemon's headless verdict and
//     maps the outcome to the held apt transaction's proceed/cancel.
//   - The daemon does NOT write the /var/log audit file; the root worker writes
//     install events there during an install. The daemon keeps the live ring for
//     the dashboard.

use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::net::UnixListener;
use tokio::sync::{broadcast, mpsc};

use ghost_sentri_core::clam::{self, ScanResult, SystemClamBackend};
use ghost_sentri_core::config::Config;
use ghost_sentri_core::deb_inspect;
use ghost_sentri_core::protocol::{
    ControlEvent, ControlRequest, DefinitionSnapshot, MonitorState,
};

use crate::backends::{self, BackendKind, InterceptEvent, PackageVerdict, ScanVerdict};
use crate::tray::{self, TrayCommand};

const LOG_RING_CAP: usize = 500;
const BROADCAST_CAP: usize = 256;
const DEF_CHECK_INTERVAL_SECS: u64 = 60 * 60 * 24; // daily

// ─────────────────────────────────────────────────────────────────────────────
// Shared state
// ─────────────────────────────────────────────────────────────────────────────

pub struct DaemonState {
    pub config:     Config,
    pub log_ring:   VecDeque<String>,
    pub definition: DefinitionSnapshot,
    /// Live backend tasks, keyed by kind — aborting a handle stops a monitor.
    pub handles:    HashMap<BackendKind, tokio::task::JoinHandle<()>>,
    /// Session scan switch. true = scanning active; false = suspended (intercepts
    /// proceed without scanning). RAM-only; resets to true on daemon start.
    pub active:     bool,
}

pub type Shared = Arc<Mutex<DaemonState>>;

impl DaemonState {
    fn snapshot_monitors(&self) -> Vec<MonitorState> {
        // apt is the always-on intercept server; its "Packaged Apps" state is the
        // presence of the apt.conf.d hook file. Include it so the row shows correct
        // state on connect instead of waiting for a toggle echo.
        let apt = MonitorState {
            monitor:   "apt".to_string(),
            enabled:   std::path::Path::new("/etc/apt/apt.conf.d/99ghost-sentri").exists(),
            available: true,
        };
        std::iter::once(apt)
            .chain(backends::managed_kinds().into_iter().map(|k| MonitorState {
                monitor:   k.id().to_string(),
                enabled:   self.handles.contains_key(&k) || k.enabled_in(&self.config),
                available: true,
            }))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Daemon
// ─────────────────────────────────────────────────────────────────────────────

pub struct GhostDaemon {
    state:        Shared,
    clam:         SystemClamBackend,
    events_tx:    broadcast::Sender<ControlEvent>,
    intercept_tx: mpsc::Sender<InterceptEvent>,
    intercept_rx: mpsc::Receiver<InterceptEvent>,
}

impl GhostDaemon {
    pub fn new(config: Config) -> Self {
        let clam = SystemClamBackend::new(config.resolve_clamscan(), config.resolve_definition_path());
        let definition = DefinitionSnapshot { version: "checking…".into(), age: "".into(), stale: false };
        let state = Arc::new(Mutex::new(DaemonState {
            config,
            log_ring: VecDeque::with_capacity(LOG_RING_CAP),
            definition,
            handles: HashMap::new(),
            active: true,
        }));
        let (events_tx, _) = broadcast::channel(BROADCAST_CAP);
        let (intercept_tx, intercept_rx) = mpsc::channel(64);
        Self { state, clam, events_tx, intercept_tx, intercept_rx }
    }

    /// Push a log line into the ring and broadcast it to subscribers.
    fn log(&self, line: impl Into<String>) {
        let line = line.into();
        log::info!("{}", line);
        {
            let mut st = self.state.lock().unwrap();
            if st.log_ring.len() == LOG_RING_CAP { st.log_ring.pop_front(); }
            st.log_ring.push_back(line.clone());
        }
        let _ = self.events_tx.send(ControlEvent::LogLine { line });
    }

    pub async fn run(mut self) -> Result<()> {
        // The control socket is the dashboard's lifeline. Bind it FIRST and
        // SYNCHRONOUSLY, before any slower startup (definition checks shell out to
        // clamscan; backends; tray). On a slow runtime a spawned bind
        // would not run until the first await, and a blocking clamscan at early
        // login (autostart) can delay that indefinitely — leaving the daemon alive
        // but unreachable. Binding here means the socket file exists the instant the
        // daemon starts; connections queue in the listen backlog until accept runs.
        if let Some(listener) = self.bind_control_socket() {
            self.spawn_control_accept(listener);
        }

        self.ensure_quarantine().await;

        // Close any fence scratch a prior crash leaked (mounts/images under the scan
        // base) before the first scan can provision a new one.
        clam::sweep_stale_scratch();

        if !self.clam.is_available() {
            self.log("ClamAV (clamscan) not found — install with: sudo apt install clamav");
        }

        // Definition status on a daily interval. The first check fires immediately
        // inside the loop, off-thread, so clamscan never stalls startup.
        self.spawn_def_check_loop();
        self.spawn_resident_report();

        // The apt socket server is the intercept entry point — always on while the
        // daemon runs. The "Packaged Apps" monitor toggle controls the apt.conf.d
        // hook FILE, not this server.
        // NB: the lock guard MUST be dropped before re-locking below. A guard taken
        // in an `if let` scrutinee lives for the whole block, so locking inside the
        // body would deadlock on the same mutex. Resolve the handle first, lock drops.
        let apt_handle = {
            let cfg = self.state.lock().unwrap().config.clone();
            backends::start_backend(&BackendKind::Apt, self.intercept_tx.clone(), &cfg)
        };
        if let Some(h) = apt_handle {
            self.state.lock().unwrap().handles.insert(BackendKind::Apt, h);
        }

        // Managed monitors — started per enable_* flags (fresh install: all off).
        {
            let cfg = self.state.lock().unwrap().config.clone();
            let started = backends::probe_and_start(self.intercept_tx.clone(), &cfg);
            let names: Vec<String> = started.keys().map(|k| k.to_string()).collect();
            self.state.lock().unwrap().handles.extend(started);
            if names.is_empty() {
                self.log("No monitors enabled — toggle them on from the dashboard.");
            } else {
                self.log(format!("Monitors active: {}", names.join(", ")));
            }
        }

        // Tray (DBus). The ksni tray needs a user session bus; a root system
        // service has none, so start it only when one is present (e.g. running
        // the daemon by hand inside a session). Otherwise skip cleanly.
        if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_ok() {
            let tray_rx = tray::start();
            self.spawn_tray_watch(tray_rx);
        } else {
            self.log("System service mode — tray disabled (no session bus).");
        }

        self.log("Ghost Sentri daemon ready.");

        // Main intercept loop. It is serial (one event per recv), and hook+shim
        // duplicates of the same install are collapsed downstream by the content-hash
        // verdict cache in build_verdict → cached_scan, so no path-level dedupe is
        // needed here.
        while let Some(mut event) = self.intercept_rx.recv().await {
            let hook_respond = event.hook_respond.take();

            // Session suspend — proceed without scanning, but log it (no silent gap).
            if !self.state.lock().unwrap().active {
                if let Some(tx) = hook_respond { let _ = tx.send(ScanVerdict::suspended()); }
                self.log(format!("[SUSPENDED] Proceeded without scan: {}", event.filename()));
                continue;
            }

            match hook_respond {
                // Blocking apt-hook intercept → SCAN HEADLESSLY, return a verdict.
                // The hook process presents it (GUI into the live session / TTY /
                // policy) and decides proceed/cancel. The daemon never draws.
                Some(tx) => {
                    let mut paths = vec![event.path.clone()];
                    paths.extend(event.bulk_paths.clone());
                    self.log(format!(
                        "[Intercept] {} — scanning {} package(s)",
                        event.backend, paths.len(),
                    ));

                    let (clamscan, def_path) = {
                        let st = self.state.lock().unwrap();
                        (st.config.resolve_clamscan(), st.config.resolve_definition_path())
                    };
                    let verdict = tokio::task::spawn_blocking(move || {
                        build_verdict(paths, clamscan, def_path)
                    })
                    .await
                    .unwrap_or_else(|_| ScanVerdict { suspended: false, packages: vec![] });

                    self.log(verdict_summary(&event.filename(), &verdict));
                    let _ = tx.send(verdict);
                }
                // Non-blocking detection (flatpak/wine/snap) → log only (live ring).
                None => {
                    self.log(format!("[Detected] {} — {}", event.backend, event.filename()));
                }
            }
        }
        Ok(())
    }

    // ── Definitions ──────────────────────────────────────────────────────────

    /// Push the daemon's resident memory to subscribers every 300s.
    fn spawn_resident_report(&self) {
        let events = self.events_tx.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                tick.tick().await;
                let _ = events.send(ControlEvent::ResidentMemory { resident_kb: read_pss_kb() });
            }
        });
    }

    fn spawn_def_check_loop(&self) {
        let state = self.state.clone();
        let events = self.events_tx.clone();
        let clamscan  = state.lock().unwrap().config.resolve_clamscan();
        let def_path0 = state.lock().unwrap().config.resolve_definition_path();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(DEF_CHECK_INTERVAL_SECS));
            // First tick fires immediately — this replaces the old synchronous
            // startup refresh, but runs here off the startup path.
            loop {
                tick.tick().await;
                // clamscan is a blocking subprocess; to keep it off the reactor threads it
                // runs on the blocking pool rather than an async worker.
                let cs = clamscan.clone();
                let dp = def_path0.clone();
                let version = tokio::task::spawn_blocking(move || {
                    SystemClamBackend::new(cs, dp)
                        .get_definition_version()
                        .unwrap_or_else(|_| "unknown".to_string())
                })
                .await
                .unwrap_or_else(|_| "unknown".to_string());

                let (def_path, threshold) = {
                    let st = state.lock().unwrap();
                    (st.config.resolve_definition_path(), st.config.definitions.stale_threshold_days)
                };
                let status = clam::check_definition_status(&def_path, threshold, version);
                let snap = DefinitionSnapshot {
                    version: status.version_string.clone(),
                    age:     status.display_age(),
                    stale:   status.is_stale,
                };
                state.lock().unwrap().definition = snap.clone();
                let _ = events.send(ControlEvent::DefinitionStatus(snap));
            }
        });
    }

    // ── Control socket server ────────────────────────────────────────────────

    /// Bind the control socket SYNCHRONOUSLY. Called first in run() so the socket
    /// file exists the instant the daemon starts — connections then queue in the
    /// listen backlog until the accept loop is scheduled. tokio's UnixListener::bind
    /// is synchronous and only needs the runtime context (we are inside it).
    fn bind_control_socket(&self) -> Option<UnixListener> {
        let socket_path = self.state.lock().unwrap().config.sentry.control_socket_path.clone();
        if let Some(parent) = socket_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::remove_file(&socket_path);
        match UnixListener::bind(&socket_path) {
            Ok(listener) => {
                // World-accessible: the root daemon serves every user's GUI, and
                // privileged requests are gated per-call by polkit (see polkit.rs),
                // not by socket ownership. /run/ghost-sentri itself is 0755.
                if let Ok(meta) = std::fs::metadata(&socket_path) {
                    use std::os::unix::fs::PermissionsExt;
                    let mut p = meta.permissions();
                    p.set_mode(0o666);
                    let _ = std::fs::set_permissions(&socket_path, p);
                }
                log::info!("[control] listening at {:?}", socket_path);
                Some(listener)
            }
            Err(e) => { log::error!("[control] bind failed: {}", e); None }
        }
    }

    /// Spawn the accept loop for the already-bound control socket.
    fn spawn_control_accept(&self, listener: UnixListener) {
        let state = self.state.clone();
        let events_tx = self.events_tx.clone();
        let intercept_tx = self.intercept_tx.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let st = state.clone();
                        let ev = events_tx.clone();
                        let itx = intercept_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_control_client(stream, st, ev, itx).await {
                                log::debug!("[control] client ended: {}", e);
                            }
                        });
                    }
                    Err(e) => log::error!("[control] accept error: {}", e),
                }
            }
        });
    }

    fn spawn_tray_watch(&self, rx: std::sync::mpsc::Receiver<TrayCommand>) {
        tokio::spawn(async move {
            // Block on the std receiver off-reactor; shut the process down on request.
            let cmd = tokio::task::spawn_blocking(move || rx.recv()).await;
            if let Ok(Ok(TrayCommand::Shutdown)) = cmd {
                log::info!("[tray] shutdown requested");
                std::process::exit(0);
            }
        });
    }

    async fn ensure_quarantine(&self) {
        let q = self.state.lock().unwrap().config.quarantine.path.clone();
        if !q.exists() {
            let _ = tokio::fs::create_dir_all(&q).await;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Headless scan → verdict (apt-hook path)
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Scan dedupe cache
// ─────────────────────────────────────────────────────────────────────────────
//
// nala-repo and apt installs hit BOTH the apt Pre-Install-Pkgs hook AND the dpkg
// PATH-shim, so the same .deb would otherwise reload the ClamAV signature DB
// twice (~8s each). This cache returns the prior result for a .deb scanned within
// the last CACHE_TTL, keyed by CONTENT HASH (sha256) so a changed file — different
// bytes, different key — always re-scans; forgeable path/mtime are never trusted.
//
// Footprint: bounded (≤ CACHE_MAX entries, oldest evicted) and TTL-swept, so it
// is tens of KB that clear themselves between installs — transient housekeeping,
// not a standing engine-sized reservation. Only definitive verdicts (Clean /
// Threat) are cached; a transient Error re-scans next time rather than sticking.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

const CACHE_TTL: Duration = Duration::from_secs(120);
const CACHE_MAX: usize = 64;

#[allow(clippy::type_complexity)]
fn verdict_cache() -> &'static Mutex<std::collections::HashMap<String, (ScanResult, Instant)>> {
    static CACHE: OnceLock<Mutex<std::collections::HashMap<String, (ScanResult, Instant)>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// sha256 of a file via `sha256sum` (no new dependency — matches the subprocess
/// idiom used for clamscan/dpkg-deb/df). `None` if it can't be computed, in which
/// case the caller scans uncached rather than risk a wrong key.
fn deb_hash(path: &std::path::Path) -> Option<String> {
    let out = std::process::Command::new("sha256sum").arg(path).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .map(|h| h.to_string())
}

/// ClamAV scan with short-TTL dedupe. A fresh content-hash hit returns the cached
/// result (no DB reload); otherwise it scans and records the verdict.
fn cached_scan(clam: &SystemClamBackend, path: &std::path::Path) -> ScanResult {
    let key = match deb_hash(path) {
        Some(k) => k,
        None => return clam.scan_file(path), // unkeyable → scan, don't cache
    };
    let now = Instant::now();

    if let Ok(mut map) = verdict_cache().lock() {
        map.retain(|_, (_, t)| now.duration_since(*t) < CACHE_TTL); // sweep stale
        if let Some((res, _)) = map.get(&key) {
            return res.clone(); // fresh hit — no rescan
        }
    }

    let res = clam.scan_file(path);

    // Cache only definitive verdicts; a transient Error must re-scan next time.
    if !matches!(res, ScanResult::Error(_)) {
        if let Ok(mut map) = verdict_cache().lock() {
            if map.len() >= CACHE_MAX {
                if let Some(oldest) =
                    map.iter().min_by_key(|(_, (_, t))| *t).map(|(k, _)| k.clone())
                {
                    map.remove(&oldest);
                }
            }
            map.insert(key, (res.clone(), now));
        }
    }
    res
}

// ─────────────────────────────────────────────────────────────────────────────

/// Scan every held package as root, with NO display required: a ClamAV signature
/// scan plus the deb_inspect heuristic per `.deb`. Pure authority — presentation
/// and the proceed/cancel decision belong to the hook process. Runs on the
/// blocking pool (clamscan + dpkg-deb are subprocesses).
fn build_verdict(paths: Vec<std::path::PathBuf>, clamscan: std::path::PathBuf, def_path: std::path::PathBuf) -> ScanVerdict {
    let clam = SystemClamBackend::new(clamscan, def_path);
    let medium = deb_inspect::Severity::Medium as u8;
    let mut packages = Vec::new();

    for path in &paths {
        // ── ClamAV signature scan (the hard-block authority) ──
        // A threat is a positive hit. An ERROR means ClamAV could not vouch for
        // the package at all (e.g. it could not be extracted to scan) — that is
        // NOT clean: it is captured as `unscannable` and hard-blocked downstream,
        // never silently passed.
        let scan = cached_scan(&clam, path);
        let (threat, threat_detail) = match &scan {
            ScanResult::Threat(d) => (Some(d.name.clone()), Some(d.plain_english.clone())),
            _ => (None, None),
        };
        let unscannable = match &scan {
            ScanResult::Error(e) => Some(e.clone()),
            _ => None,
        };

        // ── Heuristic + structural inspection (advisory) ──
        match deb_inspect::inspect(path) {
            Ok(r) => {
                let band = match r.script_risk {
                    deb_inspect::RiskBand::Clean => "clean",
                    deb_inspect::RiskBand::Suspicious => "suspicious",
                    deb_inspect::RiskBand::HighRisk => "highrisk",
                }
                .to_string();
                let mut findings = Vec::new();
                for s in &r.maintainer_scripts {
                    for f in &s.findings {
                        if (f.severity as u8) >= medium {
                            findings.push(format!("{} L{}: {}", s.name, f.line, f.message));
                        }
                    }
                }
                packages.push(PackageVerdict {
                    path: path.to_string_lossy().into_owned(),
                    name: r.package.clone(),
                    version: r.version.clone(),
                    band,
                    threat,
                    threat_detail,
                    findings,
                    setuid: !r.setuid_files.is_empty(),
                    adds_apt_source: r.adds_apt_source || r.adds_gpg_key,
                    inspect_failed: false,
                    unscannable,
                });
            }
            Err(_) => {
                // Inspection failed — surface it, never silently pass. A ClamAV
                // threat verdict is still carried through.
                packages.push(PackageVerdict {
                    path: path.to_string_lossy().into_owned(),
                    name: path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown").to_string(),
                    version: String::new(),
                    band: "clean".into(),
                    threat,
                    threat_detail,
                    findings: vec![],
                    setuid: false,
                    adds_apt_source: false,
                    inspect_failed: true,
                    unscannable,
                });
            }
        }
    }

    ScanVerdict { suspended: false, packages }
}

/// One-line dashboard log summarising a verdict.
fn verdict_summary(filename: &str, v: &ScanVerdict) -> String {
    if v.has_threat() {
        let names: Vec<&str> = v.threats().iter().filter_map(|p| p.threat.as_deref()).collect();
        format!("[Intercept] {} — THREAT: {}", filename, names.join(", "))
    } else {
        let flagged = v.flagged().len();
        format!(
            "[Intercept] {} — scanned {} pkg(s), {} flagged for review",
            filename, v.packages.len(), flagged,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Control client handler
// ─────────────────────────────────────────────────────────────────────────────

/// Daemon's private (unshared) resident memory in kB —
/// `Private_Clean + Private_Dirty` from smaps_rollup, matching the system
/// monitor's memory column (excludes shared-library pages). VmRSS fallback.
fn read_pss_kb() -> u64 {
    if let Ok(rollup) = std::fs::read_to_string("/proc/self/smaps_rollup") {
        let mut sum = 0u64;
        let mut found = false;
        for l in rollup.lines() {
            for key in ["Private_Clean:", "Private_Dirty:"] {
                if let Some(v) = l.strip_prefix(key)
                    .and_then(|v| v.split_whitespace().next())
                    .and_then(|n| n.parse::<u64>().ok())
                {
                    sum += v;
                    found = true;
                }
            }
        }
        if found {
            return sum;
        }
    }
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:").and_then(|v| v.split_whitespace().next()).and_then(|n| n.parse().ok()))
        .unwrap_or(0)
}

async fn handle_control_client(
    stream:       tokio::net::UnixStream,
    state:        Shared,
    events_tx:    broadcast::Sender<ControlEvent>,
    intercept_tx: mpsc::Sender<InterceptEvent>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    // Identify the caller for per-request polkit authorization (SO_PEERCRED).
    let (peer_uid, peer_pid) = match stream.peer_cred() {
        Ok(c) => (c.uid(), c.pid().map(|p| p as u32)),
        Err(_) => (u32::MAX, None),
    };

    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut lines = BufReader::new(read_half).lines();
    let mut sub = events_tx.subscribe();

    // Send the snapshot up front.
    let snapshot = {
        let st = state.lock().unwrap();
        ControlEvent::StateSnapshot {
            monitors: st.snapshot_monitors(),
            definition: st.definition.clone(),
            recent_log: st.log_ring.iter().cloned().collect(),
            resident_kb: read_pss_kb(),
            active: st.active,
        }
    };
    write_half.write_all(ghost_sentri_core::protocol::to_line(&snapshot)?.as_bytes()).await?;

    loop {
        tokio::select! {
            // Inbound request from the dashboard.
            maybe_line = lines.next_line() => {
                let line = match maybe_line? { Some(l) => l, None => break };
                if line.trim().is_empty() { continue; }
                if let Ok(req) = ghost_sentri_core::protocol::from_line::<ControlRequest>(&line) {
                    handle_request(req, peer_uid, peer_pid, &state, &events_tx, &intercept_tx).await;
                }
            }
            // Outbound broadcast to the dashboard.
            ev = sub.recv() => {
                match ev {
                    Ok(ev) => {
                        write_half.write_all(ghost_sentri_core::protocol::to_line(&ev)?.as_bytes()).await?;
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        }
    }
    Ok(())
}

/// Authorise the calling subject for the manage action via polkit. Blocking
/// D-Bus, so it runs on the blocking pool. Denies if the caller's pid is unknown.
async fn authorize(peer_pid: Option<u32>, peer_uid: u32) -> bool {
    match peer_pid {
        Some(pid) => tokio::task::spawn_blocking(move || {
            crate::polkit::check_authorization(pid, peer_uid, true)
        }).await.unwrap_or(false),
        None => false,
    }
}

async fn handle_request(
    req:          ControlRequest,
    peer_uid:     u32,
    peer_pid:     Option<u32>,
    state:        &Shared,
    events_tx:    &broadcast::Sender<ControlEvent>,
    intercept_tx: &mpsc::Sender<InterceptEvent>,
) {
    match req {
        ControlRequest::Subscribe => { /* snapshot already sent on connect */ }

        // Single-monitor reconcile (kept for compatibility). No write, so no auth.
        ControlRequest::ToggleMonitor { .. } => handle_reload(state, events_tx, intercept_tx).await,

        // Disabled in this build. WrapperBackend resolves the target rc files from
        // dirs::home_dir(), which under the ROOT system daemon is /root — so this
        // would write shell wrappers into root's .bashrc, not the requesting user's.
        // Terminal-build wrapper install belongs on the GUI side (per-user, resolved
        // from the invoking uid) and lands with the traced-source-install feature.
        // Refuse cleanly rather than corrupt root's shell config.
        ControlRequest::InstallWrappers => {
            let _ = events_tx.send(ControlEvent::WrappersInstalled {
                ok: false,
                message: "Terminal-build wrappers are not available in this build.".into(),
            });
        }

        // User-initiated definition update. The daemon is root, so it runs
        // freshclam directly (no pkexec) after a polkit authorization.
        ControlRequest::RequestDefinitionUpdate => {
            if !authorize(peer_pid, peer_uid).await {
                let _ = events_tx.send(ControlEvent::LogLine {
                    line: "Authorisation declined — definitions not updated.".into(),
                });
                let _ = events_tx.send(ControlEvent::DefinitionUpdateComplete { success: false });
                return;
            }
            let events = events_tx.clone();
            let cfg = state.lock().unwrap().config.clone();
            tokio::task::spawn_blocking(move || {
                use std::io::{BufRead, BufReader};
                use std::process::Stdio;
                let child = Command::new("freshclam")
                    .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn();
                match child {
                    Ok(mut c) => {
                        if let Some(out) = c.stdout.take() {
                            for line in BufReader::new(out).lines().map_while(Result::ok) {
                                let _ = events.send(ControlEvent::DefinitionUpdateProgress { message: line });
                            }
                        }
                        let ok = c.wait().map(|s| s.success()).unwrap_or(false);
                        if ok {
                            let def_path = cfg.resolve_definition_path();
                            let clamscan = cfg.resolve_clamscan();
                            let version  = SystemClamBackend::new(clamscan, def_path.clone())
                                .get_definition_version().unwrap_or_default();
                            let status = clam::check_definition_status(
                                &def_path, cfg.definitions.stale_threshold_days, version,
                            );
                            let _ = events.send(ControlEvent::DefinitionStatus(
                                ghost_sentri_core::protocol::DefinitionSnapshot {
                                    version: status.version_string.clone(),
                                    age:     status.display_age(),
                                    stale:   status.is_stale,
                                },
                            ));
                        }
                        let _ = events.send(ControlEvent::DefinitionUpdateComplete { success: ok });
                    }
                    Err(e) => {
                        let _ = events.send(ControlEvent::DefinitionUpdateProgress {
                            message: format!("freshclam launch failed: {e}"),
                        });
                        let _ = events.send(ControlEvent::DefinitionUpdateComplete { success: false });
                    }
                }
            });
        }

        // Batch commit from the dashboard. The daemon (root) authorises the caller
        // via polkit, then writes /etc config + the .deb handler IN-PROCESS and
        // reconciles running monitors live — no relogin, no pkexec.
        ControlRequest::ApplyChanges { enable, disable, update_defs } => {
            if !authorize(peer_pid, peer_uid).await {
                let _ = events_tx.send(ControlEvent::LogLine {
                    line: "Authorisation declined — no changes applied.".into(),
                });
                return;
            }
            let (en, di) = (enable.clone(), disable.clone());
            let (ok, defs_attempted, defs_ok) = tokio::task::spawn_blocking(move || {
                crate::apply::apply_config(&en, &di, update_defs)
            }).await.unwrap_or((false, false, false));

            if !ok {
                let _ = events_tx.send(ControlEvent::LogLine {
                    line: "Apply failed — see daemon journal.".into(),
                });
                return;
            }
            if defs_attempted {
                let _ = events_tx.send(ControlEvent::LogLine {
                    line: if defs_ok { "Virus definitions updated.".into() }
                          else { "[ERROR] Definition update failed.".to_string() },
                });
            }
            // Reconcile tasks against the freshly-written /etc config + broadcast
            // MonitorChanged for each transition (the GUI commits its display from
            // these). Changes are live this session.
            handle_reload(state, events_tx, intercept_tx).await;
            let _ = events_tx.send(ControlEvent::LogLine { line: "Selections applied.".into() });
        }

        // Re-read /etc config and reconcile running backend tasks to match it.
        ControlRequest::Reload => handle_reload(state, events_tx, intercept_tx).await,

        // Session scan suspend/resume — RAM-only, no config write, no polkit.
        // Session scan suspend/resume — RAM-only, no config write. Still polkit-gated:
        // the control socket is world-connectable (0666 + per-request polkit), so an
        // ungated suspend would let any local process silently disable install
        // scanning machine-wide before the next `apt install`. One auth per toggle.
        ControlRequest::SetActive { active } => {
            if !authorize(peer_pid, peer_uid).await {
                let _ = events_tx.send(ControlEvent::LogLine {
                    line: "Authorisation declined — scanning state unchanged.".into(),
                });
                // Echo the unchanged state so the GUI reverts its optimistic toggle.
                let current = state.lock().unwrap().active;
                let _ = events_tx.send(ControlEvent::ActiveChanged { active: current });
                return;
            }
            state.lock().unwrap().active = active;
            let _ = events_tx.send(ControlEvent::ActiveChanged { active });
            let _ = events_tx.send(ControlEvent::LogLine {
                line: if active { "Install scanning resumed.".into() }
                      else { "Install scanning suspended for this session.".into() },
            });
        }
    }
}

/// Reconcile running backend tasks against /etc config after a root --apply.
/// The root apply is the sole writer of config and system files; the daemon only
/// reads the result and starts/stops its managed monitor tasks to match. apt has
/// no per-task lifecycle here — its hook server is always resident and its
/// interception is gated by the apt.conf.d hook file (written by --apply), so its
/// state is reported from that file's presence.
///
/// No await is held across the state lock (start_backend only spawns), so this
/// cannot reintroduce the cross-await lock contention that caused the historical
/// connect deadlock.
async fn handle_reload(
    state:        &Shared,
    events_tx:    &broadcast::Sender<ControlEvent>,
    intercept_tx: &mpsc::Sender<InterceptEvent>,
) {
    let new_cfg = Config::load().unwrap_or_default();

    let mut started: Vec<String> = Vec::new();
    let mut stopped: Vec<String> = Vec::new();
    {
        let mut st = state.lock().unwrap();
        st.config = new_cfg.clone();
        for kind in backends::managed_kinds() {
            if kind == BackendKind::Apt { continue; }
            let want = kind.enabled_in(&new_cfg);
            let running = st.handles.contains_key(&kind);
            if want && !running {
                if let Some(h) = backends::start_backend(&kind, intercept_tx.clone(), &new_cfg) {
                    st.handles.insert(kind.clone(), h);
                    started.push(kind.id().to_string());
                }
            } else if !want && running {
                if let Some(h) = st.handles.remove(&kind) { h.abort(); }
                stopped.push(kind.id().to_string());
            }
        }
    } // lock dropped before broadcasting

    for id in started {
        let _ = events_tx.send(ControlEvent::MonitorChanged { monitor: id, enable: true });
    }
    for id in stopped {
        let _ = events_tx.send(ControlEvent::MonitorChanged { monitor: id, enable: false });
    }
    // apt state reflects the hook file written by --apply.
    let apt_on = std::path::Path::new("/etc/apt/apt.conf.d/99ghost-sentri").exists();
    let _ = events_tx.send(ControlEvent::MonitorChanged { monitor: "apt".into(), enable: apt_on });
}
