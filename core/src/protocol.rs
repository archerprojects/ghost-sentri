// core/src/protocol.rs
// Canonical wire types for every channel in the split architecture.
//
// There are THREE channels, at two trust levels:
//
//   1. hook.sock   (root-reachable, /run/ghost-sentri/hook.sock)
//        The apt pre-install hook (running as root) connects here and BLOCKS
//        until the daemon returns a decision. Narrow: install decisions only.
//        Wire form is hand-built JSON (see daemon/src/backends/apt.rs), not a
//        typed enum here.
//
//   2. control.sock (/run/ghost-sentri/control.sock)
//        The on-demand dashboard GUI connects here. The socket is world-
//        connectable (0666, relaxed by the root daemon); it is NOT protected by
//        file permissions — every privileged ControlRequest is gated per-call by
//        polkit (see daemon/src/polkit.rs). The daemon is the single source of
//        truth; the GUI is a viewer/controller.
//        Types: ControlRequest / ControlEvent.
//
//   3. worker stdio (no socket — pkexec pipes)
//        The unprivileged installer GUI pkexec's the headless `ghost-sentri-installer`
//        worker ONCE, up front, and drives it over stdin/stdout with line-delimited
//        JSON. The worker holds root for the whole sequence (scan + install + audit
//        log). Types: WorkerInbound (GUI->worker) / WorkerOutbound (worker->GUI).
//
// All enums serialize as {"type":"<snake_case>", ...fields}.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Shared
// ─────────────────────────────────────────────────────────────────────────────

/// The install avenue an event arrived through. Mirrors the monitor strip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Avenue {
    Apt,        // apt / dpkg / gdebi / Synaptic — caught by the apt.conf.d hook
    Nemo,       // file-manager double-click (MIME handler) — same dpkg family
    Flatpak,
    Snap,       // detect-and-log only — snapd does not permit pre-install gating
    Wine,
    Source,     // make install / curl|bash — disabled by default
}

/// How the worker should treat an install request.
///
/// The two avenues differ fundamentally:
///   * Nemo/standalone — no apt transaction is in flight, so the worker performs
///     the install itself (`apt install`).
///   * Apt hook — apt is ALREADY mid-transaction and merely held pending our
///     decision; the worker must NOT run a second apt (dpkg lock / re-entrancy).
///     It evaluates and returns approve/deny so apt's own transaction proceeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerMode {
    /// Worker runs the install itself (Nemo / standalone .deb).
    EvaluateAndInstall,
    /// Worker only scans + decides; apt performs the install (apt-hook path).
    EvaluateOnly,
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. hook.sock — install-decision protocol (root-reachable)
//
// The apt pre-install hook (running as root) connects here and BLOCKS until the
// daemon returns a decision. The wire form is hand-built JSON
// ({"type":"intercept","paths":[...],"backend":"apt"} → {"type":"decision",
// "action":"proceed"|"cancel"}); see daemon/src/backends/apt.rs.
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// 2. control.sock — dashboard GUI <-> daemon (user-only)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlRequest {
    /// On connect: ask for the current snapshot and subscribe to live events.
    Subscribe,
    /// Turn a monitor on/off. The daemon — which owns the backend task handles —
    /// actually spawns/aborts the backend, persists config, and broadcasts the
    /// new state. (This is what makes the monitor strip real rather than cosmetic.)
    ToggleMonitor { monitor: String, enable: bool },
    /// User-initiated definition update (daemon runs pkexec freshclam, streams).
    RequestDefinitionUpdate,
    /// Install the terminal-build shell wrappers (daemon owns WrapperBackend).
    InstallWrappers,
    /// Batch commit from the dashboard's "Confirm Selections". The privileged
    /// apply (config write, autostart, apt hook, .deb MIME, freshclam) now runs
    /// in a single root `--apply` invocation driven by the GUI via pkexec, so the
    /// commit works whether or not a daemon is running (fresh install has none).
    /// The daemon no longer performs the commit; it only reconciles on Reload.
    ApplyChanges { enable: Vec<String>, disable: Vec<String>, update_defs: bool },
    /// Re-read /etc config and reconcile running backend tasks to match it. Sent
    /// by the GUI after a successful root apply so an already-running daemon
    /// picks up the change live (no relogin needed for this session).
    Reload,
    /// Suspend / resume install scanning for THIS session only. RAM-only flag in
    /// the daemon — no config write, no polkit, no relogin. While suspended the
    /// apt-hook intercept proceeds without scanning (still logged). Resets to
    /// active on the next daemon start (login).
    SetActive { active: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlEvent {
    /// Full current state, sent immediately on Subscribe.
    StateSnapshot {
        monitors: Vec<MonitorState>,
        definition: DefinitionSnapshot,
        recent_log: Vec<String>,
        /// Daemon's own resident set size (VmRSS), in kB.
        resident_kb: u64,
        /// Whether install scanning is currently active (vs. session-suspended).
        active: bool,
    },
    /// Install scanning was suspended/resumed (echo of SetActive, or default).
    ActiveChanged { active: bool },
    /// Periodic daemon RSS push (every 300s) so the dashboard's resident figure
    /// stays current without a full snapshot.
    ResidentMemory { resident_kb: u64 },
    /// A new log line (live stream while the dashboard is open).
    LogLine { line: String },
    /// A monitor's state changed (echo of a successful toggle, or external change).
    MonitorChanged { monitor: String, enable: bool },
    /// Definition status changed (daemon's daily stat, or after an update).
    DefinitionStatus(DefinitionSnapshot),
    /// Streamed freshclam output during a user-initiated update.
    DefinitionUpdateProgress { message: String },
    /// Definition update finished.
    DefinitionUpdateComplete { success: bool },
    /// Result of an InstallWrappers request.
    WrappersInstalled { ok: bool, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorState {
    pub monitor: String,
    pub enabled: bool,
    pub available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefinitionSnapshot {
    pub version: String,
    pub age: String,
    pub stale: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. worker stdio — installer GUI <-> headless privileged worker
// ─────────────────────────────────────────────────────────────────────────────

/// GUI -> worker (written to the worker's stdin, one JSON object per line).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerInbound {
    /// The user's choice from the three intercept buttons.
    Choice { choice: InterceptChoice },
    /// Answer to a threat prompt after a scan flagged the package.
    ThreatDecision { install_anyway: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterceptChoice {
    Cancel,
    InstallWithoutScan,
    ScanThenInstall,
}

/// worker -> GUI (written to the worker's stdout, one JSON object per line).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerOutbound {
    /// Worker is elevated and waiting for the user's Choice. Emitted once at start.
    Ready,
    ScanStarted,
    ScanProgress { message: String },
    /// Scan finished clean — proceeding to install (or approving, in EvaluateOnly).
    ScanClean,
    /// Scan flagged a threat — GUI must prompt and reply with ThreatDecision.
    ScanThreat { name: String, plain_english: String },
    ScanError { message: String },
    InstallProgress { message: String },
    /// Terminal: the whole sequence is done. `approved` is the apt-hook decision
    /// (EvaluateOnly); `installed` is the result of a worker-run install.
    Done { approved: bool, installed: bool, message: String },
    Error { message: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers — line-delimited JSON framing used on every channel
// ─────────────────────────────────────────────────────────────────────────────

/// Serialize a message as a single newline-terminated JSON line.
pub fn to_line<T: Serialize>(msg: &T) -> serde_json::Result<String> {
    Ok(format!("{}\n", serde_json::to_string(msg)?))
}

/// Parse one JSON line into a message type.
pub fn from_line<T: for<'de> Deserialize<'de>>(line: &str) -> serde_json::Result<T> {
    serde_json::from_str(line.trim())
}
