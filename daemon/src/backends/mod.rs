// daemon/src/backends/mod.rs
// Split notes:
//   - Lives in the `daemon` crate; shared types come from ghost_sentri_core.
//   - Snap backend (detect-and-log; snapd permits no pre-install gate) — a real
//     toggleable monitor via config.backends.enable_snap.
//   - InstallRequest path REMOVED — the privileged worker performs installs now,
//     so the daemon no longer routes installs over the socket. InterceptEvent
//     loses is_install_request / install_respond.
//   - probe_and_start GATES on config.backends.enable_* and the daemon owns the
//     task handles so a monitor toggle can actually start/stop a backend at runtime.

pub mod apt;
pub mod flatpak_backend;
pub mod snap;
pub mod source;
pub mod wine;
pub mod wrapper;

use anyhow::Result;
use async_trait::async_trait;
use ghost_sentri_core::config::Config;
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

// ─────────────────────────────────────────────────────────────────────────────
// BackendKind
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BackendKind {
    Apt,
    Flatpak,
    Wine,
    BuildSource,
    Wrapper,
    Snap,
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendKind::Apt         => write!(f, "APT Hook"),
            BackendKind::Flatpak     => write!(f, "Flatpak"),
            BackendKind::Wine         => write!(f, "Wine"),
            BackendKind::BuildSource => write!(f, "Build Source"),
            BackendKind::Wrapper     => write!(f, "Wrapper"),
            BackendKind::Snap         => write!(f, "Snap"),
        }
    }
}

impl BackendKind {
    /// Stable wire/identifier string used on the control socket and config.
    pub fn id(&self) -> &'static str {
        match self {
            BackendKind::Apt         => "apt",
            BackendKind::Flatpak     => "flatpak",
            BackendKind::Wine         => "wine",
            BackendKind::BuildSource => "source",
            BackendKind::Wrapper     => "wrapper",
            BackendKind::Snap         => "snap",
        }
    }

    /// Whether this backend's `enable_*` flag is set in config.
    pub fn enabled_in(&self, config: &Config) -> bool {
        let b = &config.backends;
        match self {
            BackendKind::Apt         => b.enable_apt,
            BackendKind::Flatpak     => b.enable_flatpak,
            BackendKind::Wine         => b.enable_wine,
            BackendKind::BuildSource => b.enable_build_source,
            BackendKind::Wrapper     => b.enable_wrapper,
            BackendKind::Snap         => b.enable_snap,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BackendExtra — optional metadata per backend type
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[allow(dead_code)] // metadata consumed by the dashboard (stage 3)
pub enum BackendExtra {
    Flatpak {
        signed:      bool,
        publisher:   Option<String>,
        key_trusted: bool,
    },
    Wine {
        wine_binary: PathBuf,
    },
    BuildSource {
        command:    String,
        source_dir: PathBuf,
    },
    Snap {
        snap_name: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// InterceptEvent  (install-request fields removed — worker owns installs now)
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Scan verdict — the daemon's headless judgement on a held apt transaction.
// Crosses the hook socket as JSON (the `--apt-hook` process is a separate, short-
// lived invocation of this same binary), so it carries serde derives. Built by
// the daemon (it owns ClamAV + deb_inspect); consumed by the hook for
// presentation and the proceed/cancel decision.
// ─────────────────────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageVerdict {
    pub path:    String,
    pub name:    String,
    pub version: String,
    /// "clean" | "suspicious" | "highrisk" — the deb_inspect heuristic band.
    pub band: String,
    /// ClamAV signature hit name, if any. A threat is a hard block regardless of
    /// presentation context (it never needs a human to be acted on).
    pub threat:        Option<String>,
    pub threat_detail: Option<String>,
    /// Compact heuristic findings + structural flags, for the TTY/compact view.
    pub findings:        Vec<String>,
    pub setuid:          bool,
    pub adds_apt_source: bool,
    /// deb_inspect could not read this package; surfaced, not silently passed.
    pub inspect_failed: bool,
    /// The ClamAV signature scan could not complete (e.g. insufficient disk to
    /// extract the payload). ClamAV is the hard-block authority, so if it could
    /// not vouch for the package, the install is BLOCKED — never passed. Carries
    /// the user-facing reason. Distinct from `inspect_failed` (heuristic-only,
    /// advisory → review) and from `threat` (a positive signature hit).
    pub unscannable: Option<String>,
}

impl PackageVerdict {
    /// A package the user should be asked about (heuristic-flagged or structurally
    /// sensitive). Threats are handled separately as a hard block, not "flagged".
    pub fn is_flagged(&self) -> bool {
        self.band != "clean" || self.setuid || self.adds_apt_source || self.inspect_failed
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanVerdict {
    /// Scanning is suspended (RAM toggle) — proceed without scan, daemon logs it.
    pub suspended: bool,
    pub packages:  Vec<PackageVerdict>,
}

impl ScanVerdict {
    pub fn suspended() -> Self {
        Self { suspended: true, packages: vec![] }
    }
    pub fn has_threat(&self) -> bool {
        self.packages.iter().any(|p| p.threat.is_some())
    }
    pub fn threats(&self) -> Vec<&PackageVerdict> {
        self.packages.iter().filter(|p| p.threat.is_some()).collect()
    }
    /// Packages whose signature scan could not complete — a hard block, handled
    /// separately from threats and from heuristic review.
    pub fn unscannable(&self) -> Vec<&PackageVerdict> {
        self.packages.iter().filter(|p| p.unscannable.is_some()).collect()
    }
    pub fn flagged(&self) -> Vec<&PackageVerdict> {
        self.packages
            .iter()
            .filter(|p| p.is_flagged() && p.threat.is_none() && p.unscannable.is_none())
            .collect()
    }
}

#[derive(Debug)]
pub struct InterceptEvent {
    pub path:         PathBuf,
    pub backend:      BackendKind,
    pub bulk_paths:   Vec<PathBuf>,
    /// Set for blocking intercepts (apt hook). The daemon scans headlessly and
    /// returns a verdict; the HOOK process presents it (GUI into the live session,
    /// TTY review over SSH, or policy when unattended) and decides proceed/cancel.
    pub hook_respond: Option<oneshot::Sender<ScanVerdict>>,
    pub extra:        Option<BackendExtra>,
}

impl InterceptEvent {
    pub fn new(path: PathBuf, backend: BackendKind) -> Self {
        Self { path, backend, bulk_paths: vec![], hook_respond: None, extra: None }
    }

    pub fn filename(&self) -> String {
        self.path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown").to_string()
    }

    #[allow(dead_code)] // used by the dashboard's bulk-install view (stage 3)
    pub fn is_bulk(&self) -> bool { !self.bulk_paths.is_empty() }
}

// ─────────────────────────────────────────────────────────────────────────────
// InterceptBackend trait
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
pub trait InterceptBackend: Send + Sync {
    #[allow(dead_code)] // backend identity — surfaced in the dashboard (stage 3)
    fn kind(&self)         -> BackendKind;
    fn is_available(&self) -> bool;
    async fn run(&self, sender: mpsc::Sender<InterceptEvent>) -> Result<()>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Construction + start/stop — daemon owns the handles so toggles are real
// ─────────────────────────────────────────────────────────────────────────────

/// Build a backend instance for a kind. Wrapper has no resident task (its hook is
/// the shell wrapper itself), so it constructs to None here.
fn make_backend(kind: &BackendKind, config: &Config) -> Option<Box<dyn InterceptBackend>> {
    match kind {
        BackendKind::Apt =>
            Some(Box::new(apt::AptBackend::new(config.sentry.hook_socket_path.clone()))),
        BackendKind::Flatpak =>
            Some(Box::new(flatpak_backend::FlatpakBackend::new(config.sentry.trusted_gpg_keys.clone()))),
        BackendKind::Wine =>
            Some(Box::new(wine::WineBackend::new(config.sentry.hook_socket_path.clone()))),
        BackendKind::BuildSource =>
            Some(Box::new(source::SourceBackend::new(config.sentry.hook_socket_path.clone()))),
        BackendKind::Snap =>
            Some(Box::new(snap::SnapBackend::new())),
        BackendKind::Wrapper => None,
    }
}

/// The kinds the daemon manages as resident tasks (toggleable monitors).
/// The apt SOCKET SERVER is started unconditionally elsewhere — it is the
/// daemon's intercept entry point. The "Packaged Apps" monitor toggle controls
/// the apt.conf.d hook FILE (root-gated), not this socket.
pub fn managed_kinds() -> Vec<BackendKind> {
    vec![
        BackendKind::Flatpak,
        BackendKind::Wine,
        BackendKind::BuildSource,
        BackendKind::Snap,
    ]
}

/// Spawn a single backend task, returning its JoinHandle (for later abort).
/// Returns None if the backend is unavailable on this system.
pub fn start_backend(
    kind:   &BackendKind,
    sender: mpsc::Sender<InterceptEvent>,
    config: &Config,
) -> Option<JoinHandle<()>> {
    let backend = make_backend(kind, config)?;
    if !backend.is_available() {
        log::info!("[backends] {} not available — not started", kind);
        return None;
    }
    let kind_log = kind.clone();
    Some(tokio::spawn(async move {
        if let Err(e) = backend.run(sender).await {
            log::error!("[{}] backend exited: {}", kind_log, e);
        }
    }))
}

/// Start every managed backend whose enable_* flag is set AND that is available.
/// Returns the handle map the daemon retains so toggles can abort tasks.
pub fn probe_and_start(
    sender: mpsc::Sender<InterceptEvent>,
    config: &Config,
) -> HashMap<BackendKind, JoinHandle<()>> {
    let mut handles = HashMap::new();
    for kind in managed_kinds() {
        if !kind.enabled_in(config) {
            log::info!("[backends] {} disabled in config — not started", kind);
            continue;
        }
        if let Some(h) = start_backend(&kind, sender.clone(), config) {
            handles.insert(kind, h);
        }
    }
    handles
}
