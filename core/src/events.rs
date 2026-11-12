// core/src/events.rs — v1.1.0 — Thursday 12 November 2026
// Machine-wide install audit trail.
//
// Threat model (locked in design): the adversary is the PACKAGE, not the user.
// So this log is NOT defended against a hostile user — it is the forensic record
// of what was installed on the system, most valuable for the clean-but-later-
// regretted install the scanner waved through.
//
// One shared file for the whole machine: /var/log/ghost-sentri/events.jsonl
//   - root-owned, world-readable (644) — anyone reads, only root writes
//   - written by the privileged installer worker during an install, and by the
//     root daemon for the Downloads watch and allow-list changes
//   - JSON Lines (one object per line), NOT a JSON array: appends never rewrite
//     the file, so a crash mid-write can't corrupt prior records, and you can
//     still tail/grep it like a plain log.
//
// Rotation: at 2MB the file is rolled to events.jsonl.1 (single generation kept).

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::protocol::Avenue;

/// Canonical audit-log location. The worker writes here as root.
pub const AUDIT_LOG_PATH: &str = "/var/log/ghost-sentri/events.jsonl";
/// Directory that must exist (created by postinst, root-owned).
pub const AUDIT_LOG_DIR: &str = "/var/log/ghost-sentri";
/// Roll to .1 once the live file reaches this size.
pub const AUDIT_ROTATE_BYTES: u64 = 2 * 1024 * 1024; // 2 MB

/// What happened to the package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Intercepted, // install detected and held for a decision
    Installed,   // install completed successfully
    InstallFailed,
    Cancelled,   // user cancelled at the intercept
    Quarantined, // threat moved to quarantine instead of installed
    Scanned,     // Downloads watch: file scanned (verdict in `scan`), left in place
    Allowed,     // file hash added to the allow list (false-positive override)
    AllowRemoved,
}

/// The scan verdict, if a scan was run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ScanOutcome {
    Clean,
    Threat { name: String },
    NotScanned, // user chose Install Without Scan, or scanning unavailable
    Error { message: String },
}

/// One line in events.jsonl.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// RFC3339 UTC timestamp.
    pub time: String,
    /// The user whose session triggered the install (invoking user, not root).
    pub user: String,
    pub avenue: Avenue,
    pub action: Action,
    /// Package name when known (derived from the .deb / control metadata).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    /// Filesystem path of the package being installed.
    pub path: String,
    /// Scan verdict, when a scan was part of the flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan: Option<ScanOutcome>,
    /// Free-form extra context (apt exit reason, quarantine destination, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl AuditEvent {
    /// Construct an event stamped now (UTC). `user` is the invoking session user.
    pub fn new(user: impl Into<String>, avenue: Avenue, action: Action, path: impl Into<String>) -> Self {
        Self {
            time: chrono::Utc::now().to_rfc3339(),
            user: user.into(),
            avenue,
            action,
            package: None,
            path: path.into(),
            scan: None,
            detail: None,
        }
    }

    pub fn with_package(mut self, pkg: impl Into<String>) -> Self {
        self.package = Some(pkg.into());
        self
    }
    pub fn with_scan(mut self, scan: ScanOutcome) -> Self {
        self.scan = Some(scan);
        self
    }
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Serialize as one newline-terminated JSON line.
    pub fn to_jsonl(&self) -> serde_json::Result<String> {
        Ok(format!("{}\n", serde_json::to_string(self)?))
    }
}

/// Append an event to the canonical audit log, rotating first if needed.
/// Caller must have write permission to AUDIT_LOG_DIR (i.e. be root — the worker).
pub fn append(event: &AuditEvent) -> std::io::Result<()> {
    append_to(Path::new(AUDIT_LOG_PATH), event)
}

/// Append to a specific path (kept path-agnostic for testing and for the worker,
/// which passes the root-owned canonical path explicitly).
pub fn append_to(path: &Path, event: &AuditEvent) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    rotate_if_needed(path)?;

    let line = event
        .to_jsonl()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(line.as_bytes())?;
    Ok(())
}

/// Roll the live file to `<path>.1` once it reaches AUDIT_ROTATE_BYTES.
/// Single generation: an existing `.1` is overwritten.
fn rotate_if_needed(path: &Path) -> std::io::Result<()> {
    let size = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(_) => return Ok(()), // no file yet — nothing to rotate
    };
    if size < AUDIT_ROTATE_BYTES {
        return Ok(());
    }
    let rolled: PathBuf = {
        let mut s = path.as_os_str().to_owned();
        s.push(".1");
        PathBuf::from(s)
    };
    // rename is atomic on the same filesystem; overwrites any prior .1
    std::fs::rename(path, &rolled)
}
