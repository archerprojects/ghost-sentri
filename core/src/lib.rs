// core/src/lib.rs — v1.1.0 — Thursday 12 November 2026
// ghost-sentri-core — shared foundation for the daemon, gui, and installer worker.
//
// Contains everything that crosses crate boundaries:
//   config    — on-disk configuration (TOML), monitor flags, paths
//   clam      — ClamAV scan backend + definition status (used by daemon & worker)
//   protocol  — wire types for hook.sock, control.sock, and worker stdio
//   events    — machine-wide audit log records (/var/log/ghost-sentri/events.jsonl)
//   allowlist — machine-wide allow list of exact file hashes
//   quarantine — per-user quarantine records and file operations
//
// No GTK, no relm4, no tokio here. This crate must stay toolkit-free so the
// resident daemon never links a GUI stack.

pub mod allowlist;
pub mod clam;
pub mod config;
pub mod deb_inspect;
pub mod events;
pub mod protocol;
pub mod quarantine;

// Convenience re-exports for the common types.
pub use deb_inspect::{
    DebReport, InstallAction, MaintainerScript, FlaggedFile, ScriptFinding, Severity,
    RuleFamily, RiskBand, inspect as inspect_deb,
};
pub use config::{
    BackendConfig, Config, DefinitionConfig, DownloadsConfig, QuarantineConfig,
    ScanConfig, SentryConfig,
};
pub use clam::{
    DefinitionStatus, FileVerdict, ScanResult, SystemClamBackend, ThreatClassification,
    ThreatDetail,
};
pub use allowlist::{AllowEntry, AllowList};
pub use events::{Action, AuditEvent, ScanOutcome};
pub use quarantine::{load_manifest, QuarantineRecord};
pub use protocol::{
    Avenue, ControlEvent, ControlRequest, DefinitionSnapshot, InterceptChoice, MonitorState,
    WorkerInbound, WorkerMode, WorkerOutbound,
};
