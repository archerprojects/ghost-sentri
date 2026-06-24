// core/src/quarantine.rs — v1.0
// Quarantine record + manifest reader. Moved into core in the split so the GUI
// (which no longer shares a process with the daemon) can display quarantine
// history by reading the manifest directly. Writing quarantine entries is a
// privileged/daemon concern and lives elsewhere.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub filename:           String,
    pub original_path:      PathBuf,
    pub quarantine_path:    PathBuf,
    pub threat_name:        String,
    pub definition_version: String,
    pub timestamp:          DateTime<Utc>,
}

/// Read the quarantine manifest (`<dir>/.manifest.json`). Returns an empty list
/// when the manifest is absent or unreadable — display is best-effort.
pub fn load_manifest(quarantine_dir: &std::path::Path) -> Vec<QuarantineRecord> {
    let manifest = quarantine_dir.join(".manifest.json");
    match std::fs::read_to_string(&manifest) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => vec![],
    }
}
