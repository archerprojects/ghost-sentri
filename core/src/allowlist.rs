// core/src/allowlist.rs — v1.1.0 — Thursday 12 November 2026
// Machine-wide allow list: the false-positive override.
//
// One entry = the SHA256 of one exact file. That file then skips the ClamAV scan
// everywhere (Downloads watch, apt installs, double-click installs), from any
// source or path. Keyed ONLY by hash: a name, path, source or package name never
// qualifies, so a different version, a rebuild or a tampered copy is scanned as
// usual. The deb_inspect heuristics still run on an allowed package.
//
// /etc/ghost-sentri/allowlist.toml — root-owned, 0644, written only by the daemon
// after a polkit "manage" authorisation. Entries never expire.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

pub const ALLOWLIST_PATH: &str = "/etc/ghost-sentri/allowlist.toml";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowEntry {
    pub sha256: String,
    /// The threat name it was allowed over.
    pub threat: String,
    /// File name at the time it was allowed.
    pub filename: String,
    /// Who allowed it (user name).
    pub allowed_by: String,
    /// RFC3339 UTC.
    pub allowed_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AllowList {
    #[serde(default)]
    pub entries: Vec<AllowEntry>,
}

impl AllowList {
    pub fn load() -> Self {
        Self::load_from(Path::new(ALLOWLIST_PATH))
    }

    /// Missing or unreadable → empty (nothing allowed).
    pub fn load_from(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn contains(&self, sha256: &str) -> bool {
        let s = sha256.to_ascii_lowercase();
        self.entries.iter().any(|e| e.sha256 == s)
    }

    pub fn get(&self, sha256: &str) -> Option<&AllowEntry> {
        let s = sha256.to_ascii_lowercase();
        self.entries.iter().find(|e| e.sha256 == s)
    }

    /// Add (or replace) an entry. The hash is stored lower-case.
    pub fn add(&mut self, mut entry: AllowEntry) {
        entry.sha256 = entry.sha256.to_ascii_lowercase();
        self.entries.retain(|e| e.sha256 != entry.sha256);
        self.entries.push(entry);
    }

    /// Remove an entry; true if one was removed.
    pub fn remove(&mut self, sha256: &str) -> bool {
        let s = sha256.to_ascii_lowercase();
        let before = self.entries.len();
        self.entries.retain(|e| e.sha256 != s);
        before != self.entries.len()
    }

    pub fn save(&self) -> std::io::Result<()> {
        self.save_to(Path::new(ALLOWLIST_PATH))
    }

    /// Write via temp file + rename, mode 0644.
    pub fn save_to(&self, path: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let text = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
        std::fs::rename(&tmp, path)
    }
}

/// Current time, RFC3339 UTC — the `allowed_at` stamp.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// 64 hex digits.
pub fn is_valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// SHA256 of a file via `sha256sum` (coreutils — no new dependency).
pub fn file_sha256(path: &Path) -> Option<String> {
    let out = Command::new("sha256sum")
        .arg("--")
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let h = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()?
        .to_ascii_lowercase();
    if is_valid_sha256(&h) {
        Some(h)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_remove_round_trip() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/test-scratch");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("allow-{}.toml", std::process::id()));
        let h = "AB".repeat(32);
        let mut l = AllowList::default();
        l.add(AllowEntry {
            sha256: h.clone(),
            threat: "Eicar".into(),
            filename: "x.exe".into(),
            allowed_by: "u".into(),
            allowed_at: "2026-11-12T00:00:00Z".into(),
        });
        l.save_to(&path).unwrap();
        let back = AllowList::load_from(&path);
        assert!(back.contains(&h));
        assert!(back.contains(&h.to_lowercase()));
        assert_eq!(back.get(&h).unwrap().threat, "Eicar");
        let mut back = back;
        assert!(back.remove(&h));
        assert!(!back.remove(&h));
        assert!(!back.contains(&h));
        let _ = std::fs::remove_file(&path);
        assert!(AllowList::load_from(&path).entries.is_empty());
    }

    #[test]
    fn sha_validation() {
        assert!(is_valid_sha256(&"a".repeat(64)));
        assert!(!is_valid_sha256(&"a".repeat(63)));
        assert!(!is_valid_sha256(&"g".repeat(64)));
    }
}
