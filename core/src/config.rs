// core/src/config.rs — v1.1.0 — Thursday 12 November 2026
// Shared machine config — used by daemon, gui, and installer worker.
// System-wide, root-owned policy at /etc/ghost-sentri/config.toml. Only the
// privileged root `--apply` path writes it; every other context reads it.
// Backend enable flags default to ALL FALSE — a fresh install starts inert and
// the user opts in. SentryConfig.control_socket_path is the user-only GUI<->daemon
// channel, separate from the root-reachable hook socket. The .deb MIME default and
// apt hook are machine policy written by `--apply`, not per-user xdg-mime calls.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub sentry:      SentryConfig,
    pub scan:        ScanConfig,
    #[serde(default)]
    pub quarantine:  QuarantineConfig,
    pub definitions: DefinitionConfig,
    pub backends:    BackendConfig,
    /// Downloads watch folders. `serde(default)` so pre-1.1.0 files still load.
    #[serde(default)]
    pub downloads:   DownloadsConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SentryConfig {
    pub trusted_gpg_keys:   Vec<String>,
    /// Root-reachable install-decision socket (apt hook connects here as root).
    pub hook_socket_path:   PathBuf,
    /// User-only GUI<->daemon control channel. Separate trust level from the
    /// hook socket. `serde(default)` so pre-split config.toml files still load.
    #[serde(default = "default_control_socket_path")]
    pub control_socket_path: PathBuf,
}

/// Control socket lives under the daemon's systemd RuntimeDirectory
/// (`/run/ghost-sentri`), created 0755 by the unit. The root system daemon binds
/// it and relaxes the socket mode so any user can connect; per-request polkit
/// authorization — not file permissions — gates privileged operations.
fn default_control_socket_path() -> PathBuf {
    PathBuf::from("/run/ghost-sentri/control.sock")
}

impl Default for SentryConfig {
    fn default() -> Self {
        Self {
            trusted_gpg_keys: vec![],
            hook_socket_path: PathBuf::from("/run/ghost-sentri/hook.sock"),
            control_socket_path: default_control_socket_path(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanConfig {
    pub clamscan_path:       Option<PathBuf>,
    /// Retained as the override point for the clamscan SCAN_LIMITS in the planned
    /// detect-and-degrade path (probe clamscan version/flag support, fall back to a
    /// permissive arg set). Not yet wired — annotated, not dropped, so the field
    /// survives the round-trip through /etc without a blanket allow.
    #[serde(default)]
    #[allow(dead_code)]
    pub extra_clamscan_args: Vec<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self { clamscan_path: None, extra_clamscan_args: vec![] }
    }
}

/// Per-user quarantine location, RELATIVE to each user's home. One setting for
/// the machine; each user's quarantine lives in their own home and is owned by
/// them. (The pre-1.1.0 absolute `path` key resolved to /root under the root
/// daemon; it is ignored on load and dropped on the next save.)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QuarantineConfig {
    #[serde(default = "default_quarantine_dir")]
    pub dir: String,
}

pub const DEFAULT_QUARANTINE_DIR: &str = ".quarantine";

fn default_quarantine_dir() -> String {
    DEFAULT_QUARANTINE_DIR.to_string()
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self { dir: default_quarantine_dir() }
    }
}

impl QuarantineConfig {
    /// The quarantine folder for a given home. An invalid stored value falls back
    /// to the default rather than escaping the home.
    pub fn dir_for(&self, home: &std::path::Path) -> PathBuf {
        let rel = if is_valid_home_relative(&self.dir) { self.dir.as_str() } else { DEFAULT_QUARANTINE_DIR };
        home.join(rel)
    }
}

/// Downloads watch. The user's XDG download folder is always watched; `folders`
/// are extra folders, each RELATIVE to the user's home. Top level only.
/// `extensions` (lower-case, no dot) decides which files are scanned; any other
/// file is scanned only if its first bytes are an ELF/Windows program or `#!`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DownloadsConfig {
    #[serde(default = "default_download_folders")]
    pub folders: Vec<String>,
    #[serde(default = "default_download_extensions")]
    pub extensions: Vec<String>,
}

fn default_download_folders() -> Vec<String> {
    vec!["Downloads".to_string()]
}

pub fn default_download_extensions() -> Vec<String> {
    [
        // Linux packages and installers
        "deb", "rpm", "appimage", "flatpak", "flatpakref", "snap", "run", "bin",
        // Scripts (a .desktop file can launch any command)
        "sh", "py", "pl", "desktop",
        // Windows
        "exe", "msi", "bat", "cmd", "ps1", "scr", "lnk",
        // Java
        "jar",
        // Archives — ClamAV scans inside (.tar.gz/.tar.xz/.tar.zst match gz/xz/zst)
        "zip", "7z", "tar", "tgz", "gz", "xz", "bz2", "zst", "iso", "rar",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl Default for DownloadsConfig {
    fn default() -> Self {
        Self { folders: default_download_folders(), extensions: default_download_extensions() }
    }
}

/// A path that stays inside the home it is joined to: non-empty, relative, no
/// `..` component, no NUL.
pub fn is_valid_home_relative(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() || t.contains('\0') {
        return false;
    }
    let p = std::path::Path::new(t);
    if p.is_absolute() {
        return false;
    }
    p.components().all(|c| matches!(c, std::path::Component::Normal(_) | std::path::Component::CurDir))
        && p.components().any(|c| matches!(c, std::path::Component::Normal(_)))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DefinitionConfig {
    pub stale_threshold_days:  u64,
    pub definition_path:       Option<PathBuf>,
}

impl Default for DefinitionConfig {
    fn default() -> Self {
        Self {
            stale_threshold_days: 2,
            definition_path:      None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackendConfig {
    #[serde(default)]
    pub enable_apt:          bool,
    #[serde(default)]
    pub enable_wrapper:      bool,
    /// Disabled by default — /proc polling fires on GUI package managers.
    #[serde(default)]
    pub enable_build_source: bool,
    /// Downloads watch — scans new files in each user's download folders and
    /// quarantines threats. Replaces the Wine and Flatpak monitors.
    #[serde(default)]
    pub enable_downloads:    bool,
    /// Snap — detect-and-log monitor (snapd permits no pre-install gate).
    #[serde(default)]
    pub enable_snap:         bool,
    /// Pre-1.1.0 keys. Read once so a user who had either monitor on keeps
    /// protection (Downloads starts on); never written back.
    #[serde(default, rename = "enable_wine", skip_serializing)]
    legacy_enable_wine:      bool,
    #[serde(default, rename = "enable_flatpak", skip_serializing)]
    legacy_enable_flatpak:   bool,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            enable_apt:          false,
            enable_wrapper:      false,
            enable_build_source: false,
            enable_downloads:    false,
            enable_snap:         false,
            legacy_enable_wine:    false,
            legacy_enable_flatpak: false,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sentry:      SentryConfig::default(),
            scan:        ScanConfig::default(),
            quarantine:  QuarantineConfig::default(),
            definitions: DefinitionConfig::default(),
            backends:    BackendConfig::default(),
            downloads:   DownloadsConfig::default(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Load / save / resolve
// ─────────────────────────────────────────────────────────────────────────────

impl Config {
    /// System-wide, root-owned policy. Scanner state is machine policy, not a
    /// per-user preference: one config governs every user on the host. Only the
    /// privileged apply path (root, via pkexec) writes it; the daemon reads it.
    pub fn config_path() -> PathBuf {
        PathBuf::from("/etc/ghost-sentri/config.toml")
    }

    /// Load the machine config. If absent (fresh install, nothing enabled yet) or
    /// unreadable, return the all-off default WITHOUT attempting to write — the
    /// user-context daemon cannot write /etc, and a missing file legitimately
    /// means "inert install." Persistence happens only through the root apply.
    pub fn load() -> Result<Self> {
        let path = Self::config_path();
        match std::fs::read_to_string(&path) {
            Ok(raw) => Ok(Self::parse(&raw)?),
            Err(_) => Ok(Config::default()),
        }
    }

    /// Parse config text, applying the one-time Wine/Flatpak → Downloads migration.
    pub fn parse(raw: &str) -> Result<Self> {
        let mut cfg: Config = toml::from_str(raw)?;
        let b = &mut cfg.backends;
        if b.legacy_enable_wine || b.legacy_enable_flatpak {
            b.enable_downloads = true;
        }
        b.legacy_enable_wine = false;
        b.legacy_enable_flatpak = false;
        Ok(cfg)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, toml::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn resolve_definition_path(&self) -> PathBuf {
        self.definitions.definition_path.clone()
            .unwrap_or_else(|| PathBuf::from("/var/lib/clamav"))
    }

    pub fn resolve_clamscan(&self) -> PathBuf {
        self.scan.clamscan_path.clone()
            .unwrap_or_else(|| PathBuf::from("/usr/bin/clamscan"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = r#"
[sentry]
trusted_gpg_keys = []
hook_socket_path = "/run/ghost-sentri/hook.sock"

[scan]

[quarantine]
path = "/root/.quarantine"

[definitions]
stale_threshold_days = 2

[backends]
enable_apt = true
enable_wine = true
enable_flatpak = false
"#;

    #[test]
    fn legacy_monitor_turns_downloads_on() {
        let cfg = Config::parse(OLD).unwrap();
        assert!(cfg.backends.enable_downloads);
        assert!(cfg.backends.enable_apt);
        assert_eq!(cfg.quarantine.dir, ".quarantine");
        assert_eq!(cfg.downloads.folders, vec!["Downloads".to_string()]);
        let out = toml::to_string_pretty(&cfg).unwrap();
        assert!(!out.contains("enable_wine"));
        assert!(!out.contains("enable_flatpak"));
        assert!(out.contains("enable_downloads = true"));
    }

    #[test]
    fn legacy_off_stays_off() {
        let cfg = Config::parse(&OLD.replace("enable_wine = true", "enable_wine = false")).unwrap();
        assert!(!cfg.backends.enable_downloads);
    }

    #[test]
    fn home_relative_validation() {
        assert!(is_valid_home_relative(".quarantine"));
        assert!(is_valid_home_relative("Documents/quarantine"));
        assert!(!is_valid_home_relative(""));
        assert!(!is_valid_home_relative("/etc"));
        assert!(!is_valid_home_relative("../x"));
        assert!(!is_valid_home_relative("a/../../x"));
        assert!(!is_valid_home_relative("."));
        let q = QuarantineConfig { dir: "../../etc".into() };
        assert_eq!(q.dir_for(std::path::Path::new("/home/u")), PathBuf::from("/home/u/.quarantine"));
    }
}
