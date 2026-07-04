// core/src/config.rs
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
    pub quarantine:  QuarantineConfig,
    pub definitions: DefinitionConfig,
    pub backends:    BackendConfig,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QuarantineConfig {
    pub path: PathBuf,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        let path = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(".quarantine");
        Self { path }
    }
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
    #[serde(default)]
    pub enable_flatpak:      bool,
    #[serde(default)]
    pub enable_wine:         bool,
    /// Snap — detect-and-log monitor (snapd permits no pre-install gate).
    #[serde(default)]
    pub enable_snap:         bool,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            enable_apt:          false,
            enable_wrapper:      false,
            enable_build_source: false,
            enable_flatpak:      false,
            enable_wine:         false,
            enable_snap:         false,
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
            Ok(raw) => Ok(toml::from_str(&raw)?),
            Err(_) => Ok(Config::default()),
        }
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

