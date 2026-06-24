// src/backends/flatpak_backend.rs — v1.0
// Flatpak bundle intercept backend
//
// Two intercept points:
// 1. inotify on ~/Downloads and XDG download dir — catches .flatpak files as they land
// 2. Wrapper hook for `flatpak install` command (via wrapper.rs shell function)
//
// When a .flatpak bundle is detected:
// 1. GPG signature check via `flatpak install --gpg-verify` or gpg directly
// 2. Check publisher against trusted_gpg_keys list from config
// 3. Build InterceptEvent with Flatpak extra context (signed, publisher, trusted)
// 4. Forward to daemon — UI shows Flatpak-specific dialog variant
//
// Signed bundles from verified publishers in trusted_gpg_keys: signature warning bypassed
// Signed bundles from unknown publishers: signature warning shown, scan still runs
// Unsigned bundles: explicit unsigned warning + scan

use super::{BackendExtra, BackendKind, InterceptBackend, InterceptEvent};
use anyhow::Result;
use async_trait::async_trait;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use tokio::sync::mpsc;

pub struct FlatpakBackend {
    trusted_gpg_keys: Vec<String>,
}

impl FlatpakBackend {
    pub fn new(trusted_gpg_keys: Vec<String>) -> Self {
        Self { trusted_gpg_keys }
    }

    fn is_flatpak_file(path: &PathBuf) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e == "flatpak")
            .unwrap_or(false)
    }

    /// Verify GPG signature of a .flatpak bundle
    /// Returns (signed, publisher_fingerprint)
    fn verify_signature(path: &PathBuf) -> (bool, Option<String>) {
        // flatpak build-bundle produces bundles with optional GPG signatures
        // We check using gpg --verify on the bundle's detached signature if present
        // The .flatpak format is an OSTree repo — signature is in the summary.sig file
        //
        // Approach: call `flatpak install --dry-run --gpg-verify` or extract OSTree summary
        // For v2.0: use gpg to check for any signature metadata
        let sig_check = std::process::Command::new("gpg")
            .args(["--verify", "--status-fd=1"])
            .arg(path)
            .output();

        match sig_check {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains("GOODSIG") || stdout.contains("VALIDSIG") {
                    // Extract fingerprint from VALIDSIG line
                    let fingerprint = stdout
                        .lines()
                        .find(|l| l.contains("VALIDSIG"))
                        .and_then(|l| l.split_whitespace().nth(2))
                        .map(|s| s.to_string());
                    (true, fingerprint)
                } else {
                    (false, None)
                }
            }
            Err(_) => (false, None),
        }
    }

    fn is_key_trusted(&self, fingerprint: &Option<String>) -> bool {
        match fingerprint {
            Some(fp) => self
                .trusted_gpg_keys
                .iter()
                .any(|k| k.contains(fp.as_str()) || fp.contains(k.as_str())),
            None => false,
        }
    }

    fn watch_download_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = vec![];
        if let Some(dl) = dirs::download_dir() {
            dirs.push(dl);
        }
        if let Some(home) = dirs::home_dir() {
            dirs.push(home.join("Downloads"));
            dirs.push(home.join("Desktop"));
        }
        dirs.dedup();
        dirs.into_iter().filter(|d| d.exists()).collect()
    }
}

#[async_trait]
impl InterceptBackend for FlatpakBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Flatpak
    }

    fn is_available(&self) -> bool {
        std::process::Command::new("which")
            .arg("flatpak")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    async fn run(&self, sender: mpsc::Sender<InterceptEvent>) -> Result<()> {
        let watch_dirs = self.watch_download_dirs();
        if watch_dirs.is_empty() {
            log::warn!("[FlatpakBackend] no download directories found to watch");
            return Ok(());
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(32);
        let trusted_keys = self.trusted_gpg_keys.clone();

        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(event) = res {
                    let _ = tx.blocking_send(event);
                }
            },
            Config::default(),
        )?;

        for dir in &watch_dirs {
            watcher.watch(dir, RecursiveMode::NonRecursive)?;
            log::info!("[FlatpakBackend] watching {:?}", dir);
        }

        while let Some(event) = rx.recv().await {
            if event.kind.is_create() || event.kind.is_modify() {
                for path in event.paths {
                    if !Self::is_flatpak_file(&path) {
                        continue;
                    }

                    log::info!("[FlatpakBackend] detected .flatpak: {:?}", path);

                    // GPG signature check — run in blocking thread (subprocess)
                    let p = path.clone();
                    let keys = trusted_keys.clone();
                    let (signed, fingerprint) =
                        tokio::task::spawn_blocking(move || Self::verify_signature(&p))
                            .await
                            .unwrap_or((false, None));

                    let key_trusted = FlatpakBackend { trusted_gpg_keys: keys }
                        .is_key_trusted(&fingerprint);

                    let publisher = fingerprint.clone();
                    let mut evt = InterceptEvent::new(path, BackendKind::Flatpak);
                    evt.extra = Some(BackendExtra::Flatpak {
                        signed,
                        publisher,
                        key_trusted,
                    });

                    let _ = sender.send(evt).await;
                }
            }
        }

        Ok(())
    }
}
