// src/backends/wine.rs — v1.0
// Wine execution intercept backend
//
// Wine is NOT sandboxed — a Windows .exe run through Wine has full access
// to the user's home directory and can make network connections.
// ClamAV has extensive Windows malware signatures — this is a strong scan.
//
// Intercept mechanism:
// 1. inotify on Wine prefix directories (~/.wine, ~/.PlayOnLinux, Bottles prefixes)
//    — catches .exe and .msi files being staged for execution
// 2. Wrapper hook for `wine` and `wine64` commands (via wrapper.rs shell function)
//
// The wine wrapper function: wine <file> → ghost-sentri --wrapper-hook wine <file>
// which connects to the daemon socket, sends the .exe path, waits for decision.
#![allow(dead_code)] // socket_path reserved for the wine wrapper-hook (stage 3)

use super::{BackendExtra, BackendKind, InterceptBackend, InterceptEvent};
use anyhow::Result;
use async_trait::async_trait;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use tokio::sync::mpsc;

pub struct WineBackend {
    socket_path: PathBuf,
}

impl WineBackend {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    fn is_wine_executable(path: &PathBuf) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| matches!(e.to_lowercase().as_str(), "exe" | "msi"))
            .unwrap_or(false)
    }

    fn wine_watch_dirs() -> Vec<PathBuf> {
        let mut dirs = vec![];
        if let Some(home) = dirs::home_dir() {
            // Standard Wine prefix
            dirs.push(home.join(".wine").join("drive_c"));
            // PlayOnLinux
            dirs.push(home.join(".PlayOnLinux").join("wineprefix"));
            // Bottles
            dirs.push(home.join(".var/app/com.usebottles.bottles/data/bottles"));
            // Downloads — common staging area
            if let Some(dl) = dirs::download_dir() {
                dirs.push(dl);
            }
            dirs.push(home.join("Downloads"));
        }
        dirs.into_iter().filter(|d| d.exists()).collect()
    }

    fn detect_wine_binary() -> Option<PathBuf> {
        for candidate in &["/usr/bin/wine", "/usr/bin/wine64", "/usr/local/bin/wine"] {
            if std::path::Path::new(candidate).exists() {
                return Some(PathBuf::from(candidate));
            }
        }
        None
    }
}

#[async_trait]
impl InterceptBackend for WineBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Wine
    }

    fn is_available(&self) -> bool {
        Self::detect_wine_binary().is_some()
    }

    async fn run(&self, sender: mpsc::Sender<InterceptEvent>) -> Result<()> {
        let watch_dirs = Self::wine_watch_dirs();
        if watch_dirs.is_empty() {
            log::info!("[WineBackend] no Wine directories found — backend passive");
            // Still run — will activate if directories appear
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            return Ok(());
        }

        let wine_binary = Self::detect_wine_binary();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(32);

        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(event) = res {
                    let _ = tx.blocking_send(event);
                }
            },
            Config::default(),
        )?;

        for dir in &watch_dirs {
            watcher.watch(dir, RecursiveMode::Recursive)?;
            log::info!("[WineBackend] watching {:?}", dir);
        }

        while let Some(event) = rx.recv().await {
            // Intercept on access/open events for exe/msi files
            // This catches files being loaded for execution, not just creation
            if event.kind.is_access() || event.kind.is_create() || event.kind.is_modify() {
                for path in event.paths {
                    if !Self::is_wine_executable(&path) {
                        continue;
                    }

                    log::info!("[WineBackend] detected Wine executable: {:?}", path);

                    let wb = wine_binary.clone().unwrap_or_else(|| PathBuf::from("wine"));
                    let mut evt = InterceptEvent::new(path, BackendKind::Wine);
                    evt.extra = Some(BackendExtra::Wine { wine_binary: wb });

                    let _ = sender.send(evt).await;
                }
            }
        }

        Ok(())
    }
}
