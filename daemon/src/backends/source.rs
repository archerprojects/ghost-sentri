// src/backends/source.rs — v1.0
// Build-from-source intercept backend
//
// Monitors for source install commands run with elevated privileges:
//   make install, cmake --install, cargo install, meson install, ninja install
//
// Mechanism: watches for sudo/pkexec being called with these commands
// via /proc filesystem monitoring on Linux. When detected, fires the
// universal intercept dialog with the "build from source" variant.
//
// Implementation note: /proc monitoring for arbitrary process args requires
// polling /proc/*/cmdline — resource-intensive. For v2.0 this is implemented
// as a wrapper backend extension. The install commands are also added to the
// wrapper shell function block in wrapper.rs (cargo, make, cmake, meson, ninja).
//
// TODO v2.1: Implement auditd-based monitoring for more reliable detection
// without polling. Requires libaudit and auditd running.
#![allow(dead_code)] // source/wrapper-hook fields wired in stage 3

use super::{BackendExtra, BackendKind, InterceptBackend, InterceptEvent};
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

pub struct SourceBackend {
    socket_path: PathBuf,
}

impl SourceBackend {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Source install command signatures to watch for in /proc
    fn source_install_patterns() -> Vec<Vec<&'static str>> {
        vec![
            vec!["make", "install"],
            vec!["cmake", "--install"],
            vec!["ninja", "install"],
            vec!["meson", "install"],
            vec!["cargo", "install"],
            vec!["pip", "install"],
            vec!["pip3", "install"],
        ]
    }

    async fn scan_proc_for_installs(
        sender: &mpsc::Sender<InterceptEvent>,
    ) -> Result<()> {
        let mut dir = tokio::fs::read_dir("/proc").await?;

        while let Some(entry) = dir.next_entry().await? {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Only process numeric entries (PIDs)
            if !name_str.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }

            let cmdline_path = entry.path().join("cmdline");
            if let Ok(raw) = tokio::fs::read(&cmdline_path).await {
                // cmdline is null-separated
                let args: Vec<String> = raw
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect();

                for pattern in Self::source_install_patterns() {
                    if pattern_matches(&args, &pattern) {
                        // Check if running with elevated privileges
                        let status_path = entry.path().join("status");
                        if is_elevated(&status_path).await {
                            // Find the working directory (source dir)
                            let cwd_path = entry.path().join("cwd");
                            let source_dir = tokio::fs::read_link(&cwd_path)
                                .await
                                .unwrap_or_else(|_| PathBuf::from("."));

                            let command = args.join(" ");
                            let mut evt = InterceptEvent::new(
                                source_dir.clone(),
                                BackendKind::BuildSource,
                            );
                            evt.extra = Some(BackendExtra::BuildSource {
                                command: command.clone(),
                                source_dir,
                            });

                            let _ = sender.send(evt).await;
                            // Brief pause to avoid re-triggering on same process
                            sleep(Duration::from_secs(2)).await;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn pattern_matches(args: &[String], pattern: &[&str]) -> bool {
    if args.len() < pattern.len() {
        return false;
    }
    // Check if pattern appears anywhere in args
    for window in args.windows(pattern.len()) {
        if window
            .iter()
            .zip(pattern.iter())
            .all(|(arg, pat)| arg.contains(pat))
        {
            return true;
        }
    }
    false
}

async fn is_elevated(status_path: &PathBuf) -> bool {
    if let Ok(content) = tokio::fs::read_to_string(status_path).await {
        for line in content.lines() {
            if line.starts_with("Uid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // Effective UID is the 3rd field
                if let Some(euid) = parts.get(2) {
                    return *euid == "0";
                }
            }
        }
    }
    false
}

#[async_trait]
impl InterceptBackend for SourceBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::BuildSource
    }

    fn is_available(&self) -> bool {
        // Available on any Linux system with /proc
        std::path::Path::new("/proc").exists()
    }

    async fn run(&self, sender: mpsc::Sender<InterceptEvent>) -> Result<()> {
        log::info!("[SourceBackend] monitoring /proc for source install commands");

        // Poll /proc every 2 seconds — acceptable latency for install intercept
        // TODO v2.1: Replace with auditd for real-time, zero-poll detection
        loop {
            if let Err(e) = Self::scan_proc_for_installs(&sender).await {
                log::debug!("[SourceBackend] proc scan error: {}", e);
            }
            sleep(Duration::from_secs(2)).await;
        }
    }
}
