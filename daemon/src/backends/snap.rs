// daemon/src/backends/snap.rs — v1.1.0 — Thursday 12 November 2026
// Snap install monitor — DETECT-AND-LOG ONLY.
//
// IMPORTANT, by design: snapd exposes no pre-install gate a third party can hold
// the way the apt.conf.d hook holds dpkg. snapd's REST API (/v2/changes) and the
// `snap changes` CLI report installs as/after they happen — there is no
// block-before-install. So this backend cannot show the Cancel/Scan/Install
// intercept dialog and cannot stop a snap mid-install. It DETECTS a snap install,
// LOGS it to the audit trail and dashboard, and can drive a POST-install scan.
//
// Mechanism: poll `snap changes` on an interval, emit a non-blocking
// InterceptEvent (hook_respond = None) for each newly-seen Install change.
// Subprocess polling keeps this dependency-free (no zbus, no HTTP-over-unix
// client) — deliberate, to preserve the zbus removal.
//
// NOTE: untested against a live snapd in this build. Parsing of `snap changes`
// output is best-effort and may need tightening against real-world rows.

use super::{BackendExtra, BackendKind, InterceptBackend, InterceptEvent};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

const POLL_INTERVAL_SECS: u64 = 5;

pub struct SnapBackend {
    /// Change IDs already reported, so each install is emitted once.
    seen: Arc<Mutex<HashSet<String>>>,
}

impl SnapBackend {
    pub fn new() -> Self {
        Self { seen: Arc::new(Mutex::new(HashSet::new())) }
    }

    /// Parse `snap changes` output into (change_id, snap_name) for Install rows.
    /// Expected columns: ID  Status  Spawn  Ready  Summary
    ///   e.g.  42   Done   ...   ...   Install "hello" snap
    fn parse_install_changes(output: &str) -> Vec<(String, String)> {
        let mut out = vec![];
        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("ID") {
                continue; // header / blank
            }
            // Summaries we care about describe an install.
            if !line.contains("Install") {
                continue;
            }
            let id = match line.split_whitespace().next() {
                Some(id) if id.chars().all(|c| c.is_ascii_digit()) => id.to_string(),
                _ => continue,
            };
            // snap name is the quoted token in the summary, if present.
            let name = line
                .split('"')
                .nth(1)
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            out.push((id, name));
        }
        out
    }
}

impl Default for SnapBackend {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl InterceptBackend for SnapBackend {
    fn kind(&self) -> BackendKind { BackendKind::Snap }

    fn is_available(&self) -> bool {
        Command::new("which")
            .arg("snap")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    async fn run(&self, sender: mpsc::Sender<InterceptEvent>) -> Result<()> {
        log::info!("[SnapBackend] detect-and-log monitor started (no pre-install gate)");
        let seen = self.seen.clone();

        loop {
            // `snap changes` is cheap; run it off-thread to keep the reactor free.
            let output = tokio::task::spawn_blocking(|| {
                Command::new("snap").arg("changes").output()
            })
            .await;

            if let Ok(Ok(out)) = output {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for (id, name) in Self::parse_install_changes(&text) {
                        let is_new = { seen.lock().unwrap().insert(id.clone()) };
                        if !is_new {
                            continue;
                        }
                        log::info!("[SnapBackend] detected snap install: {} (change {})", name, id);

                        // Non-blocking event: hook_respond stays None — there is
                        // nothing to gate. The daemon logs/audits and may scan after.
                        let mut evt = InterceptEvent::new(
                            PathBuf::from(format!("snap:{name}")),
                            BackendKind::Snap,
                        );
                        evt.extra = Some(BackendExtra::Snap { snap_name: name });
                        let _ = sender.send(evt).await;
                    }
                }
            }

            sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
        }
    }
}
