// src/backends/wrapper.rs — v1.1
// Shell wrapper backend
// Fix: generate_wrapper_block no longer passes unused `socket` arg to format!
// The shell wrappers call ghost-sentri directly; socket path is resolved by the binary
#![allow(dead_code)] // wrapper hook + installer wiring lands in stage 3

use super::{BackendKind, InterceptBackend, InterceptEvent};
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::mpsc;

pub struct WrapperBackend {
    socket_path: PathBuf,
}

impl WrapperBackend {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    fn wrappers_installed() -> bool {
        let marker = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("ghost-sentri")
            .join(".wrapper-installed");
        marker.exists()
    }

    /// Generate the shell wrapper block for .bashrc / .zshrc / .profile
    pub fn generate_wrapper_block(_socket_path: &PathBuf) -> String {
        // Shell script does not need the socket path embedded —
        // ghost-sentri --wrapper-hook resolves it from config at runtime
        r#"
# Ghost Sentri — install interceptor wrappers
# Added by Ghost Sentri v2.0 — do not edit manually
__ghost_sentri_hook() {
    local cmd="$1"
    shift
    ghost-sentri --wrapper-hook "$cmd" "$@"
    local result=$?
    if [ $result -eq 0 ]; then
        command "$cmd" "$@"
    else
        echo "Ghost Sentri blocked this install. Open the dashboard for details."
        return 1
    fi
}
for __gs_cmd in apt apt-get dpkg flatpak pip pip3 npm; do
    if command -v "$__gs_cmd" > /dev/null 2>&1; then
        alias "$__gs_cmd"="__ghost_sentri_hook $__gs_cmd"
    fi
done
unset __gs_cmd
# End Ghost Sentri wrappers
"#
        .to_string()
    }

    pub fn install_wrappers(socket_path: &PathBuf) -> Result<Vec<PathBuf>> {
        let block = Self::generate_wrapper_block(socket_path);
        let mut modified = vec![];

        let shells = [".bashrc", ".zshrc", ".profile"];
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));

        for shell_file in &shells {
            let path = home.join(shell_file);
            if !path.exists() {
                continue;
            }
            let existing = std::fs::read_to_string(&path).unwrap_or_default();
            if existing.contains("Ghost Sentri — install interceptor wrappers") {
                continue;
            }
            let mut content = existing;
            content.push_str(&block);
            std::fs::write(&path, content)?;
            modified.push(path);
        }

        let marker = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("ghost-sentri")
            .join(".wrapper-installed");
        if let Some(parent) = marker.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&marker, "")?;

        Ok(modified)
    }
}

#[async_trait]
impl InterceptBackend for WrapperBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Wrapper
    }

    fn is_available(&self) -> bool {
        Self::wrappers_installed()
    }

    async fn run(&self, sender: mpsc::Sender<InterceptEvent>) -> Result<()> {
        let socket_path = self.socket_path.with_extension("wrapper.sock");

        if let Some(parent) = socket_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        if socket_path.exists() {
            tokio::fs::remove_file(&socket_path).await?;
        }

        let listener = UnixListener::bind(&socket_path)?;
        log::info!("[WrapperBackend] listening at {:?}", socket_path);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let s = sender.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_wrapper_connection(stream, s).await {
                            log::error!("[WrapperBackend] connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    log::error!("[WrapperBackend] accept error: {}", e);
                }
            }
        }
    }
}

async fn handle_wrapper_connection(
    stream: tokio::net::UnixStream,
    sender: mpsc::Sender<InterceptEvent>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let msg: serde_json::Value = serde_json::from_str(&line)?;

        if msg["type"] == "wrapper_intercept" {
            let paths: Vec<PathBuf> = msg["paths"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| v.as_str().map(PathBuf::from))
                .collect();

            if paths.is_empty() {
                writer
                    .write_all(b"{\"type\":\"decision\",\"action\":\"proceed\"}\n")
                    .await?;
                continue;
            }

            let mut pkg_paths = paths;
            let primary = pkg_paths.remove(0);
            let mut evt = InterceptEvent::new(primary, BackendKind::Wrapper);
            evt.bulk_paths = pkg_paths;

            sender.send(evt).await?;

            if let Some(response) = lines.next_line().await? {
                writer.write_all(response.as_bytes()).await?;
                writer.write_all(b"\n").await?;
            }
        }
    }

    Ok(())
}
