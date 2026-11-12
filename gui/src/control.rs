// gui/src/control.rs — v1.1.0 — Thursday 12 November 2026
// Control-socket client. Runs on the GUI's dedicated tokio runtime (crate::rt()),
// NOT on the relm4/GTK thread. Connects to the daemon's control socket, subscribes,
// forwards every ControlEvent into the dashboard, and drains ControlRequests back.
//
// v1.1.0: `request_once` — a short-lived connection for one request and its
// answer (allow-list commands from the terminal and the "Install blocked" dialog).
//
// v2.0: single select loop (reader + writer share one connection), explicit phase
// logging so connection problems are visible in the dashboard log, and automatic
// reconnect so a daemon that starts late / restarts is picked up without relaunch.

use ghost_sentri_core::protocol::{from_line, to_line, ControlEvent, ControlRequest};
use relm4::ComponentSender;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use crate::{DashboardModel, DashboardMsg};

fn log(sender: &ComponentSender<DashboardModel>, line: impl Into<String>) {
    sender.input(DashboardMsg::ControlEvent(ControlEvent::LogLine { line: line.into() }));
}

/// Connect to the daemon's control socket. Returns a sender for ControlRequests.
pub fn connect(
    socket_path: PathBuf,
    sender: ComponentSender<DashboardModel>,
) -> mpsc::Sender<ControlRequest> {
    let (req_tx, mut req_rx) = mpsc::channel::<ControlRequest>(32);

    crate::rt().spawn(async move {
        loop {
            log(&sender, format!("Connecting to daemon at {}…", socket_path.display()));

            let stream = match UnixStream::connect(&socket_path).await {
                Ok(s) => s,
                Err(e) => {
                    log(&sender, format!("Cannot reach daemon: {e} — retrying in 2s."));
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };

            let (read_half, mut write_half) = tokio::io::split(stream);
            // Subscribe so the daemon sends its StateSnapshot.
            if let Ok(line) = to_line(&ControlRequest::Subscribe) {
                if write_half.write_all(line.as_bytes()).await.is_err() {
                    log(&sender, "Daemon closed during subscribe — retrying.".to_string());
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            }
            log(&sender, "Socket open — awaiting daemon snapshot.".to_string());

            let mut lines = BufReader::new(read_half).lines();
            loop {
                tokio::select! {
                    // Outbound: dashboard requests -> socket.
                    req = req_rx.recv() => {
                        match req {
                            Some(r) => {
                                if let Ok(line) = to_line(&r) {
                                    if write_half.write_all(line.as_bytes()).await.is_err() { break; }
                                }
                            }
                            None => return, // dashboard gone
                        }
                    }
                    // Inbound: daemon events -> dashboard.
                    line = lines.next_line() => {
                        match line {
                            Ok(Some(l)) => {
                                if l.trim().is_empty() { continue; }
                                match from_line::<ControlEvent>(&l) {
                                    Ok(ev) => sender.input(DashboardMsg::ControlEvent(ev)),
                                    Err(e) => log(&sender, format!("Unparsable daemon event: {e}")),
                                }
                            }
                            Ok(None) => break,                  // EOF — daemon closed
                            Err(e) => { log(&sender, format!("Read error: {e}")); break; }
                        }
                    }
                }
            }

            log(&sender, "Daemon connection lost — reconnecting in 2s.".to_string());
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });

    req_tx
}

/// Connect, send one request, and wait (up to `wait`) for the first event that
/// `pick` accepts. Used outside the dashboard, where no live connection exists.
pub async fn request_once<T>(
    socket_path: &std::path::Path,
    req: ControlRequest,
    wait: Duration,
    pick: impl Fn(&ControlEvent) -> Option<T>,
) -> Result<T, String> {
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| format!("cannot reach the Ghost Sentri daemon ({e})"))?;
    let (read_half, mut write_half) = tokio::io::split(stream);
    let line = to_line(&req).map_err(|e| e.to_string())?;
    write_half.write_all(line.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut lines = BufReader::new(read_half).lines();
    let read = async {
        while let Ok(Some(l)) = lines.next_line().await {
            if let Ok(ev) = from_line::<ControlEvent>(&l) {
                if let Some(t) = pick(&ev) {
                    return Ok(t);
                }
            }
        }
        Err("the daemon closed the connection".to_string())
    };
    tokio::time::timeout(wait, read).await.map_err(|_| "no answer from the daemon".to_string())?
}

/// Ask the daemon to allow one exact file. Ok((approved, message)).
pub async fn request_allow(
    socket_path: &std::path::Path,
    sha256: String,
    threat: String,
    filename: String,
) -> Result<(bool, String), String> {
    let want = sha256.to_ascii_lowercase();
    request_once(
        socket_path,
        ControlRequest::AllowHash { sha256, threat, filename },
        Duration::from_secs(300), // the user may take a while at the password prompt
        move |ev| match ev {
            ControlEvent::AllowResult { sha256, ok, message } if *sha256 == want => Some((*ok, message.clone())),
            _ => None,
        },
    )
    .await
}
