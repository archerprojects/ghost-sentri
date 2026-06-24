// gui/src/control.rs — v2.0
// Control-socket client. Runs on the GUI's dedicated tokio runtime (crate::rt()),
// NOT on the relm4/GTK thread. Connects to the daemon's control socket, subscribes,
// forwards every ControlEvent into the dashboard, and drains ControlRequests back.
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
