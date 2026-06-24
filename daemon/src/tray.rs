// daemon/src/tray.rs — v1.0
// System tray for the headless daemon. Pure ksni (DBus) — no GTK, no relm4.
//
// "Open Dashboard" launches the on-demand GUI process (`ghost-sentri`, default
// mode). "Shutdown" signals the daemon to exit via a shutdown channel. The tray
// is the only always-present UI surface; it owns no window.

use std::process::Command;
use std::sync::mpsc::Sender;

/// Sent from tray menu activations to the daemon main loop.
pub enum TrayCommand {
    Shutdown,
}

pub struct GhostTray {
    cmd_tx: Sender<TrayCommand>,
}

impl ksni::Tray for GhostTray {
    fn id(&self)        -> String { "org.ghost.Sentri".to_string() }
    fn title(&self)     -> String { "Ghost Sentri".to_string() }
    fn icon_name(&self) -> String { "ghost-sentri".to_string() }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;
        vec![
            StandardItem {
                label: "Open Dashboard".into(),
                activate: Box::new(|_: &mut Self| {
                    // Launch the on-demand GUI; detached, daemon does not wait.
                    if let Err(e) = Command::new("ghost-sentri").spawn() {
                        log::error!("[tray] failed to launch dashboard: {}", e);
                    }
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Shutdown Ghost Sentri".into(),
                activate: Box::new(|t: &mut Self| {
                    let _ = t.cmd_tx.send(TrayCommand::Shutdown);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}

/// Spawn the tray service. Returns the receiver the daemon awaits for shutdown.
pub fn start() -> std::sync::mpsc::Receiver<TrayCommand> {
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
    let _ = ksni::TrayService::new(GhostTray { cmd_tx }).spawn();
    cmd_rx
}
