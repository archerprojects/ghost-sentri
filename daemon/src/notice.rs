// daemon/src/notice.rs — v1.1.0 — Thursday 12 November 2026
// Desktop notices for the Downloads watch.
//
// The root daemon has no session of its own, so a notice goes to ONE user: the
// owner of the folder the file landed in. `session::resolve_for_uid` finds that
// user's active graphical session and lifts its display environment (it carries
// DBUS_SESSION_BUS_ADDRESS, which notify-send needs). notify-send then runs as
// that user's uid and gid, in its own thread, because `-A` makes it wait until
// the user answers. A chosen action launches the dashboard as the same user.
//
// No graphical session → nothing pops up; the item stays unseen in the manifest
// and the dashboard shows the count when it next opens. notify-send missing
// (libnotify-bin is only Recommended) → a one-time warning in the journal.

use crate::session;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

const NOTIFY_SEND: &str = "/usr/bin/notify-send";
const GUI: &str = "/usr/bin/ghost-sentri";
const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Urgency {
    Normal,
    Critical,
}

#[derive(Debug, Clone)]
pub struct Notice {
    pub uid: u32,
    pub urgency: Urgency,
    pub title: String,
    pub body: String,
    /// Button label and the dashboard arguments it launches with.
    pub action: Option<(String, Vec<String>)>,
}

/// Fire and forget.
pub fn send(n: Notice) {
    std::thread::spawn(move || deliver(n));
}

fn deliver(n: Notice) {
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !std::path::Path::new(NOTIFY_SEND).exists() {
        if !WARNED.swap(true, Ordering::Relaxed) {
            log::warn!("[notify] {NOTIFY_SEND} not found (install libnotify-bin) — Downloads notices shown in the dashboard only");
        }
        return;
    }
    let Some(sess) = session::resolve_for_uid(n.uid) else {
        log::info!(
            "[notify] uid {} has no graphical session — notice left for the dashboard",
            n.uid
        );
        return;
    };

    let mut cmd = Command::new(NOTIFY_SEND);
    cmd.args(["-a", "Ghost Sentri", "-i", "ghost-sentri", "-u"])
        .arg(match n.urgency {
            Urgency::Normal => "normal",
            Urgency::Critical => "critical",
        });
    if let Some((label, _)) = &n.action {
        cmd.arg("-A").arg(format!("open={label}"));
        cmd.arg("-A").arg("dismiss=Dismiss");
    }
    cmd.arg("--").arg(&n.title).arg(escape(&n.body));
    as_user(&mut cmd, &sess);
    cmd.stdin(Stdio::null()).stderr(Stdio::null());

    let out = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            log::warn!("[notify] notify-send failed: {e}");
            return;
        }
    };
    if String::from_utf8_lossy(&out.stdout).trim() != "open" {
        return;
    }
    if let Some((_, args)) = n.action {
        let mut gui = Command::new(GUI);
        gui.args(&args);
        as_user(&mut gui, &sess);
        gui.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        gui.process_group(0);
        match gui.spawn() {
            Ok(mut c) => {
                let _ = c.wait();
            }
            Err(e) => log::warn!("[notify] could not open the dashboard: {e}"),
        }
    }
}

fn as_user(cmd: &mut Command, sess: &session::Session) {
    cmd.uid(sess.uid)
        .gid(sess.gid)
        .env_clear()
        .env("HOME", &sess.home)
        .env("USER", &sess.user)
        .env("LOGNAME", &sess.user)
        .env("PATH", SAFE_PATH)
        .envs(sess.env.iter().cloned());
}

/// Notification bodies may be read as markup; file names must not be.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// "a, b, c and 4 more" — at most three names.
pub fn name_list(names: &[String]) -> String {
    match names.len() {
        0 => String::new(),
        1..=3 => names.join(", "),
        n => format!("{} and {} more", names[..3].join(", "), n - 3),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_capped_at_three() {
        let v: Vec<String> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(name_list(&v[..1]), "a");
        assert_eq!(name_list(&v[..3]), "a, b, c");
        assert_eq!(name_list(&v), "a, b, c and 2 more");
        assert_eq!(escape("<a&b>"), "&lt;a&amp;b&gt;");
    }
}
