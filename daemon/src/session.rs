// daemon/src/session.rs — v1.1.0 — Thursday 12 November 2026
// Resolve the live LOCAL graphical session so the root apt-hook can launch the
// review GUI INTO it — same session the user is already logged into. No relogin,
// no autostart, no per-user daemon. This is what makes terminal `sudo apt` show
// the GUI again after the privilege inversion: the hook is root, so it asks
// logind who is active, lifts that session's display environment from a process
// the user already owns, and launches as that user.
//
// Pure resolution — shells out to loginctl/getent and reads /proc. No GTK.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

pub struct Session {
    pub uid:  u32,
    pub gid:  u32,
    pub user: String,
    pub home: PathBuf,
    /// Display environment lifted from the session (DISPLAY/WAYLAND_DISPLAY plus
    /// the supporting vars). Guaranteed to contain at least one display variable.
    pub env: Vec<(String, String)>,
}

/// First active x11/wayland session with a resolvable display environment, or
/// None (→ caller falls back to TTY review or policy).
pub fn resolve_active_graphical() -> Option<Session> {
    resolve(None)
}

/// The active x11/wayland session of one user (Downloads watch notices go to
/// the owner of the folder, nobody else), or None if that user has none.
pub fn resolve_for_uid(uid: u32) -> Option<Session> {
    resolve(Some(uid))
}

fn resolve(only_uid: Option<u32>) -> Option<Session> {
    for sid in list_sessions() {
        let props = show_session(&sid);
        let active = props.get("Active").map(|v| v == "yes").unwrap_or(false);
        let typ = props.get("Type").map(String::as_str).unwrap_or("");
        if !active || (typ != "x11" && typ != "wayland") {
            continue;
        }
        let uid: u32 = match props.get("User").and_then(|v| v.parse().ok()) {
            Some(u) => u,
            None => continue,
        };
        if only_uid.is_some_and(|want| want != uid) {
            continue;
        }
        let leader: Option<i32> = props.get("Leader").and_then(|v| v.parse().ok());
        let (user, home, gid) = match passwd(uid) {
            Some(t) => t,
            None => continue,
        };
        if let Some(env) = lift_display_env(uid, leader) {
            return Some(Session { uid, gid, user, home: PathBuf::from(home), env });
        }
    }
    None
}

/// Session IDs from `loginctl list-sessions --no-legend` (first column).
fn list_sessions() -> Vec<String> {
    let out = Command::new("loginctl")
        .args(["list-sessions", "--no-legend"])
        .output();
    let text = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => return Vec::new(),
    };
    text.lines()
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .collect()
}

/// `loginctl show-session <id>` parsed into KEY=VALUE pairs.
fn show_session(sid: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let out = Command::new("loginctl").args(["show-session", sid]).output();
    if let Ok(o) = out {
        if o.status.success() {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                if let Some((k, v)) = line.split_once('=') {
                    map.insert(k.trim().to_string(), v.trim().to_string());
                }
            }
        }
    }
    map
}

/// (username, home, gid) for a uid via `getent passwd`.
fn passwd(uid: u32) -> Option<(String, String, u32)> {
    let out = Command::new("getent").args(["passwd", &uid.to_string()]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&out.stdout);
    // name:passwd:uid:gid:gecos:home:shell
    let f: Vec<&str> = line.trim().split(':').collect();
    if f.len() < 7 {
        return None;
    }
    let gid: u32 = f[3].parse().ok()?;
    Some((f[0].to_string(), f[5].to_string(), gid))
}

/// Display vars worth carrying into the GUI launch.
const WANTED: &[&str] = &[
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_SESSION_TYPE",
    "XDG_DATA_DIRS",
];

/// Lift the display environment for `uid`. Tries the session leader's environ
/// first, then scans the user's processes for one that actually has a display
/// set. Returns None if no DISPLAY/WAYLAND_DISPLAY can be found (no GUI possible).
fn lift_display_env(uid: u32, leader: Option<i32>) -> Option<Vec<(String, String)>> {
    if let Some(pid) = leader {
        if let Some(env) = display_env_of(pid, uid) {
            return Some(env);
        }
    }
    // Scan /proc for a process owned by uid that carries a display var.
    let entries = std::fs::read_dir("/proc").ok()?;
    for e in entries.flatten() {
        let name = e.file_name();
        let pid: i32 = match name.to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        if let Some(env) = display_env_of(pid, uid) {
            return Some(env);
        }
    }
    None
}

/// Read /proc/<pid>/environ if owned by `uid`; extract WANTED vars. Returns Some
/// only if a display variable is present.
fn display_env_of(pid: i32, uid: u32) -> Option<Vec<(String, String)>> {
    if proc_uid(pid)? != uid {
        return None;
    }
    let raw = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    let mut found: HashMap<String, String> = HashMap::new();
    for kv in raw.split(|b| *b == 0) {
        if kv.is_empty() {
            continue;
        }
        let s = String::from_utf8_lossy(kv);
        if let Some((k, v)) = s.split_once('=') {
            if WANTED.contains(&k) {
                found.insert(k.to_string(), v.to_string());
            }
        }
    }
    if found.contains_key("DISPLAY") || found.contains_key("WAYLAND_DISPLAY") {
        Some(found.into_iter().collect())
    } else {
        None
    }
}

/// Real uid of a process from /proc/<pid>/status ("Uid:\treal\teff\t…").
fn proc_uid(pid: i32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next().and_then(|n| n.parse().ok());
        }
    }
    None
}
