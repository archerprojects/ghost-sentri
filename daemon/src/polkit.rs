// daemon/src/polkit.rs — v1.1.0 — Thursday 12 November 2026
// Authorize a control-socket caller via polkit's D-Bus API, the same mechanism
// packagekitd / udisks2 use. The daemon runs as root (systemd system service);
// it does NOT use pkexec. Instead, for each privileged request it identifies the
// caller by SO_PEERCRED (pid/uid) and asks polkit whether that subject is allowed
// to perform our action. polkit routes the auth prompt into the caller's own
// graphical session via logind — the daemon needs no session of its own.
//
// Blocking D-Bus call: invoke from a spawn_blocking context, never on a reactor
// thread.

use dbus::blocking::Connection;
use std::collections::HashMap;
use std::time::Duration;

/// polkit action id declared in com.archerprojects.ghost-sentri.policy.
pub const ACTION_MANAGE: &str = "com.archerprojects.ghost-sentri.manage";

/// Read the process start time (field 22 of /proc/<pid>/stat, in clock ticks) —
/// polkit's unix-process subject needs it to make the (pid, start_time) pair
/// unforgeable across pid reuse.
fn process_start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The comm field can contain spaces/parentheses; everything after the final
    // ')' is space-separated, with starttime at index 19 of that tail.
    let tail = stat.rsplit_once(')')?.1;
    tail.split_whitespace().nth(19)?.parse::<u64>().ok()
}

/// Ask polkit whether the process `pid`/`uid` may perform ACTION_MANAGE.
/// `allow_interaction` lets polkit pop an auth dialog in the caller's session.
/// Returns true only on an explicit authorization.
pub fn check_authorization(pid: u32, _uid: u32, allow_interaction: bool) -> bool {
    let start_time = match process_start_time(pid) {
        Some(t) => t,
        None => {
            log::warn!("[polkit] no start_time for pid {pid}; denying");
            return false;
        }
    };

    let conn = match Connection::new_system() {
        Ok(c) => c,
        Err(e) => { log::error!("[polkit] system bus: {e}"); return false; }
    };

    let proxy = conn.with_proxy(
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        Duration::from_secs(60),
    );

    // Subject: ("unix-process", { "pid": u32, "start-time": u64 }).
    // The variant value type for the inner map is dbus::arg::Variant<Box<dyn RefArg>>.
    use dbus::arg::{RefArg, Variant};
    let mut subject_details: HashMap<String, Variant<Box<dyn RefArg>>> = HashMap::new();
    subject_details.insert("pid".into(), Variant(Box::new(pid)));
    subject_details.insert("start-time".into(), Variant(Box::new(start_time)));
    let subject = ("unix-process", subject_details);

    let action_id = ACTION_MANAGE.to_string();
    let details: HashMap<String, String> = HashMap::new();
    let flags: u32 = if allow_interaction { 1 } else { 0 }; // 1 = AllowUserInteraction
    let cancellation_id = String::new();

    // CheckAuthorization returns a SINGLE struct value of type (bba{ss}):
    // (is_authorized, is_challenge, details). In dbus-rs a returned struct is a
    // tuple, and since it is the sole return value it must be decoded as a 1-tuple
    // WRAPPING that struct — ((bool, bool, a{ss}),). Decoding it as three loose
    // args (bool, bool, a{ss}) is a signature mismatch and method_call errors,
    // which previously surfaced as a spurious "authorisation declined".
    let res: Result<((bool, bool, HashMap<String, String>),), dbus::Error> = proxy.method_call(
        "org.freedesktop.PolicyKit1.Authority",
        "CheckAuthorization",
        (subject, action_id, details, flags, cancellation_id),
    );

    match res {
        Ok(((authorized, _challenge, _d),)) => authorized,
        Err(e) => { log::error!("[polkit] CheckAuthorization: {e}"); false }
    }
}
