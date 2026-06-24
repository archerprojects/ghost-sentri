// daemon/src/apply.rs
// Root-side commit of machine policy. The daemon now runs as a root systemd
// SYSTEM service, so it calls `apply_config()` IN-PROCESS after authorising the
// caller via polkit — there is no per-op pkexec anymore. The `run_apply()` CLI
// wrapper (`ghost-sentri-daemon --apply …`) is retained for manual/offline use.
// This is the ONLY writer of machine policy:
//   - /etc/ghost-sentri/config.toml      (scanner enable flags)
//   - /etc/apt/apt.conf.d/99ghost-sentri (terminal apt install hook)
//   - /etc/xdg/mimeapps.list             (.deb file-manager default handler)
// Daemon RUN is owned by systemd (ghost-sentri-daemon.service), so this no longer
// installs an XDG autostart entry.

use ghost_sentri_core::config::Config;
use std::path::Path;
use std::process::Command;

const STATE: &str             = "/var/lib/ghost-sentri";
const SYS_MIME: &str          = "/etc/xdg/mimeapps.list";
const MIME_TYPE: &str         = "application/vnd.debian.binary-package";
const HANDLER: &str           = "ghost-sentri.desktop";
const HOOK: &str              = "/etc/apt/apt.conf.d/99ghost-sentri";
const HOOK_TEMPLATE: &str     = "/usr/share/ghost-sentri/99ghost-sentri";
// Local .deb interception: a dpkg PATH-shim at /usr/local/sbin (ahead of
// /usr/bin in sudoers secure_path) catches LOCAL installs (nala ./x.deb,
// dpkg -i) that the apt Pre-Install-Pkgs hook never sees. Armed with the apt
// monitor; the shim itself fails open to /usr/bin/dpkg.
const SHIM_BIN: &str          = "/usr/libexec/ghost-sentri-dpkg-shim";
const SHIM_LINK: &str         = "/usr/local/sbin/dpkg";

/// Commit a toggle set as root, in-process. Writes /etc config and the .deb
/// package handler, and optionally refreshes definitions. Returns
/// `(ok, defs_attempted, defs_ok)`. Performs NO authorization itself — the caller
/// (daemon control handler) authorises via polkit first.
pub fn apply_config(enable: &[String], disable: &[String], update_defs: bool) -> (bool, bool, bool) {
    let mut cfg = Config::load().unwrap_or_default();

    for id in disable { set_flag(&mut cfg, id, false); }
    for id in enable  { set_flag(&mut cfg, id, true); }

    if let Some(dir) = Path::new(&Config::config_path()).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(e) = cfg.save() {
        eprintln!("[apply] config write failed: {e}");
        return (false, false, false);
    }

    // .deb package handler (apt hook + MIME default) follows the apt monitor.
    if cfg.backends.enable_apt { enable_package_handler(); } else { disable_package_handler(); }

    let (defs_attempted, defs_ok) = if update_defs {
        let ok = Command::new("freshclam").status().map(|s| s.success()).unwrap_or(false);
        (true, ok)
    } else {
        (false, false)
    };

    (true, defs_attempted, defs_ok)
}

/// CLI wrapper: `ghost-sentri-daemon --apply …`. Prints the `GS_*` markers the
/// (legacy) GUI parsed and returns a process exit code. The live path is now
/// `apply_config()` called inside the daemon.
pub fn run_apply(enable: Vec<String>, disable: Vec<String>, update_defs: bool) -> i32 {
    let (ok, defs_attempted, defs_ok) = apply_config(&enable, &disable, update_defs);
    if defs_attempted {
        println!("{}", if defs_ok { "GS_DEFS_OK" } else { "GS_DEFS_FAIL" });
    }
    if ok { println!("GS_APPLY_OK"); 0 } else { 1 }
}

fn set_flag(cfg: &mut Config, id: &str, on: bool) {
    let b = &mut cfg.backends;
    match id {
        "apt"        => b.enable_apt = on,
        "flatpak"    => b.enable_flatpak = on,
        "wine"       => b.enable_wine = on,
        "source"     => b.enable_build_source = on,
        "wrapper"    => b.enable_wrapper = on,
        "snap"       => b.enable_snap = on,
        _ => {}
    }
}

// ── .deb package handler (apt hook + MIME default) ──────────────────────────

fn enable_package_handler() {
    if let Err(e) = std::fs::copy(HOOK_TEMPLATE, HOOK) {
        eprintln!("[apply] apt hook install failed: {e}");
    }
    backup_mime_once();
    set_mime_default();
    refresh_desktop_db();
    enable_dpkg_shim();
}

fn disable_package_handler() {
    let _ = std::fs::remove_file(HOOK);
    restore_mime();
    refresh_desktop_db();
    disable_dpkg_shim();
}

// ── local .deb interception (dpkg PATH-shim) ────────────────────────────────
// We touch ONLY our own symlink. A pre-existing /usr/local/sbin/dpkg placed by
// the admin is never clobbered (enable) and never removed (disable). The link
// is only created when the shim binary is actually present, so we can never
// leave a dangling /usr/local/sbin/dpkg that would break package management.

fn enable_dpkg_shim() {
    if !Path::new(SHIM_BIN).exists() {
        eprintln!("[apply] dpkg shim missing ({SHIM_BIN}); local-.deb interception NOT armed");
        return;
    }
    if let Some(dir) = Path::new(SHIM_LINK).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    match std::fs::symlink_metadata(SHIM_LINK) {
        Ok(_) => {
            // Something already at the path.
            if std::fs::read_link(SHIM_LINK).ok().as_deref() == Some(Path::new(SHIM_BIN)) {
                return; // already our shim — idempotent
            }
            eprintln!("[apply] {SHIM_LINK} exists and is not ours; leaving it untouched");
        }
        Err(_) => {
            if let Err(e) = std::os::unix::fs::symlink(SHIM_BIN, SHIM_LINK) {
                eprintln!("[apply] dpkg shim symlink failed: {e}");
            }
        }
    }
}

fn disable_dpkg_shim() {
    if std::fs::read_link(SHIM_LINK).ok().as_deref() == Some(Path::new(SHIM_BIN)) {
        let _ = std::fs::remove_file(SHIM_LINK);
    }
}

/// Re-read the desktop/MIME databases so the file manager picks up a default
/// handler change immediately rather than after the next login.
fn refresh_desktop_db() {
    let _ = Command::new("update-desktop-database")
        .arg("/usr/share/applications")
        .status();
}

/// The current `.deb` default handler recorded in a given mimeapps file, if any.
fn deb_default_in(path: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut in_default = false;
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with('[') { in_default = t == "[Default Applications]"; continue; }
        if in_default && is_key_line(t, MIME_TYPE) {
            return t.split_once('=').map(|(_, v)| v.trim().to_string());
        }
    }
    None
}

/// Back up the prior system mimeapps.list exactly once, so disable/removal can
/// put the user's previous default `.deb` handler back. Mirrors postinst markers
/// so postrm restoration stays consistent.
fn backup_mime_once() {
    let backup  = format!("{STATE}/mimeapps.gs-backup");
    let created = format!("{STATE}/mimeapps.gs-created");
    let _ = std::fs::create_dir_all(STATE);
    if Path::new(&backup).exists() || Path::new(&created).exists() { return; }
    if Path::new(SYS_MIME).exists() {
        // Never record OUR handler as the "original" default — a leftover state
        // from an earlier cycle would otherwise make a later disable restore
        // ghost-sentri instead of the real prior handler. In that case mark the
        // file as created-by-us, so disable cleanly drops our line and the real
        // default (e.g. gdebi) resumes.
        if deb_default_in(SYS_MIME).as_deref() == Some(HANDLER) {
            let _ = std::fs::write(&created, b"");
        } else {
            let _ = std::fs::copy(SYS_MIME, &backup);
        }
    } else {
        let _ = std::fs::write(&created, b""); // marker: we created the file
    }
}

fn restore_mime() {
    let backup  = format!("{STATE}/mimeapps.gs-backup");
    let created = format!("{STATE}/mimeapps.gs-created");
    if Path::new(&backup).exists() {
        // Defend against a backup that itself carries our handler (a polluted
        // capture from a prior cycle): reinstating it would keep ghost-sentri as
        // the default. Drop our line instead so the real default resumes.
        if deb_default_in(&backup).as_deref() == Some(HANDLER) {
            remove_mime_default();
        } else {
            let _ = std::fs::copy(&backup, SYS_MIME);
        }
    } else if Path::new(&created).exists() {
        // We created the file: dropping our default line is the clean restore.
        remove_mime_default();
    } else {
        remove_mime_default();
    }
}

/// Set `MIME_TYPE=HANDLER` under [Default Applications], preserving every other
/// association. Creates the section/file if absent.
fn set_mime_default() {
    let entry = format!("{MIME_TYPE}={HANDLER}");
    let existing = std::fs::read_to_string(SYS_MIME).unwrap_or_default();

    let mut out: Vec<String> = Vec::new();
    let mut in_default = false;
    let mut wrote = false;
    let mut saw_default = false;

    for line in existing.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            if in_default && !wrote { out.push(entry.clone()); wrote = true; }
            in_default = t == "[Default Applications]";
            if in_default { saw_default = true; }
            out.push(line.to_string());
            continue;
        }
        if in_default && is_key_line(t, MIME_TYPE) {
            if !wrote { out.push(entry.clone()); wrote = true; }
            continue; // drop the prior value
        }
        out.push(line.to_string());
    }
    if in_default && !wrote { out.push(entry.clone()); }
    if !saw_default {
        if !out.is_empty() && !out.last().map(|l| l.trim().is_empty()).unwrap_or(true) {
            out.push(String::new());
        }
        out.push("[Default Applications]".to_string());
        out.push(entry);
    }

    let mut joined = out.join("\n");
    joined.push('\n');
    let _ = std::fs::write(SYS_MIME, joined);
}

/// Drop our MIME_TYPE line from [Default Applications] (used when we created the
/// file, or have no backup to restore).
fn remove_mime_default() {
    let Ok(content) = std::fs::read_to_string(SYS_MIME) else { return };
    let mut in_default = false;
    let mut out: Vec<String> = Vec::new();
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with('[') { in_default = t == "[Default Applications]"; }
        if in_default && is_key_line(t, MIME_TYPE) { continue; }
        out.push(line.to_string());
    }
    let mut joined = out.join("\n");
    joined.push('\n');
    let _ = std::fs::write(SYS_MIME, joined);
}

fn is_key_line(t: &str, key: &str) -> bool {
    t.strip_prefix(key).map(|r| r.trim_start().starts_with('=')).unwrap_or(false)
}
