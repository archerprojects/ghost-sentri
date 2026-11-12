// core/src/quarantine.rs — v1.1.0 — Thursday 12 November 2026
// Per-user quarantine: records, manifest, and every file operation on it.
//
// Each user's quarantine is a folder in their own home (QuarantineConfig.dir,
// default ~/.quarantine), mode 0700 and owned by them. Quarantined files sit there
// at 0600 with execute bits removed, next to a `.manifest.json` that records what
// each one is. The user may open, edit or delete anything in it directly.
//
// Who calls this:
//   - the root daemon, through a child process that has switched to the user's
//     uid (`ghost-sentri-daemon --quarantine-move …`), so a planted symlink can
//     never trick root into moving or chmod-ing a file the user does not own;
//   - the dashboard GUI, which already runs as the user (restore / delete).
// Both writers take `.manifest.lock` and replace the manifest by rename, so a
// crash never leaves it half-written.
//
// `.released.json` lists the hashes of files the user restored. The Downloads
// watch skips those for that user only, so a restored file is not re-quarantined
// in a loop. Installing a released file is still scanned as usual.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const MANIFEST: &str = ".manifest.json";
pub const MANIFEST_LOCK: &str = ".manifest.lock";
pub const RELEASED: &str = ".released.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub filename:           String,
    pub original_path:      PathBuf,
    pub quarantine_path:    PathBuf,
    pub threat_name:        String,
    pub definition_version: String,
    pub timestamp:          DateTime<Utc>,
    /// Stable id (also the stored file's name prefix).
    #[serde(default)]
    pub id:     String,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub size:   u64,
    /// false until the user has seen it in the Quarantine tab.
    #[serde(default)]
    pub seen:   bool,
}

/// Read the quarantine manifest (`<dir>/.manifest.json`). Returns an empty list
/// when the manifest is absent or unreadable — display is best-effort.
pub fn load_manifest(quarantine_dir: &Path) -> Vec<QuarantineRecord> {
    match std::fs::read_to_string(quarantine_dir.join(MANIFEST)) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => vec![],
    }
}

/// Items the user has not yet seen.
pub fn unseen_count(quarantine_dir: &Path) -> usize {
    load_manifest(quarantine_dir).iter().filter(|r| !r.seen).count()
}

/// Create the quarantine folder (0700) if absent. Refuses a path that exists as
/// anything other than a real directory (a symlink included).
pub fn ensure_dir(dir: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_dir() => {}
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a folder", dir.display()),
            ))
        }
        Err(_) => {
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        }
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

/// Run `f` on the manifest under the manifest lock, then write it back
/// atomically (temp file + rename).
pub fn with_manifest<R>(
    dir: &Path,
    f: impl FnOnce(&mut Vec<QuarantineRecord>) -> R,
) -> std::io::Result<R> {
    ensure_dir(dir)?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(MANIFEST_LOCK))?;
    lock.lock()?;
    let mut records = load_manifest(dir);
    let out = f(&mut records);
    let res = write_atomic(dir, MANIFEST, &serde_json::to_vec_pretty(&records).map_err(to_io)?);
    let _ = lock.unlock();
    res.map(|_| out)
}

fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, dir.join(name))
}

fn to_io(e: serde_json::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
}

/// Move `src` into the quarantine. Must run as the file's owner (the daemon runs
/// it in a uid-switched child). `src` must be a regular file, not a symlink.
pub fn quarantine_file(
    src: &Path,
    dir: &Path,
    threat: &str,
    definition_version: &str,
    sha256: &str,
) -> std::io::Result<QuarantineRecord> {
    let meta = std::fs::symlink_metadata(src)?;
    if !meta.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", src.display()),
        ));
    }
    ensure_dir(dir)?;
    let filename = src
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    let now = Utc::now();
    let short = if sha256.len() >= 12 { &sha256[..12] } else { sha256 };
    let id = format!("{}-{}", now.format("%Y%m%d%H%M%S%3f"), short);
    let stored = dir.join(format!("{id}__{filename}"));

    move_file(src, &stored)?;
    std::fs::set_permissions(&stored, std::fs::Permissions::from_mode(0o600))?;

    let rec = QuarantineRecord {
        filename,
        original_path: src.to_path_buf(),
        quarantine_path: stored,
        threat_name: threat.to_string(),
        definition_version: definition_version.to_string(),
        timestamp: now,
        id,
        sha256: sha256.to_string(),
        size: meta.len(),
        seen: false,
    };
    let r = rec.clone();
    with_manifest(dir, move |m| m.push(r))?;
    Ok(rec)
}

/// Rename, falling back to copy + remove across filesystems.
fn move_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    match std::fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(18) => {
            // EXDEV — different filesystem.
            std::fs::copy(src, dst)?;
            std::fs::remove_file(src)
        }
        Err(e) => Err(e),
    }
}

/// `name.ext` → first free of `name.ext`, `name (1).ext`, `name (2).ext`, …
pub fn free_restore_path(target: &Path) -> PathBuf {
    if std::fs::symlink_metadata(target).is_err() {
        return target.to_path_buf();
    }
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let name = target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (name[..i].to_string(), name[i..].to_string()),
        _ => (name.clone(), String::new()),
    };
    for n in 1.. {
        let p = parent.join(format!("{stem} ({n}){ext}"));
        if std::fs::symlink_metadata(&p).is_err() {
            return p;
        }
    }
    unreachable!()
}

/// Restore an item to its original folder (or a free name beside it), at 0644
/// with no execute bit, release its hash for the Downloads watch, and drop its
/// record. Runs as the user (GUI).
pub fn restore(dir: &Path, id: &str) -> std::io::Result<PathBuf> {
    let rec = load_manifest(dir)
        .into_iter()
        .find(|r| r.id == id)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such quarantine item"))?;
    if let Some(parent) = rec.original_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let target = free_restore_path(&rec.original_path);
    move_file(&rec.quarantine_path, &target)?;
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))?;
    if !rec.sha256.is_empty() {
        add_released(dir, &rec.sha256)?;
    }
    with_manifest(dir, |m| m.retain(|r| r.id != id))?;
    Ok(target)
}

/// Delete one item and its record.
pub fn delete(dir: &Path, id: &str) -> std::io::Result<()> {
    if let Some(rec) = load_manifest(dir).into_iter().find(|r| r.id == id) {
        match std::fs::remove_file(&rec.quarantine_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    with_manifest(dir, |m| m.retain(|r| r.id != id))
}

/// Delete an unrecorded file found in the quarantine folder (by file name).
pub fn delete_unrecorded(dir: &Path, name: &str) -> std::io::Result<()> {
    if name.contains('/') || name.starts_with('.') {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad name"));
    }
    std::fs::remove_file(dir.join(name))
}

/// Delete every item, recorded or not. Keeps the released list.
pub fn delete_all(dir: &Path) -> std::io::Result<()> {
    for r in load_manifest(dir) {
        let _ = std::fs::remove_file(&r.quarantine_path);
    }
    for name in unrecorded(dir) {
        let _ = std::fs::remove_file(dir.join(name));
    }
    with_manifest(dir, |m| m.clear())
}

/// Mark every record seen.
pub fn mark_all_seen(dir: &Path) -> std::io::Result<()> {
    if load_manifest(dir).iter().all(|r| r.seen) {
        return Ok(());
    }
    with_manifest(dir, |m| m.iter_mut().for_each(|r| r.seen = true))
}

/// Drop records whose file the user removed by hand. Returns how many.
pub fn reconcile(dir: &Path) -> std::io::Result<usize> {
    let missing = load_manifest(dir)
        .iter()
        .filter(|r| std::fs::symlink_metadata(&r.quarantine_path).is_err())
        .count();
    if missing == 0 {
        return Ok(0);
    }
    with_manifest(dir, |m| {
        m.retain(|r| std::fs::symlink_metadata(&r.quarantine_path).is_ok());
    })?;
    Ok(missing)
}

/// Files in the folder with no record (dotfiles excluded).
pub fn unrecorded(dir: &Path) -> Vec<String> {
    let known: HashSet<PathBuf> = load_manifest(dir).into_iter().map(|r| r.quarantine_path).collect();
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || known.contains(&e.path()) {
                continue;
            }
            out.push(name);
        }
    }
    out.sort();
    out
}

/// Hashes the user released by restoring.
pub fn load_released(dir: &Path) -> HashSet<String> {
    match std::fs::read_to_string(dir.join(RELEASED)) {
        Ok(s) => serde_json::from_str::<Vec<String>>(&s).unwrap_or_default().into_iter().collect(),
        Err(_) => HashSet::new(),
    }
}

pub fn add_released(dir: &Path, sha256: &str) -> std::io::Result<()> {
    let mut set: Vec<String> = load_released(dir).into_iter().collect();
    if !set.iter().any(|s| s == sha256) {
        set.push(sha256.to_string());
    }
    set.sort();
    ensure_dir(dir)?;
    write_atomic(dir, RELEASED, &serde_json::to_vec_pretty(&set).map_err(to_io)?)
}

/// Move a whole quarantine to a new location (Settings change). Runs as the user.
/// Record paths are rewritten to the new folder.
pub fn relocate(old: &Path, new: &Path) -> std::io::Result<()> {
    if old == new || std::fs::symlink_metadata(old).map(|m| !m.file_type().is_dir()).unwrap_or(true) {
        return Ok(());
    }
    ensure_dir(new)?;
    let records = load_manifest(old);
    for entry in std::fs::read_dir(old)?.flatten() {
        let name = entry.file_name();
        let n = name.to_string_lossy();
        if n == MANIFEST || n == MANIFEST_LOCK || n.ends_with(".tmp") {
            continue;
        }
        let dst = free_restore_path(&new.join(&name));
        move_file(&entry.path(), &dst)?;
    }
    let moved: Vec<QuarantineRecord> = records
        .into_iter()
        .map(|mut r| {
            if let Some(n) = r.quarantine_path.file_name() {
                r.quarantine_path = new.join(n);
            }
            r
        })
        .collect();
    with_manifest(new, |m| m.extend(moved))?;
    let _ = std::fs::remove_file(old.join(MANIFEST));
    let _ = std::fs::remove_file(old.join(MANIFEST_LOCK));
    let _ = std::fs::remove_dir(old);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        // Inside the workspace target/ (gitignored), never the system temp folder.
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/test-scratch")
            .join(format!("gs-q-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn quarantine_restore_round_trip() {
        let root = scratch("rt");
        let dl = root.join("Downloads");
        std::fs::create_dir_all(&dl).unwrap();
        let src = dl.join("bad.sh");
        std::fs::write(&src, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o755)).unwrap();
        let q = root.join(".quarantine");

        let rec = quarantine_file(&src, &q, "Eicar", "v1", "ab".repeat(32).as_str()).unwrap();
        assert!(!src.exists());
        let mode = std::fs::metadata(&rec.quarantine_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::metadata(&q).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(unseen_count(&q), 1);
        mark_all_seen(&q).unwrap();
        assert_eq!(unseen_count(&q), 0);

        // Name taken → suffix.
        std::fs::write(&src, b"other").unwrap();
        let back = restore(&q, &rec.id).unwrap();
        assert_eq!(back, dl.join("bad (1).sh"));
        assert_eq!(std::fs::metadata(&back).unwrap().permissions().mode() & 0o777, 0o644);
        assert!(load_manifest(&q).is_empty());
        assert!(load_released(&q).contains(&"ab".repeat(32)));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reconcile_and_unrecorded() {
        let root = scratch("rc");
        let q = root.join("q");
        let f = root.join("x.exe");
        std::fs::write(&f, b"MZ").unwrap();
        let rec = quarantine_file(&f, &q, "T", "v", "cd".repeat(32).as_str()).unwrap();
        std::fs::write(q.join("stray.bin"), b"1").unwrap();
        assert_eq!(unrecorded(&q), vec!["stray.bin".to_string()]);
        std::fs::remove_file(&rec.quarantine_path).unwrap();
        assert_eq!(reconcile(&q).unwrap(), 1);
        assert!(load_manifest(&q).is_empty());
        delete_all(&q).unwrap();
        assert!(unrecorded(&q).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn refuses_symlink_source() {
        let root = scratch("sl");
        let target = root.join("real");
        std::fs::write(&target, b"x").unwrap();
        let link = root.join("link.sh");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(quarantine_file(&link, &root.join("q"), "T", "v", "00").is_err());
        assert!(target.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn relocate_moves_items() {
        let root = scratch("mv");
        let old = root.join("q1");
        let new = root.join("sub/q2");
        let f = root.join("a.jar");
        std::fs::write(&f, b"PK").unwrap();
        quarantine_file(&f, &old, "T", "v", "ef".repeat(32).as_str()).unwrap();
        relocate(&old, &new).unwrap();
        let m = load_manifest(&new);
        assert_eq!(m.len(), 1);
        assert!(m[0].quarantine_path.starts_with(&new));
        assert!(m[0].quarantine_path.exists());
        assert!(!old.exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
