// daemon/src/backends/downloads.rs — v1.1.0 — Thursday 12 November 2026
// Downloads watch — scans new files in every real user's download folders and
// quarantines threats. Replaces the Wine and Flatpak monitors.
//
// Users: every passwd account with UID_MIN ≤ uid ≤ UID_MAX (/etc/login.defs),
// a home folder under /home, and a login shell that is not nologin/false.
// Re-read every 60 s, so new accounts are picked up without a restart.
//
// Folders: the user's XDG download folder (~/.config/user-dirs.dirs, $HOME
// expanded) plus the config's home-relative folders (default ~/Downloads). Each
// must resolve inside that user's home. Top level only. Re-resolved every 60 s.
//
// Files: by extension (config list), else by first bytes (\x7fELF, MZ, #!).
// Temporary download names are ignored; their final rename triggers the scan.
//
// When: IN_CLOSE_WRITE and IN_MOVED_TO. Every event restarts a 5 s timer; when it
// runs out, everything collected is scanned in ONE clamscan run. A steady stream
// cannot hold the batch off for more than 60 s. A hash already scanned clean is
// skipped (same file saved twice, or copied under a new name).
//
// Verdicts:
//   threat           → moved to the user's quarantine by a child process running
//                      as that user (never root), critical notice, audit line
//   clean            → audit line only
//   over 512 MB, RAR without a matching libclamunrar, limits exceeded
//                    → left in place, notice, audit line — never a silent pass
//   scan error       → left in place, notice, retried once with the next batch
// Allow-listed hashes and hashes the user released (by restoring) are skipped.

use super::{BackendExtra, BackendKind, InterceptBackend, InterceptEvent};
use crate::notice::{self, Notice, Urgency};
use crate::scan_slot::{self, Priority};
use anyhow::Result;
use async_trait::async_trait;
use ghost_sentri_core::allowlist::{is_valid_sha256, AllowList};
use ghost_sentri_core::clam::{self, FileVerdict, SystemClamBackend};
use ghost_sentri_core::config::{is_valid_home_relative, Config};
use ghost_sentri_core::events::{self, Action, AuditEvent, ScanOutcome};
use ghost_sentri_core::protocol::Avenue;
use ghost_sentri_core::quarantine::{self, QuarantineRecord};
use notify::event::{AccessKind, AccessMode, ModifyKind, RenameMode};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const QUIET: Duration = Duration::from_secs(5);
const FORCE: Duration = Duration::from_secs(60);
const REFRESH: Duration = Duration::from_secs(60);
const MAX_AUTO_SCAN: u64 = 512 * 1024 * 1024;
const SCANNED_CAP: usize = 4096;
const DAEMON_BIN: &str = "/usr/libexec/ghost-sentri-daemon";
const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const TEMP_SUFFIXES: [&str; 6] = [
    ".part",
    ".crdownload",
    ".download",
    ".tmp",
    ".partial",
    ".!qb",
];

// ─────────────────────────────────────────────────────────────────────────────
// Users and folders
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlUser {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
    pub home: PathBuf,
}

/// (UID_MIN, UID_MAX) from /etc/login.defs; 1000/60000 when absent.
fn login_defs_range() -> (u32, u32) {
    let text = std::fs::read_to_string("/etc/login.defs").unwrap_or_default();
    parse_login_defs(&text)
}

fn parse_login_defs(text: &str) -> (u32, u32) {
    let (mut min, mut max) = (1000u32, 60000u32);
    for line in text.lines() {
        let mut f = line.split_whitespace();
        match (f.next(), f.next().and_then(|v| v.parse::<u32>().ok())) {
            (Some("UID_MIN"), Some(v)) => min = v,
            (Some("UID_MAX"), Some(v)) => max = v,
            _ => {}
        }
    }
    (min, max)
}

/// Every real user (see header). Home must exist as a folder.
pub fn real_users() -> Vec<DlUser> {
    let (min, max) = login_defs_range();
    let text = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    parse_passwd(&text, min, max)
        .into_iter()
        .filter(|u| u.home.is_dir())
        .collect()
}

fn parse_passwd(text: &str, min: u32, max: u32) -> Vec<DlUser> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 {
            continue;
        }
        let (Ok(uid), Ok(gid)) = (f[2].parse::<u32>(), f[3].parse::<u32>()) else {
            continue;
        };
        let shell = f[6].trim();
        if uid < min
            || uid > max
            || !f[5].starts_with("/home/")
            || shell.ends_with("nologin")
            || shell.ends_with("/false")
        {
            continue;
        }
        out.push(DlUser {
            uid,
            gid,
            name: f[0].to_string(),
            home: PathBuf::from(f[5]),
        });
    }
    out
}

/// User name for a uid (audit lines), "uid:N" if unknown.
pub fn user_name(uid: u32) -> String {
    let text = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    text.lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() > 2 && f[2] == uid.to_string()).then(|| f[0].to_string())
        })
        .unwrap_or_else(|| format!("uid:{uid}"))
}

/// XDG_DOWNLOAD_DIR from a user-dirs.dirs text, `$HOME` expanded.
fn parse_user_dirs(text: &str, home: &Path) -> Option<PathBuf> {
    for line in text.lines() {
        let Some(v) = line.trim().strip_prefix("XDG_DOWNLOAD_DIR=") else {
            continue;
        };
        let v = v.trim().trim_matches('"');
        if let Some(rest) = v.strip_prefix("$HOME") {
            return Some(home.join(rest.trim_start_matches('/')));
        }
        if v.starts_with('/') {
            return Some(PathBuf::from(v));
        }
    }
    None
}

/// The folders to watch for one user: canonical, existing, inside the home, and
/// never the user's quarantine folder.
pub fn folders_for(user: &DlUser, cfg: &Config) -> Vec<PathBuf> {
    let Ok(home) = std::fs::canonicalize(&user.home) else {
        return vec![];
    };
    let quarantine = std::fs::canonicalize(cfg.quarantine.dir_for(&user.home)).ok();
    let mut wanted: Vec<PathBuf> = Vec::new();
    if let Ok(text) = std::fs::read_to_string(user.home.join(".config/user-dirs.dirs")) {
        if let Some(p) = parse_user_dirs(&text, &user.home) {
            wanted.push(p);
        }
    }
    for f in &cfg.downloads.folders {
        if is_valid_home_relative(f) {
            wanted.push(user.home.join(f.trim()));
        }
    }
    let mut out: Vec<PathBuf> = Vec::new();
    for w in wanted {
        let Ok(c) = std::fs::canonicalize(&w) else {
            continue;
        }; // not there yet
        if c.is_dir()
            && c.starts_with(&home)
            && c != home
            && Some(&c) != quarantine.as_ref()
            && !out.contains(&c)
        {
            out.push(c);
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// File selection
// ─────────────────────────────────────────────────────────────────────────────

fn is_temp_or_hidden(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.starts_with('.') || TEMP_SUFFIXES.iter().any(|s| l.ends_with(s))
}

fn extension(name: &str) -> Option<String> {
    let i = name.rfind('.')?;
    (i > 0).then(|| name[i + 1..].to_ascii_lowercase())
}

fn ext_listed(name: &str, exts: &[String]) -> bool {
    extension(name).is_some_and(|e| exts.iter().any(|x| x.eq_ignore_ascii_case(&e)))
}

fn magic_is_program(head: &[u8]) -> bool {
    head.starts_with(b"\x7fELF") || head.starts_with(b"MZ") || head.starts_with(b"#!")
}

/// First 4 bytes of a regular file. Opened O_NONBLOCK|O_NOFOLLOW and re-checked
/// on the handle, so a FIFO or symlink swapped in can never stall the daemon.
fn read_head(path: &Path) -> Option<Vec<u8>> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut buf = [0u8; 4];
    let n = f.read(&mut buf).ok()?;
    Some(buf[..n].to_vec())
}

fn is_candidate(path: &Path, exts: &[String]) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    ext_listed(&name, exts) || read_head(path).is_some_and(|h| magic_is_program(&h))
}

/// sha256sum under a 2-minute ceiling (a swapped-in FIFO cannot hang it).
fn sha256_bounded(path: &Path) -> Option<String> {
    let out = Command::new("timeout")
        .args(["-k", "5", "120", "sha256sum", "--"])
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let h = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()?
        .to_ascii_lowercase();
    is_valid_sha256(&h).then_some(h)
}

fn human_size(b: u64) -> String {
    const G: f64 = 1024.0 * 1024.0 * 1024.0;
    const M: f64 = 1024.0 * 1024.0;
    if b as f64 >= G {
        format!("{:.1} GB", b as f64 / G)
    } else {
        format!("{:.0} MB", b as f64 / M)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Backend
// ─────────────────────────────────────────────────────────────────────────────

pub struct DownloadsBackend {
    config: Config,
}

impl DownloadsBackend {
    pub fn new(config: Config) -> Self {
        Self { config }
    }
}

/// Hashes recently scanned clean (bounded, oldest dropped).
#[derive(Default)]
struct Scanned {
    order: VecDeque<String>,
    set: HashSet<String>,
}

impl Scanned {
    fn contains(&self, h: &str) -> bool {
        self.set.contains(h)
    }
    fn insert(&mut self, h: String) {
        if self.set.insert(h.clone()) {
            self.order.push_back(h);
            if self.order.len() > SCANNED_CAP {
                if let Some(old) = self.order.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
    }
}

struct Report {
    note: String,
    quarantined: bool,
}

struct BatchResult {
    reports: Vec<Report>,
    retry: Vec<(PathBuf, DlUser)>,
    scanned: Scanned,
}

#[async_trait]
impl InterceptBackend for DownloadsBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Downloads
    }

    fn is_available(&self) -> bool {
        self.config.resolve_clamscan().exists()
    }

    async fn run(&self, sender: mpsc::Sender<InterceptEvent>) -> Result<()> {
        let (tx, mut rx) = mpsc::channel::<Event>(1024);
        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(ev) = res {
                    let _ = tx.blocking_send(ev);
                }
            },
            notify::Config::default(),
        )?;

        let cfg = self.config.clone();
        let mut watched: HashMap<PathBuf, DlUser> = HashMap::new();
        refresh_watches(&mut watcher, &mut watched, &cfg, &sender).await;

        let mut pending: HashMap<PathBuf, DlUser> = HashMap::new();
        let mut first_pending: Option<Instant> = None;
        let mut last_event: Option<Instant> = None;
        let mut retry_next: Vec<(PathBuf, DlUser)> = Vec::new();
        let mut scanned = Scanned::default();

        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut refresh = tokio::time::interval(REFRESH);
        refresh.tick().await; // first tick is immediate; watches were just set

        loop {
            tokio::select! {
                ev = rx.recv() => {
                    let Some(ev) = ev else { break };
                    let path = match ev.kind {
                        EventKind::Access(AccessKind::Close(AccessMode::Write))
                        | EventKind::Modify(ModifyKind::Name(RenameMode::To))
                        | EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => ev.paths.last().cloned(),
                        _ => None,
                    };
                    let Some(path) = path else { continue };
                    let Some(user) = path.parent().and_then(|p| watched.get(p)).cloned() else { continue };
                    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                    if is_temp_or_hidden(&name) {
                        continue;
                    }
                    let now = Instant::now();
                    pending.insert(path, user);
                    first_pending.get_or_insert(now);
                    last_event = Some(now);
                }
                _ = tick.tick() => {
                    let (Some(first), Some(last)) = (first_pending, last_event) else { continue };
                    if pending.is_empty() || (last.elapsed() < QUIET && first.elapsed() < FORCE) {
                        continue;
                    }
                    let mut items: Vec<(PathBuf, DlUser)> = pending.drain().collect();
                    first_pending = None;
                    last_event = None;
                    let retry_set: HashSet<PathBuf> = retry_next.iter().map(|(p, _)| p.clone()).collect();
                    for r in retry_next.drain(..) {
                        if !items.iter().any(|(p, _)| *p == r.0) {
                            items.push(r);
                        }
                    }
                    let cfg_b = cfg.clone();
                    let sc = std::mem::take(&mut scanned);
                    let res = tokio::task::spawn_blocking(move || process_batch(items, &retry_set, &cfg_b, sc)).await;
                    match res {
                        Ok(r) => {
                            scanned = r.scanned;
                            retry_next = r.retry;
                            for rep in r.reports {
                                let mut evt = InterceptEvent::new(PathBuf::new(), BackendKind::Downloads);
                                evt.note = Some(rep.note);
                                evt.extra = Some(BackendExtra::Downloads { quarantined: rep.quarantined });
                                let _ = sender.send(evt).await;
                            }
                        }
                        Err(e) => log::error!("[Downloads] batch task failed: {e}"),
                    }
                }
                _ = refresh.tick() => {
                    refresh_watches(&mut watcher, &mut watched, &cfg, &sender).await;
                }
            }
        }
        Ok(())
    }
}

async fn report(sender: &mpsc::Sender<InterceptEvent>, note: String) {
    let mut evt = InterceptEvent::new(PathBuf::new(), BackendKind::Downloads);
    evt.note = Some(note);
    let _ = sender.send(evt).await;
}

/// Bring the watch set in line with the current users and folders.
async fn refresh_watches(
    watcher: &mut RecommendedWatcher,
    watched: &mut HashMap<PathBuf, DlUser>,
    cfg: &Config,
    sender: &mpsc::Sender<InterceptEvent>,
) {
    let c = cfg.clone();
    let want: HashMap<PathBuf, DlUser> = tokio::task::spawn_blocking(move || {
        let mut m = HashMap::new();
        for u in real_users() {
            for f in folders_for(&u, &c) {
                m.entry(f).or_insert_with(|| u.clone());
            }
        }
        m
    })
    .await
    .unwrap_or_default();

    let gone: Vec<PathBuf> = watched
        .keys()
        .filter(|k| !want.contains_key(*k))
        .cloned()
        .collect();
    for p in gone {
        let _ = watcher.unwatch(&p);
        watched.remove(&p);
        report(
            sender,
            format!("[Downloads] stopped watching {}", p.display()),
        )
        .await;
    }
    for (p, u) in want {
        if watched.contains_key(&p) {
            continue;
        }
        match watcher.watch(&p, RecursiveMode::NonRecursive) {
            Ok(()) => {
                report(sender, format!("[Downloads] watching {}", p.display())).await;
                watched.insert(p, u);
            }
            Err(e) => log::warn!("[Downloads] cannot watch {}: {e}", p.display()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// One batch (blocking)
// ─────────────────────────────────────────────────────────────────────────────

struct Item {
    path: PathBuf,
    user: DlUser,
    name: String,
    sha: String,
}

#[derive(Default)]
struct UserNotices {
    threats: Vec<String>,
    not_scanned: Vec<(String, String)>, // (name, reason)
}

fn process_batch(
    items: Vec<(PathBuf, DlUser)>,
    retried: &HashSet<PathBuf>,
    cfg: &Config,
    mut scanned: Scanned,
) -> BatchResult {
    let allow = AllowList::load();
    let rar_ok = clam::rar_supported();
    let clam = SystemClamBackend::new(cfg.resolve_clamscan(), cfg.resolve_definition_path());
    let mut reports = Vec::new();
    let mut retry = Vec::new();
    let mut notices: Notices = HashMap::new();
    let mut to_scan: Vec<Item> = Vec::new();

    for (path, user) in items {
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        }; // gone again
        if !meta.file_type().is_file() || !is_candidate(&path, &cfg.downloads.extensions) {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let Some(sha) = sha256_bounded(&path) else {
            if std::fs::symlink_metadata(&path).is_ok() {
                not_scanned(
                    &mut notices,
                    &mut reports,
                    &user,
                    &path,
                    &name,
                    "it could not be read".into(),
                    ScanOutcome::Error {
                        message: "unreadable".into(),
                    },
                );
            }
            continue;
        };
        if scanned.contains(&sha) {
            continue;
        }
        let qdir = cfg.quarantine.dir_for(&user.home);
        if quarantine::load_released(&qdir).contains(&sha) {
            reports.push(Report {
                note: format!(
                    "[Downloads] {name} — released by {} earlier, not rescanned",
                    user.name
                ),
                quarantined: false,
            });
            continue;
        }
        if allow.contains(&sha) {
            reports.push(Report {
                note: format!("[Downloads] {name} — on the allow list, not scanned"),
                quarantined: false,
            });
            audit(
                &user,
                Action::Scanned,
                &path,
                Some(ScanOutcome::NotScanned),
                Some("on the allow list"),
            );
            continue;
        }
        if meta.len() > MAX_AUTO_SCAN {
            not_scanned(&mut notices, &mut reports, &user, &path, &name,
                format!("{name} ({}) is too large for automatic scanning. Scan it from the dashboard if you want it checked.", human_size(meta.len())),
                ScanOutcome::NotScanned);
            continue;
        }
        if extension(&name).as_deref() == Some("rar") && !rar_ok {
            not_scanned(&mut notices, &mut reports, &user, &path, &name,
                "RAR archives can't be scanned on this system (no libclamunrar matching the installed ClamAV). It was left in place.".into(),
                ScanOutcome::NotScanned);
            continue;
        }
        to_scan.push(Item {
            path,
            user,
            name,
            sha,
        });
    }

    if !to_scan.is_empty() {
        let paths: Vec<PathBuf> = to_scan.iter().map(|i| i.path.clone()).collect();
        let verdicts = {
            let _slot = scan_slot::acquire(Priority::Background);
            clam.scan_batch(&paths, true)
        };
        let defver = clam
            .get_definition_version()
            .map(|v| v.lines().next().unwrap_or_default().to_string())
            .unwrap_or_default();

        for (item, verdict) in to_scan.into_iter().zip(verdicts) {
            let Item {
                path,
                user,
                name,
                sha,
            } = item;
            match verdict {
                FileVerdict::Clean => {
                    scanned.insert(sha);
                    audit(
                        &user,
                        Action::Scanned,
                        &path,
                        Some(ScanOutcome::Clean),
                        None,
                    );
                    reports.push(Report {
                        note: format!("[Downloads] {name} — clean"),
                        quarantined: false,
                    });
                }
                FileVerdict::Threat(d) => {
                    let qdir = cfg.quarantine.dir_for(&user.home);
                    match quarantine_as_user(&user, &qdir, &path, &d.name, &defver, &sha) {
                        Ok(rec) => {
                            audit(
                                &user,
                                Action::Quarantined,
                                &path,
                                Some(ScanOutcome::Threat {
                                    name: d.name.clone(),
                                }),
                                Some(&rec.quarantine_path.to_string_lossy()),
                            );
                            reports.push(Report {
                                note: format!(
                                    "[Downloads] {name} — THREAT {} — quarantined",
                                    d.name
                                ),
                                quarantined: true,
                            });
                            notices
                                .entry(user.uid)
                                .or_insert_with(|| (user.clone(), UserNotices::default()))
                                .1
                                .threats
                                .push(format!("{name} ({})", d.name));
                        }
                        Err(e) => {
                            let reason = format!("threat {} found, but it could not be moved to quarantine ({e}). Delete it.", d.name);
                            audit(
                                &user,
                                Action::Scanned,
                                &path,
                                Some(ScanOutcome::Threat {
                                    name: d.name.clone(),
                                }),
                                Some(&reason),
                            );
                            reports.push(Report {
                                note: format!(
                                    "[Downloads] {name} — THREAT {} — NOT QUARANTINED: {e}",
                                    d.name
                                ),
                                quarantined: false,
                            });
                            notice::send(Notice {
                                uid: user.uid,
                                urgency: Urgency::Critical,
                                title: "Ghost Sentri: threat not quarantined".into(),
                                body: format!("{name}: {reason}"),
                                action: Some(("Open Ghost Sentri".into(), vec![])),
                            });
                        }
                    }
                }
                FileVerdict::LimitsExceeded => {
                    not_scanned(&mut notices, &mut reports, &user, &path, &name,
                        "it could not be fully scanned (its contents exceed the scan limits). It was left in place.".into(),
                        ScanOutcome::Error { message: "scan limits exceeded".into() });
                }
                FileVerdict::Error(e) => {
                    let again = retried.contains(&path);
                    let reason = if again {
                        format!("it could not be scanned again ({e}). It was left in place.")
                    } else {
                        format!("it could not be scanned ({e}). It was left in place and will be tried again with the next batch.")
                    };
                    not_scanned(
                        &mut notices,
                        &mut reports,
                        &user,
                        &path,
                        &name,
                        reason,
                        ScanOutcome::Error { message: e },
                    );
                    if !again {
                        retry.push((path, user));
                    }
                }
            }
        }
    }

    for (_, (user, n)) in notices {
        if !n.threats.is_empty() {
            notice::send(Notice {
                uid: user.uid,
                urgency: Urgency::Critical,
                title: "Ghost Sentri: threat quarantined".into(),
                body: format!("Moved to quarantine: {}", notice::name_list(&n.threats)),
                action: Some((
                    "Open Quarantine".into(),
                    vec!["--tab".into(), "quarantine".into()],
                )),
            });
        }
        match n.not_scanned.len() {
            0 => {}
            1 => {
                let (name, reason) = &n.not_scanned[0];
                let body = if reason.starts_with(name.as_str()) {
                    reason.clone()
                } else {
                    format!("{name}: {reason}")
                };
                notice::send(Notice {
                    uid: user.uid,
                    urgency: Urgency::Normal,
                    title: "Ghost Sentri: file not scanned".into(),
                    body,
                    action: Some(("Open Ghost Sentri".into(), vec![])),
                });
            }
            _ => {
                let names: Vec<String> = n.not_scanned.iter().map(|(n, _)| n.clone()).collect();
                notice::send(Notice {
                    uid: user.uid,
                    urgency: Urgency::Normal,
                    title: "Ghost Sentri: files not scanned".into(),
                    body: format!(
                        "{} files were left in place unscanned: {}. The reasons are in the dashboard log.",
                        names.len(),
                        notice::name_list(&names)
                    ),
                    action: Some(("Open Ghost Sentri".into(), vec![])),
                });
            }
        }
    }

    BatchResult {
        reports,
        retry,
        scanned,
    }
}

type Notices = HashMap<u32, (DlUser, UserNotices)>;

/// Left in place, not fully scanned: audit line, dashboard line, notice.
fn not_scanned(
    notices: &mut Notices,
    reports: &mut Vec<Report>,
    user: &DlUser,
    path: &Path,
    name: &str,
    reason: String,
    outcome: ScanOutcome,
) {
    audit(user, Action::Scanned, path, Some(outcome), Some(&reason));
    reports.push(Report {
        note: format!("[Downloads] {name} — NOT SCANNED: {reason}"),
        quarantined: false,
    });
    notices
        .entry(user.uid)
        .or_insert_with(|| (user.clone(), UserNotices::default()))
        .1
        .not_scanned
        .push((name.to_string(), reason));
}

fn audit(
    user: &DlUser,
    action: Action,
    path: &Path,
    scan: Option<ScanOutcome>,
    detail: Option<&str>,
) {
    let mut ev = AuditEvent::new(
        user.name.clone(),
        Avenue::Downloads,
        action,
        path.to_string_lossy(),
    );
    if let Some(s) = scan {
        ev = ev.with_scan(s);
    }
    if let Some(d) = detail {
        ev = ev.with_detail(d);
    }
    if let Err(e) = events::append(&ev) {
        log::warn!("[Downloads] audit write failed: {e}");
    }
}

fn daemon_bin() -> PathBuf {
    if Path::new(DAEMON_BIN).exists() {
        PathBuf::from(DAEMON_BIN)
    } else {
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from(DAEMON_BIN))
    }
}

/// Run a quarantine operation as the user (never root).
fn run_as_user(user: &DlUser, args: &[&std::ffi::OsStr]) -> std::result::Result<Vec<u8>, String> {
    let out = Command::new(daemon_bin())
        .args(args)
        .uid(user.uid)
        .gid(user.gid)
        .env_clear()
        .env("HOME", &user.home)
        .env("PATH", SAFE_PATH)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn quarantine_as_user(
    user: &DlUser,
    qdir: &Path,
    src: &Path,
    threat: &str,
    defver: &str,
    sha: &str,
) -> std::result::Result<QuarantineRecord, String> {
    let stdout = run_as_user(
        user,
        &[
            "--quarantine-move".as_ref(),
            qdir.as_os_str(),
            src.as_os_str(),
            threat.as_ref(),
            defver.as_ref(),
            sha.as_ref(),
        ],
    )?;
    serde_json::from_slice(&stdout).map_err(|e| format!("bad reply from quarantine helper: {e}"))
}

/// Move one user's quarantine to a new location (Settings change), as that user.
pub fn relocate_as_user(user: &DlUser, old: &Path, new: &Path) -> std::result::Result<(), String> {
    run_as_user(
        user,
        &[
            "--quarantine-relocate".as_ref(),
            old.as_os_str(),
            new.as_os_str(),
        ],
    )
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_defs_and_passwd() {
        let defs = "# c\nUID_MIN\t\t\t 1000\nUID_MAX\t\t\t60000\nGID_MIN 1000\n";
        assert_eq!(parse_login_defs(defs), (1000, 60000));
        let pw = "root:x:0:0:root:/root:/bin/bash\n\
                  rjv:x:1000:1000:R,,,:/home/rjv:/bin/bash\n\
                  svc:x:1001:1001::/home/svc:/usr/sbin/nologin\n\
                  off:x:1002:1002::/home/off:/bin/false\n\
                  nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
                  odd:x:1003:1003::/srv/odd:/bin/sh\n";
        let u = parse_passwd(pw, 1000, 60000);
        assert_eq!(u.len(), 1);
        assert_eq!(u[0].name, "rjv");
        assert_eq!(u[0].home, PathBuf::from("/home/rjv"));
    }

    #[test]
    fn user_dirs_parse() {
        let home = Path::new("/home/u");
        assert_eq!(
            parse_user_dirs("XDG_DOWNLOAD_DIR=\"$HOME/Downloads\"\n", home),
            Some(home.join("Downloads"))
        );
        assert_eq!(
            parse_user_dirs("XDG_DOWNLOAD_DIR=\"$HOME/\"\n", home),
            Some(home.join(""))
        );
        assert_eq!(
            parse_user_dirs("XDG_DOWNLOAD_DIR=\"/etc\"\n", home),
            Some(PathBuf::from("/etc"))
        );
        assert_eq!(
            parse_user_dirs("XDG_MUSIC_DIR=\"$HOME/Music\"\n", home),
            None
        );
    }

    #[test]
    fn file_selection() {
        let exts = ghost_sentri_core::config::default_download_extensions();
        assert!(ext_listed("setup.EXE", &exts));
        assert!(ext_listed("app.tar.zst", &exts));
        assert!(ext_listed("x.AppImage", &exts));
        assert!(ext_listed("a.rar", &exts));
        assert!(!ext_listed("photo.jpg", &exts));
        assert!(!ext_listed("noext", &exts));
        assert!(magic_is_program(b"\x7fELF"));
        assert!(magic_is_program(b"MZ\x90\x00"));
        assert!(magic_is_program(b"#!/b"));
        assert!(!magic_is_program(b"\x89PNG"));
        for t in [
            "a.deb.part",
            "b.crdownload",
            "c.download",
            "d.tmp",
            "e.partial",
            "f.!qB",
            ".hidden.sh",
        ] {
            assert!(is_temp_or_hidden(t), "{t}");
        }
        assert!(!is_temp_or_hidden("ok.deb"));
    }

    #[test]
    fn scanned_set_is_bounded() {
        let mut s = Scanned::default();
        for i in 0..SCANNED_CAP + 10 {
            s.insert(format!("{i}"));
        }
        assert_eq!(s.set.len(), SCANNED_CAP);
        assert!(!s.contains("0"));
        assert!(s.contains(&format!("{}", SCANNED_CAP + 9)));
    }

    #[test]
    fn folders_stay_in_home() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/test-scratch")
            .join(format!("dl-folders-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("home/u");
        std::fs::create_dir_all(home.join("Downloads")).unwrap();
        std::fs::create_dir_all(home.join(".config")).unwrap();
        std::fs::create_dir_all(home.join("Inbox")).unwrap();
        std::fs::create_dir_all(root.join("outside")).unwrap();
        std::fs::write(
            home.join(".config/user-dirs.dirs"),
            "XDG_DOWNLOAD_DIR=\"$HOME/Inbox\"\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(root.join("outside"), home.join("escape")).unwrap();
        let user = DlUser {
            uid: 1,
            gid: 1,
            name: "u".into(),
            home: home.clone(),
        };
        let mut cfg = Config::default();
        cfg.downloads.folders = vec![
            "Downloads".into(),
            "escape".into(),
            "../outside".into(),
            ".quarantine".into(),
        ];
        std::fs::create_dir_all(home.join(".quarantine")).unwrap();
        let f = folders_for(&user, &cfg);
        let canon = std::fs::canonicalize(&home).unwrap();
        assert_eq!(f, vec![canon.join("Inbox"), canon.join("Downloads")]);
        let _ = std::fs::remove_dir_all(&root);
    }
}
