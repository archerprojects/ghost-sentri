// core/src/clam/mod.rs — v1.1.0 — Thursday 12 November 2026
// Scan engine: system `clamscan` subprocess (no C FFI).
// Definition status: filesystem stat of daily.cvd/.cld mtime — no network calls.
// Definition updates: the root system daemon runs `freshclam` directly after a
// per-request polkit authorisation (no pkexec) — user-initiated only, never silent.
// Staleness is checked daily by the resident daemon (in-process interval, no timer).
//
// `.deb` scans route through a size-capped loopback image (the decompression-bomb
// fence, see LoopMount); `sweep_stale_scratch()` closes any fence debris a crash
// leaked and is called once at daemon start.
//
// `scan_batch()` scans many files in ONE clamscan run (one database load) and
// attributes every hit to its file; the Downloads watch uses it. Every FOUND line
// is collected — a scan never stops at the first hit. `ScanLock` keeps clamscan
// runs from different processes (daemon, install worker) from overlapping.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanResult {
    Clean,
    Threat(ThreatDetail),
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetail {
    pub name:               String,
    pub classification:     ThreatClassification,
    pub database:           String,
    pub definition_version: String,
    pub plain_english:      String,
}

impl ThreatDetail {
    pub fn from_clamscan_line(line: &str, definition_version: &str, database: &str) -> Option<Self> {
        let parts: Vec<&str> = line.splitn(2, ": ").collect();
        if parts.len() != 2 { return None; }
        let threat_part = parts[1].trim();
        if !threat_part.ends_with(" FOUND") { return None; }
        let name           = threat_part.trim_end_matches(" FOUND").to_string();
        let classification = ThreatClassification::from_name(&name);
        let plain_english  = classification.plain_english(&name);
        Some(ThreatDetail {
            name,
            classification,
            database: database.to_string(),
            definition_version: definition_version.to_string(),
            plain_english,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatClassification {
    Trojan,
    Ransomware,
    Adware,
    Spyware,
    Rootkit,
    Worm,
    Virus,
    PUA,
    Phishing,
    Backdoor,
    Dropper,
    Unknown,
}

impl ThreatClassification {
    pub fn from_name(name: &str) -> Self {
        let u = name.to_uppercase();
        if      u.contains("RANSOM")                           { Self::Ransomware }
        else if u.contains("TROJAN") || u.contains("TROJ")    { Self::Trojan }
        else if u.contains("ADWARE") || u.contains("ADW")     { Self::Adware }
        else if u.contains("SPYWARE") || u.contains("SPY")    { Self::Spyware }
        else if u.contains("ROOTKIT")                         { Self::Rootkit }
        else if u.contains("WORM")                            { Self::Worm }
        else if u.contains("VIRUS") || u.contains("VIR")      { Self::Virus }
        else if u.contains("PUA") || u.contains("PUP")        { Self::PUA }
        else if u.contains("PHISH")                           { Self::Phishing }
        else if u.contains("BACKDOOR")                        { Self::Backdoor }
        else if u.contains("DROPPER") || u.contains("DROP")   { Self::Dropper }
        else                                                   { Self::Unknown }
    }

    pub fn display_name(&self) -> &str {
        match self {
            Self::Trojan     => "Trojan",
            Self::Ransomware => "Ransomware",
            Self::Adware     => "Adware",
            Self::Spyware    => "Spyware",
            Self::Rootkit    => "Rootkit",
            Self::Worm       => "Worm",
            Self::Virus      => "Virus",
            Self::PUA        => "Potentially Unwanted Application",
            Self::Phishing   => "Phishing",
            Self::Backdoor   => "Backdoor",
            Self::Dropper    => "Dropper",
            Self::Unknown    => "Malicious Code",
        }
    }

    pub fn plain_english(&self, name: &str) -> String {
        match self {
            Self::Trojan => format!(
                "This file contains a Trojan ({name}). Trojans disguise themselves as legitimate \
                 software while secretly performing malicious actions such as stealing data or \
                 opening backdoors for unauthorized remote access."
            ),
            Self::Ransomware => format!(
                "This file contains Ransomware ({name}). Ransomware encrypts your files and demands \
                 payment for the decryption key. Installing this could result in permanent data loss."
            ),
            Self::Adware => format!(
                "This file contains Adware ({name}). Adware displays unwanted advertisements and \
                 may track your browsing activity without consent."
            ),
            Self::Spyware => format!(
                "This file contains Spyware ({name}). Spyware covertly monitors your activity, \
                 collects personal information, and transmits it to third parties."
            ),
            Self::Rootkit => format!(
                "This file contains a Rootkit ({name}). Rootkits hide malicious processes from \
                 the operating system and grant persistent unauthorized system access."
            ),
            Self::Worm => format!(
                "This file contains a Worm ({name}). Worms self-replicate and spread across \
                 networks, consuming resources and potentially delivering additional malicious payloads."
            ),
            Self::Virus => format!(
                "This file contains a Virus ({name}). Viruses attach to legitimate programs and \
                 spread when those programs execute, potentially corrupting files and system components."
            ),
            Self::PUA => format!(
                "This file is flagged as a Potentially Unwanted Application ({name}). While not \
                 necessarily malicious, it may install additional software, modify browser settings, \
                 or behave in ways you have not consented to."
            ),
            Self::Phishing => format!(
                "This file is associated with a Phishing attack ({name}). It may attempt to steal \
                 credentials or personal information by impersonating legitimate services."
            ),
            Self::Backdoor => format!(
                "This file contains a Backdoor ({name}). Backdoors create hidden access points \
                 that allow unauthorized remote control of your system."
            ),
            Self::Dropper => format!(
                "This file is a Dropper ({name}). Droppers install additional malware onto your \
                 system after execution, often concealing the true payload until it is too late."
            ),
            Self::Unknown => format!(
                "This file contains malicious code ({name}) matching a known signature in \
                 ClamAV's virus database. The exact nature of the threat is unclear but the \
                 match indicates potentially harmful behaviour."
            ),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// System ClamAV backend — subprocess only, no C FFI
// ─────────────────────────────────────────────────────────────────────────────

pub struct SystemClamBackend {
    clamscan_path:   PathBuf,
    /// Reserved: clamscan auto-discovers its database dir, so this is carried for
    /// callers that pass an explicit --database path in a later revision.
    #[allow(dead_code)]
    definition_path: PathBuf,
}

impl SystemClamBackend {
    pub fn new(clamscan_path: PathBuf, definition_path: PathBuf) -> Self {
        Self { clamscan_path, definition_path }
    }

    pub fn is_available(&self) -> bool {
        self.clamscan_path.exists()
    }

    pub fn scan_file(&self, path: &Path) -> ScanResult {
        // A .deb stores its payload as a compressed tar member (data.tar.zst on
        // current dpkg). clamscan does NOT descend into the .deb's `ar`/zstd
        // wrapper, so scanning the raw file reports clean even when the payload
        // is infected. Scan the DECOMPRESSED streams instead — dpkg-deb handles
        // gz/xz/zst — covering both the data payload and the maintainer scripts.
        if is_deb(path) {
            return self.scan_deb(path);
        }

        let output = Command::new(&self.clamscan_path)
            .args(["--no-summary", "--infected"])
            .arg(path)
            .output();

        match output {
            Err(e) => ScanResult::Error(format!("clamscan failed to launch: {}", e)),
            Ok(out) => self.parse_scan(out.status.code(), &out.stdout, &out.stderr),
        }
    }

    /// Scan a `.deb`.
    ///
    /// clamscan reloads the entire signature database on every invocation, so the
    /// number of clamscan calls — not the package size — is the cost. The fast
    /// path decompresses both members (payload `--fsys-tarfile` + control
    /// `--ctrl-tarfile`, the maintainer scripts) to plain tars in one temp dir and
    /// runs a SINGLE recursive clamscan over them: one DB load instead of two.
    /// dpkg-deb performs the decompression, so this never depends on clamscan's
    /// own zstd/xz support (which the target's clamav may predate).
    ///
    /// The fast path materialises the uncompressed payload on disk, so it is only
    /// taken when the temp filesystem has headroom (predicted from the package's
    /// `Installed-Size`, checked against `df`, with a safety margin). When space is
    /// tight, unpredictable, or an extract write fails mid-stream, it falls back to
    /// the low-disk streaming scan (two DB loads, near-zero disk — slower but
    /// safe). A scan that cannot complete at all surfaces as `Error`, which the
    /// caller treats as a hard block — never a pass.
    fn scan_deb(&self, path: &Path) -> ScanResult {
        let base = scan_tempdir_base();
        let free = fs_available_bytes(&base);
        let need = deb_installed_bytes(path);
        let cap  = loop_cap(free);

        // `disk_pressure` shapes the user-facing message if the scan ultimately
        // can't run: true means the capped scratch was unavailable or filled.
        let mut disk_pressure = false;

        match cap {
            // A capped image is available and the package's HONEST declared size
            // plausibly fits it. A lying-small bomb also passes this test — and is
            // then physically contained by the image, which is the whole point.
            Some(cap) if need.map_or(true, |n| n <= cap) => {
                match self.scan_deb_extracted(path, &base, cap) {
                    Ok(ScanResult::Error(e)) => return ScanResult::Error(unscannable_msg(path, false, &e)),
                    Ok(other) => return other,        // scanned in a single DB load
                    Err(()) => disk_pressure = true,  // couldn't provision / image ENOSPC → stream, partial wiped
                }
            }
            // Honest package larger than the cap → skip the wasted partial extract
            // and stream directly (no disk pressure — streaming is the right tool).
            Some(_) => {}
            // No capped image at all (free space unknown or below the floor).
            None => disk_pressure = true,
        }

        match self.scan_deb_streamed(path) {
            // A contained bomb faults the capped image (disk_pressure=true), then
            // trips the streaming scan fence and returns the limits-exceeded error.
            // Its own wording is the honest one: the cap ceilings at LOOP_CAP_CEILING,
            // so "free space and retry" is a lie — freeing space never lifts the fence.
            // The streaming error text wins whenever it carried the limits trip; only
            // a genuine provisioning-for-space failure keeps the disk-pressure wording.
            ScanResult::Error(e) => {
                let space = disk_pressure && !e.contains("exceeded scan limits");
                ScanResult::Error(unscannable_msg(path, space, &e))
            }
            other => other,
        }
    }

    /// Fast path: extract the WHOLE package tree (payload + control scripts under
    /// `DEBIAN/`) into a SIZE-CAPPED loopback image and run ONE recursive clamscan
    /// over it. Scanning the extracted members as individual files — rather than
    /// handing clamscan the `data.tar` as one container — means the per-container
    /// `--max-scansize` never aggregates across a package of many small files (the
    /// common false-skip on large multi-file packages). dpkg-deb does the
    /// decompression, so this never depends on clamscan's own compression support.
    ///
    /// The capped image is the decompression-bomb disk fence: extraction (and
    /// clamscan's own descent temps, pinned to the same dir) can write at most
    /// `cap` bytes before the image ENOSPC-es. That fault returns `Err(())` exactly
    /// like any other extract failure, so a bomb routes to the streaming fallback
    /// while the host root filesystem never fills. Provisioning failure (no mkfs,
    /// no mount privilege, loop devices exhausted) also returns `Err(())` → stream.
    fn scan_deb_extracted(&self, path: &Path, base: &Path, cap: u64) -> Result<ScanResult, ()> {
        let mount = LoopMount::create(base, cap).ok_or(())?; // umount + rm on drop
        let dir = mount.path();

        let extracted = Command::new("dpkg-deb")
            .arg("--raw-extract")
            .arg(path)
            .arg(dir)
            .stderr(Stdio::null())
            .status();
        match extracted {
            Ok(s) if s.success() => {}
            _ => return Err(()), // extract failed (incl. image ENOSPC) → fall back, mount torn down on drop
        }

        // Pin clamscan's own descent temps to the same capped image so they, too,
        // fall inside the fence we already enforced.
        let tempdir_arg = format!("--tempdir={}", dir.display());
        let out = Command::new(&self.clamscan_path)
            .args(["--recursive", "--no-summary", "--infected"])
            .args(SCAN_LIMITS)
            .arg(&tempdir_arg)
            .arg(dir)
            .output();

        Ok(match out {
            Err(e) => ScanResult::Error(format!("clamscan failed to launch: {}", e)),
            Ok(o) => self.parse_scan(o.status.code(), &o.stdout, &o.stderr),
        })
    }

    /// Low-disk fallback: stream each decompressed member into `clamscan -`
    /// separately. Two DB loads, but nothing larger than clamscan's own transient
    /// descent temps ever lands on disk. A threat in either member is a threat; an
    /// error is surfaced only if nothing came back clean-or-infected.
    fn scan_deb_streamed(&self, path: &Path) -> ScanResult {
        let mut last_error: Option<ScanResult> = None;
        for member in ["--fsys-tarfile", "--ctrl-tarfile"] {
            match self.scan_dpkg_stream(path, member) {
                ScanResult::Threat(d) => return ScanResult::Threat(d),
                ScanResult::Clean => {}
                err => last_error = Some(err),
            }
        }
        last_error.unwrap_or(ScanResult::Clean)
    }

    /// `dpkg-deb <member> <deb> | clamscan --no-summary --infected -`
    fn scan_dpkg_stream(&self, path: &Path, member: &str) -> ScanResult {
        let mut dpkg = match Command::new("dpkg-deb")
            .arg(member)
            .arg(path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => return ScanResult::Error(format!("dpkg-deb failed to launch: {}", e)),
        };
        let stdout = match dpkg.stdout.take() {
            Some(s) => s,
            None => return ScanResult::Error("dpkg-deb produced no output stream".to_string()),
        };

        let scan = Command::new(&self.clamscan_path)
            .args(["--no-summary", "--infected", "-"])
            .args(SCAN_LIMITS)
            .stdin(Stdio::from(stdout))
            .output();

        let _ = dpkg.wait();

        match scan {
            Err(e) => ScanResult::Error(format!("clamscan failed to launch: {}", e)),
            Ok(out) => self.parse_scan(out.status.code(), &out.stdout, &out.stderr),
        }
    }

    /// Map a clamscan exit code + output to a ScanResult (shared by file and
    /// stream scans). 0 = clean, 1 = infected, 2 = error.
    fn parse_scan(&self, code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> ScanResult {
        let def_ver = self.get_definition_version().unwrap_or_default();
        parse_single(code, &String::from_utf8_lossy(stdout), &String::from_utf8_lossy(stderr), &def_ver)
    }

    /// Scan many regular files in ONE clamscan run and return one verdict per
    /// file, in the same order. `low_priority` runs clamscan under `nice -n 10`
    /// and `ionice -c2 -n7` (lowest best-effort, never the idle class). clamscan's
    /// own unpacking goes to a private dir under /var/tmp/ghost-sentri, removed
    /// afterwards.
    pub fn scan_batch(&self, files: &[PathBuf], low_priority: bool) -> Vec<FileVerdict> {
        if files.is_empty() {
            return vec![];
        }
        let base = scan_tempdir_base();
        let tmp = make_scan_dir(&base);
        let mut cmd = if low_priority {
            let mut c = Command::new("nice");
            c.args(["-n", "10", "ionice", "-c2", "-n7"]).arg(&self.clamscan_path);
            c
        } else {
            Command::new(&self.clamscan_path)
        };
        cmd.args(["--no-summary", "--infected"]).args(SCAN_LIMITS);
        if let Some(t) = &tmp {
            cmd.arg(format!("--tempdir={}", t.display()));
        }
        cmd.arg("--").args(files);
        let out = cmd.output();
        if let Some(t) = &tmp {
            let _ = std::fs::remove_dir_all(t);
        }
        let def_ver = self.get_definition_version().unwrap_or_default();
        match out {
            Err(e) => files
                .iter()
                .map(|_| FileVerdict::Error(format!("clamscan failed to launch: {e}")))
                .collect(),
            Ok(o) => parse_batch(
                files,
                o.status.code(),
                &String::from_utf8_lossy(&o.stdout),
                &String::from_utf8_lossy(&o.stderr),
                &def_ver,
            ),
        }
    }

    pub fn get_definition_version(&self) -> Result<String> {
        let out = Command::new(&self.clamscan_path)
            .arg("--version")
            .output()
            .context("could not run clamscan --version")?;
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Output parsing — every FOUND line counts
// ─────────────────────────────────────────────────────────────────────────────

const LIMITS_SIG: &str = "Heuristics.Limits.Exceeded";

fn limits_msg() -> String {
    "a package member exceeded scan limits (too large or too deeply nested to fully scan)".to_string()
}

/// One file's verdict from a batch scan.
#[derive(Debug, Clone)]
pub enum FileVerdict {
    Clean,
    Threat(ThreatDetail),
    /// A scan fence tripped (`Heuristics.Limits.Exceeded`): not malware, but not
    /// fully scanned either.
    LimitsExceeded,
    Error(String),
}

/// Single-target parse. A real signature anywhere in the output wins over a
/// tripped limit; a tripped limit alone is an error (fail closed, honest wording).
pub fn parse_single(code: Option<i32>, stdout: &str, stderr: &str, def_ver: &str) -> ScanResult {
    match code {
        Some(0) => ScanResult::Clean,
        Some(1) => {
            let mut limits = false;
            for line in stdout.lines() {
                if !line.ends_with("FOUND") {
                    continue;
                }
                if line.contains(LIMITS_SIG) {
                    limits = true;
                    continue;
                }
                if let Some(detail) = ThreatDetail::from_clamscan_line(line, def_ver, "daily.cvd") {
                    return ScanResult::Threat(detail);
                }
            }
            if limits {
                return ScanResult::Error(limits_msg());
            }
            ScanResult::Threat(ThreatDetail {
                name:               "Unknown".to_string(),
                classification:     ThreatClassification::Unknown,
                database:           "unknown".to_string(),
                definition_version: def_ver.to_string(),
                plain_english:      stdout.to_string(),
            })
        }
        Some(2) => ScanResult::Error(format!(
            "clamscan error: {}",
            if !stderr.is_empty() { stderr } else { stdout }
        )),
        _ => ScanResult::Error("clamscan returned unexpected exit code".to_string()),
    }
}

/// Which of `files` a clamscan output line is about: the longest `"<path>: "`
/// prefix (a path may itself contain ": ").
fn attribute<'a>(files: &[PathBuf], line: &'a str) -> Option<(usize, &'a str)> {
    let mut best: Option<(usize, usize)> = None;
    for (i, f) in files.iter().enumerate() {
        let prefix = format!("{}: ", f.display());
        if line.starts_with(&prefix) && best.is_none_or(|(_, l)| prefix.len() > l) {
            best = Some((i, prefix.len()));
        }
    }
    best.map(|(i, l)| (i, &line[l..]))
}

/// Batch parse: one verdict per file, same order as `files`.
pub fn parse_batch(
    files: &[PathBuf],
    code: Option<i32>,
    stdout: &str,
    stderr: &str,
    def_ver: &str,
) -> Vec<FileVerdict> {
    let mut v: Vec<Option<FileVerdict>> = vec![None; files.len()];
    let mut any_attributed_error = false;

    for line in stdout.lines() {
        let Some((i, rest)) = attribute(files, line) else { continue };
        let rest = rest.trim();
        if let Some(name) = rest.strip_suffix(" FOUND") {
            let name = name.trim();
            if name.contains(LIMITS_SIG) {
                if !matches!(v[i], Some(FileVerdict::Threat(_))) {
                    v[i] = Some(FileVerdict::LimitsExceeded);
                }
            } else if !matches!(v[i], Some(FileVerdict::Threat(_))) {
                let classification = ThreatClassification::from_name(name);
                v[i] = Some(FileVerdict::Threat(ThreatDetail {
                    name:               name.to_string(),
                    plain_english:      classification.plain_english(name),
                    classification,
                    database:           "daily.cvd".to_string(),
                    definition_version: def_ver.to_string(),
                }));
            }
        } else if v[i].is_none() {
            v[i] = Some(FileVerdict::Error(rest.trim_end_matches(" ERROR").to_string()));
            any_attributed_error = true;
        }
    }
    for line in stderr.lines() {
        let l = line.strip_prefix("WARNING: ").unwrap_or(line);
        if let Some((i, rest)) = attribute(files, l) {
            if v[i].is_none() {
                v[i] = Some(FileVerdict::Error(rest.trim().to_string()));
                any_attributed_error = true;
            }
        }
    }

    // Files with no line of their own: clean on a normal exit, or when exit 2 is
    // explained by per-file errors. Otherwise the run itself failed.
    let run_ok = matches!(code, Some(0) | Some(1)) || (code == Some(2) && any_attributed_error);
    let run_err = || {
        let msg = stderr.lines().find(|l| !l.trim().is_empty()).unwrap_or("clamscan did not complete");
        FileVerdict::Error(format!("clamscan error: {msg}"))
    };
    v.into_iter()
        .map(|x| x.unwrap_or_else(|| if run_ok { FileVerdict::Clean } else { run_err() }))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// RAR support — only when libclamunrar matches the installed libclamav
// ─────────────────────────────────────────────────────────────────────────────

/// True when RAR archives can be scanned: libclamunrarN is installed at the SAME
/// upstream version as libclamavN. A mismatched or missing library means a .rar
/// gets the "not scanned" notice instead.
pub fn rar_supported() -> bool {
    let out = Command::new("dpkg-query")
        .args(["-W", "-f=${Package} ${Version} ${db:Status-Abbrev}\\n", "libclamav*", "libclamunrar*"])
        .stderr(Stdio::null())
        .output();
    match out {
        Ok(o) => rar_supported_from(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => false,
    }
}

/// Upstream part of a Debian version: no epoch, no revision, no +suffix.
fn upstream(v: &str) -> &str {
    let v = v.split_once(':').map(|(_, r)| r).unwrap_or(v);
    let v = v.rsplit_once('-').map(|(l, _)| l).unwrap_or(v);
    v.split('+').next().unwrap_or(v).split('~').next().unwrap_or(v)
}

pub fn rar_supported_from(dpkg_query: &str) -> bool {
    let mut av: Vec<(String, String)> = Vec::new(); // (soname digits, upstream)
    let mut unrar: Vec<(String, String)> = Vec::new();
    for line in dpkg_query.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 || !f[2].starts_with("ii") {
            continue;
        }
        let (pkg, ver) = (f[0], f[1]);
        let pkg = pkg.split(':').next().unwrap_or(pkg);
        // Debian's 64-bit time_t transition renames libfooN to libfooNt64.
        let pkg = pkg.strip_suffix("t64").unwrap_or(pkg);
        if let Some(n) = pkg.strip_prefix("libclamunrar") {
            if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) {
                unrar.push((n.to_string(), upstream(ver).to_string()));
            }
        } else if let Some(n) = pkg.strip_prefix("libclamav") {
            if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) {
                av.push((n.to_string(), upstream(ver).to_string()));
            }
        }
    }
    av.iter().any(|a| unrar.iter().any(|u| u == a))
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-process scan lock
// ─────────────────────────────────────────────────────────────────────────────

const SCAN_LOCK_PATH: &str = "/run/ghost-sentri/scan.lock";

/// Held while one clamscan run is in progress. Dropping it releases the lock.
/// If the lock file cannot be opened (no runtime dir), scanning is not held up.
pub struct ScanLock {
    _file: Option<std::fs::File>,
}

/// Block until no other Ghost Sentri process is running clamscan.
pub fn acquire_scan_lock() -> ScanLock {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(SCAN_LOCK_PATH)
        .ok()
        .and_then(|f| f.lock().ok().map(|_| f));
    ScanLock { _file: file }
}

// ─────────────────────────────────────────────────────────────────────────────
// Definition status — filesystem stat only, no network
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefinitionStatus {
    pub version_string: String,
    pub last_updated:   Option<DateTime<Utc>>,
    pub age_days:       f64,
    pub is_stale:       bool,
}

impl DefinitionStatus {
    pub fn display_age(&self) -> String {
        if self.age_days < 1.0      { "Updated today".to_string() }
        else if self.age_days < 2.0 { "Updated yesterday".to_string() }
        else                        { format!("{:.0} days ago", self.age_days) }
    }
}

/// Stat daily.cvd (or daily.cld fallback) mtime — no network, no subprocess.
pub fn check_definition_status(
    definition_path:      &PathBuf,
    stale_threshold_days: u64,
    version_string:       String,
) -> DefinitionStatus {
    let daily    = definition_path.join("daily.cvd");
    let fallback = definition_path.join("daily.cld");
    let mtime = [&daily, &fallback]
        .iter()
        .filter_map(|p| p.metadata().and_then(|m| m.modified()).ok())
        .max();
    let (last_updated, age_days) = match mtime {
        Some(t) => {
            let age = SystemTime::now().duration_since(t)
                .map(|d| d.as_secs_f64() / 86400.0)
                .unwrap_or(f64::MAX);
            (Some(DateTime::<Utc>::from(t)), age)
        }
        None => (None, f64::MAX),
    };
    DefinitionStatus {
        version_string,
        last_updated,
        age_days,
        is_stale: age_days > stale_threshold_days as f64,
    }
}

/// True if `path` looks like a Debian package by extension.
fn is_deb(path: &Path) -> bool {
    path.extension().map(|e| e.eq_ignore_ascii_case("deb")).unwrap_or(false)
}

// ─────────────────────────────────────────────────────────────────────────────
// Single-scan temp-extract support (footprint: transient only — write, scan, rm)
// ─────────────────────────────────────────────────────────────────────────────

/// Hard ceiling on the per-scan capped scratch filesystem. The fast path extracts
/// the package tree into a loopback-backed ext4 image of at most this size, so a
/// decompression bomb — a `.deb` that declares a small `Installed-Size` but expands
/// to tens of GB — faults against OUR boundary, not the host root filesystem. The
/// bomb fills at most this many bytes of transient, reclaimed scratch instead of
/// driving the real disk to zero free and ENOSPC-ing every other process.
const LOOP_CAP_CEILING: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

/// Below this, a capped image is not worth provisioning — fall straight to the
/// streaming (no-disk) scan instead.
const LOOP_FLOOR: u64 = 256 * 1024 * 1024; // 256 MiB

/// Size the capped scratch image: at most the ceiling, and never more than HALF
/// the real free space on the backing store. The image is sparse and grows on the
/// host disk as it fills, so keeping it under half of free guarantees the image
/// ENOSPC-es before the host does — the bomb hits our fence first on any disk.
/// `None` when free space is unknown or below the floor; the caller then streams.
fn loop_cap(free: Option<u64>) -> Option<u64> {
    let cap = (free? / 2).min(LOOP_CAP_CEILING);
    if cap < LOOP_FLOOR { None } else { Some(cap) }
}

/// Resource fences applied to every `.deb` install scan. `--max-filesize` is the
/// per-FILE ceiling (one honest large binary); `--max-scansize`/`--max-recursion`/
/// `--max-scantime` are the container bomb guards (a small package that expands
/// or nests pathologically). `--alert-exceeds-max=yes` is load-bearing: without
/// it a tripped fence returns a SILENT clean pass — with it, the overage surfaces
/// as `Heuristics.Limits.Exceeded`, which we route to fail-closed `unscannable`.
/// Sized for real packages: Firefox/LibreOffice/Blender's largest single files
/// sit ~150 MB, well under the 512 MB per-file ceiling.
const SCAN_LIMITS: [&str; 5] = [
    "--max-filesize=512M",
    "--max-scansize=1024M",
    "--max-recursion=17",
    "--max-scantime=180000", // ms (3 min) — headroom for big legit packages
    "--alert-exceeds-max=yes",
];

/// Where the fast path materialises decompressed members. `/var/tmp` is persistent
/// real storage on Debian/Mint (not a tmpfs like many `/tmp` mounts), so a large
/// payload does not compete with the in-RAM signature DB on low-memory targets.
fn scan_tempdir_base() -> PathBuf {
    PathBuf::from("/var/tmp/ghost-sentri")
}

/// Predicted on-disk cost of extracting the payload, read from the package's
/// `Installed-Size` control field (KiB) — cheap, no payload touch. `None` if the
/// field is absent/unparseable, which forces the safe streaming fallback.
fn deb_installed_bytes(path: &Path) -> Option<u64> {
    let out = Command::new("dpkg-deb")
        .arg("--field").arg(path).arg("Installed-Size")
        .output().ok()?;
    if !out.status.success() { return None; }
    let kib: u64 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
    Some(kib.saturating_mul(1024))
}

/// Bytes available on the filesystem backing `dir`, via `df` (coreutils — no new
/// dependency). The base dir is created first so `df` resolves the right mount.
fn fs_available_bytes(dir: &Path) -> Option<u64> {
    let _ = std::fs::create_dir_all(dir);
    let out = Command::new("df")
        .arg("-B1").arg("--output=avail").arg(dir)
        .output().ok()?;
    if !out.status.success() { return None; }
    let s = String::from_utf8_lossy(&out.stdout);
    s.lines().nth(1)?.trim().parse().ok()
}

/// Create a private (0700) per-scan temp dir under `base`. Root-only so the
/// extracted payload is never world-readable while it briefly exists.
fn make_scan_dir(base: &Path) -> Option<PathBuf> {
    std::fs::create_dir_all(base).ok()?;
    let _ = std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o700));
    let out = Command::new("mktemp")
        .arg("-d")
        .arg(format!("--tmpdir={}", base.display()))
        .arg("gsscan.XXXXXX")
        .output().ok()?;
    if !out.status.success() { return None; }
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if p.is_empty() { None } else { Some(PathBuf::from(p)) }
}

/// User-facing reason for a `.deb` that could not be scanned. Disk pressure gets
/// the actionable message; anything else carries the underlying error.
fn unscannable_msg(path: &Path, disk_pressure: bool, err: &str) -> String {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("package");
    if disk_pressure {
        format!("could not scan {name} — insufficient disk; install blocked, free space and retry")
    } else {
        format!("could not scan {name} — install blocked ({err})")
    }
}

/// A per-scan, size-capped scratch filesystem: a sparse loopback-backed ext4
/// image mounted `nosuid,nodev,noexec` under the scan base. It exists only for the
/// duration of one `.deb` scan — created, used, then unmounted and deleted on drop
/// (matching the engine's transient-footprint rule: nothing is reserved between
/// installs). The cap is the decompression-bomb fence: extraction and clamscan's
/// descent temps fault at `cap` against THIS image rather than the host root fs.
struct LoopMount {
    image:      PathBuf,
    mountpoint: PathBuf,
    mounted:    bool,
}

impl LoopMount {
    /// Provision a `cap`-byte capped image and mount it. Returns `None` on any
    /// provisioning failure (the caller then streams) — and never leaves a partial
    /// mount or stray image behind, because a failed return drops `self`, whose
    /// `Drop` unmounts (if mounted) and removes both the mountpoint and the image.
    fn create(base: &Path, cap: u64) -> Option<Self> {
        std::fs::create_dir_all(base).ok()?;
        let _ = std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o700));

        // Unique backing image under the (root-only 0700) base.
        let image = {
            let out = Command::new("mktemp")
                .arg(format!("--tmpdir={}", base.display()))
                .arg("--suffix=.img")
                .arg("gsloop.XXXXXX")
                .output().ok()?;
            if !out.status.success() { return None; }
            let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if p.is_empty() { return None; }
            PathBuf::from(p)
        };
        let mut m = LoopMount { image: image.clone(), mountpoint: PathBuf::new(), mounted: false };

        // Sparse-size the image to the cap (no real bytes until written), lay down a
        // journalless ext4 (transient — no journal, no reserved blocks, lazy inode
        // table for a fast mkfs), then mount it. Any step failing tears the whole
        // thing down via the Drop that runs on the early return.
        let cap_s = cap.to_string();
        let img   = image.to_string_lossy().into_owned();
        if !run_ok("truncate", &["-s", cap_s.as_str(), img.as_str()]) { return None; }
        if !run_ok("mkfs.ext4", &["-q", "-F", "-m0", "-O", "^has_journal",
                                  "-E", "lazy_itable_init=1", img.as_str()]) { return None; }

        let mountpoint = make_scan_dir(base)?;
        m.mountpoint = mountpoint.clone();
        let mp = mountpoint.to_string_lossy().into_owned();
        if !run_ok("mount", &["-o", "loop,nosuid,nodev,noexec", img.as_str(), mp.as_str()]) {
            return None;
        }
        m.mounted = true;

        // Untrusted payload is extracted here — keep it root-only while it exists.
        let _ = std::fs::set_permissions(&mountpoint, std::fs::Permissions::from_mode(0o700));
        // One line so the fence is provable from `journalctl -u ghost-sentri-daemon`
        // instead of by hand: mkfs/mount run silently, this records that the capped
        // scratch actually engaged and at what ceiling.
        log::info!(
            "[fence] capped scan image mounted ({} MiB) at {}",
            cap / (1024 * 1024),
            mountpoint.display()
        );
        Some(m)
    }

    fn path(&self) -> &Path {
        &self.mountpoint
    }
}

impl Drop for LoopMount {
    fn drop(&mut self) {
        // Unmount (the loop device auto-clears on umount), then remove the
        // mountpoint and backing image. The clean path always reaches here; a crash
        // between mount and drop leaks a mount + image, which `sweep_stale_scratch`
        // (called at daemon start) closes.
        if self.mounted {
            let mp = self.mountpoint.to_string_lossy().into_owned();
            let _ = run_ok("umount", &[mp.as_str()]);
        }
        if !self.mountpoint.as_os_str().is_empty() {
            let _ = std::fs::remove_dir_all(&self.mountpoint);
        }
        let _ = std::fs::remove_file(&self.image);
        log::info!("[fence] capped scan image released");
    }
}

/// Run a command silently, returning true only on a clean exit. Every caller here
/// degrades safely on failure (provisioning failure → streaming scan), so stderr
/// is discarded rather than surfaced.
fn run_ok(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Close fence scratch leaked by a crash between mount and `LoopMount::drop`
/// (power loss, SIGKILL, OOM). The clean path always tears its own mount down, so
/// this only ever finds debris after an unclean exit. Called ONCE at daemon start,
/// before any scan runs.
///
/// Two kinds of debris under the scan base: still-mounted `gsscan.*` mountpoints
/// (unmount, then remove) and orphaned `gsloop.*.img` backing images (remove).
/// Unmount-before-remove matters — removing a live mountpoint would only empty the
/// image, not release the loop device. Best-effort throughout: a busy mount that
/// won't release is logged and left rather than forced.
pub fn sweep_stale_scratch() {
    let base = scan_tempdir_base();
    let entries = match std::fs::read_dir(&base) {
        Ok(e) => e,
        Err(_) => return, // base absent → nothing ran yet, nothing to sweep
    };

    let mut swept = 0u32;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();

        if name.starts_with("gsscan.") {
            // A leaked mountpoint: unmount if still mounted (ignore "not mounted"),
            // then remove the directory.
            let mp = path.to_string_lossy().into_owned();
            let _ = run_ok("umount", &[mp.as_str()]);
            if std::fs::remove_dir_all(&path).is_ok() {
                swept += 1;
            }
        } else if name.starts_with("gsloop.") && name.ends_with(".img") {
            // A leaked backing image (its mount, if any, is cleared with the
            // gsscan.* dir above; a bare image just needs deleting).
            if std::fs::remove_file(&path).is_ok() {
                swept += 1;
            }
        }
    }

    if swept > 0 {
        log::info!("[fence] swept {swept} stale scan-scratch item(s) at start");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/h/Downloads/eicar one.com"),
            PathBuf::from("/h/Downloads/two: odd.txt"),
            PathBuf::from("/h/Downloads/clean.txt"),
            PathBuf::from("/h/Downloads/z.zip"),
            PathBuf::from("/h/Downloads/missing.bin"),
        ]
    }

    #[test]
    fn batch_attributes_every_hit() {
        // Real clamscan 1.5.4 output for these five files.
        let out = "/h/Downloads/eicar one.com: Eicar-Test-Signature FOUND\n\
                   /h/Downloads/two: odd.txt: Eicar-Test-Signature FOUND\n\
                   /h/Downloads/z.zip: Eicar-Test-Signature FOUND\n\
                   /h/Downloads/missing.bin: No such file or directory\n";
        let err = "WARNING: /h/Downloads/missing.bin: Can't access file\n";
        let v = parse_batch(&files(), Some(1), &out.replace("                   ", ""), err, "v");
        assert!(matches!(&v[0], FileVerdict::Threat(d) if d.name == "Eicar-Test-Signature"));
        assert!(matches!(&v[1], FileVerdict::Threat(_)));
        assert!(matches!(&v[2], FileVerdict::Clean));
        assert!(matches!(&v[3], FileVerdict::Threat(_)));
        assert!(matches!(&v[4], FileVerdict::Error(_)));
    }

    #[test]
    fn batch_limits_and_run_failure() {
        let f = files();
        let out = format!("{}: Heuristics.Limits.Exceeded.MaxFileSize FOUND\n", f[2].display());
        let v = parse_batch(&f, Some(1), &out, "", "v");
        assert!(matches!(v[2], FileVerdict::LimitsExceeded));
        assert!(matches!(v[0], FileVerdict::Clean));
        // Exit 2 with nothing attributed: the run failed, nobody is clean.
        let v = parse_batch(&f, Some(2), "", "LibClamAV Error: cli_loaddb(): No supported database files found\n", "v");
        assert!(v.iter().all(|x| matches!(x, FileVerdict::Error(_))));
        // Killed by a signal.
        let v = parse_batch(&f, None, "", "", "v");
        assert!(v.iter().all(|x| matches!(x, FileVerdict::Error(_))));
    }

    #[test]
    fn single_prefers_real_threat_over_limits() {
        let out = "/x/a: Heuristics.Limits.Exceeded.MaxScanSize FOUND\n/x/b: Win.Trojan.Agent-1 FOUND\n";
        assert!(matches!(parse_single(Some(1), out, "", "v"), ScanResult::Threat(d) if d.name == "Win.Trojan.Agent-1"));
        let out = "/x/a: Heuristics.Limits.Exceeded.MaxScanSize FOUND\n";
        assert!(matches!(parse_single(Some(1), out, "", "v"), ScanResult::Error(_)));
    }

    #[test]
    fn rar_needs_matching_versions() {
        let this_host = "libclamav12:amd64 1.5.4+dfsg-0ubuntu0.24.04.1 ii \n";
        assert!(!rar_supported_from(this_host));
        let mismatch = format!("{this_host}libclamunrar12:amd64 1.3.1-0ubuntu0.24.04.1 ii \n");
        assert!(!rar_supported_from(&mismatch));
        let ok = format!("{this_host}libclamunrar12:amd64 1.5.4-0ubuntu0.24.04.1 ii \n");
        assert!(rar_supported_from(&ok));
        let removed = format!("{this_host}libclamunrar12:amd64 1.5.4-1 rc \n");
        assert!(!rar_supported_from(&removed));
    }
}
