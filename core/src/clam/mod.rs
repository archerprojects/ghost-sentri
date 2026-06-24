// core/src/clam/mod.rs
// Scan engine: system `clamscan` subprocess (no C FFI).
// Definition status: filesystem stat of daily.cvd/.cld mtime — no network calls.
// Definition updates: run via pkexec freshclam, user-initiated only (polkit auth).
// Staleness is checked daily by the resident daemon (no systemd timer).

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
        let need = deb_installed_bytes(path);
        let free = fs_available_bytes(&base);
        let fits = matches!((need, free), (Some(n), Some(f)) if f >= n.saturating_mul(SPACE_MARGIN));

        // `disk_pressure` shapes the user-facing message if the scan ultimately
        // can't run: true means space was the reason we avoided / couldn't finish
        // the extract.
        let mut disk_pressure = !fits;

        if fits {
            match self.scan_deb_extracted(path, &base) {
                Ok(ScanResult::Error(e)) => return ScanResult::Error(unscannable_msg(path, false, &e)),
                Ok(other) => return other,        // scanned in a single DB load
                Err(()) => disk_pressure = true,  // ENOSPC mid-write → fall back, partial cleaned
            }
        }

        match self.scan_deb_streamed(path) {
            ScanResult::Error(e) => ScanResult::Error(unscannable_msg(path, disk_pressure, &e)),
            other => other,
        }
    }

    /// Fast path: raw-extract the WHOLE package tree (payload + control scripts
    /// under `DEBIAN/`) and run ONE recursive clamscan over it. Scanning the
    /// extracted members as individual files — rather than handing clamscan the
    /// `data.tar` as one container — means the per-container `--max-scansize` never
    /// aggregates across a package of many small files (the common false-skip on
    /// large multi-file packages). dpkg-deb does the decompression, so this never
    /// depends on clamscan's own compression support. Returns `Err(())` only when
    /// the extract fails (incl. ENOSPC → fall back, guard wipes the partial); a
    /// clamscan launch/run failure is surfaced as `Ok(ScanResult::Error)` because
    /// streaming would fail the same way.
    fn scan_deb_extracted(&self, path: &Path, base: &Path) -> Result<ScanResult, ()> {
        let dir = make_scan_dir(base).ok_or(())?;
        let _guard = TempDirGuard(dir.clone()); // rm -rf on return — self-healing, no partial left

        let extracted = Command::new("dpkg-deb")
            .arg("--raw-extract")
            .arg(path)
            .arg(&dir)
            .stderr(Stdio::null())
            .status();
        match extracted {
            Ok(s) if s.success() => {}
            _ => return Err(()), // extract failed (incl. disk pressure) → fall back
        }

        // Pin clamscan's own descent temps to the same dir so they fall inside the
        // headroom we already checked.
        let tempdir_arg = format!("--tempdir={}", dir.display());
        let out = Command::new(&self.clamscan_path)
            .args(["--recursive", "--no-summary", "--infected"])
            .args(SCAN_LIMITS)
            .arg(&tempdir_arg)
            .arg(&dir)
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
        let stdout = String::from_utf8_lossy(stdout);
        let stderr = String::from_utf8_lossy(stderr);
        let def_ver = self.get_definition_version().unwrap_or_default();
        match code {
            Some(0) => ScanResult::Clean,
            Some(1) => {
                for line in stdout.lines() {
                    if line.ends_with("FOUND") {
                        // A tripped scan fence (via --alert-exceeds-max) is NOT
                        // malware — it means a member was too large or too deeply
                        // nested to fully scan. Surface it as an error so it fails
                        // closed as `unscannable` (block/review) with honest
                        // wording, rather than masquerading as a signature hit.
                        if line.contains("Heuristics.Limits.Exceeded") {
                            return ScanResult::Error(
                                "a package member exceeded scan limits (too large \
                                 or too deeply nested to fully scan)"
                                    .to_string(),
                            );
                        }
                        if let Some(detail) =
                            ThreatDetail::from_clamscan_line(line, &def_ver, "daily.cvd")
                        {
                            return ScanResult::Threat(detail);
                        }
                    }
                }
                ScanResult::Threat(ThreatDetail {
                    name:               "Unknown".to_string(),
                    classification:     ThreatClassification::Unknown,
                    database:           "unknown".to_string(),
                    definition_version: def_ver,
                    plain_english:      stdout.to_string(),
                })
            }
            Some(2) => ScanResult::Error(format!(
                "clamscan error: {}",
                if !stderr.is_empty() { &stderr } else { &stdout }
            )),
            _ => ScanResult::Error("clamscan returned unexpected exit code".to_string()),
        }
    }

    pub fn scan_directory(&self, path: &Path) -> Vec<(PathBuf, ScanResult)> {
        let output = Command::new(&self.clamscan_path)
            .args(["--recursive", "--no-summary"])
            .arg(path)
            .output();

        match output {
            Err(e) => vec![(path.to_path_buf(), ScanResult::Error(format!("clamscan failed: {}", e)))],
            Ok(out) => {
                let stdout  = String::from_utf8_lossy(&out.stdout);
                let def_ver = self.get_definition_version().unwrap_or_default();
                let mut results = vec![];
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.splitn(2, ": ").collect();
                    if parts.len() != 2 { continue; }
                    let file_path = PathBuf::from(parts[0].trim());
                    let status    = parts[1].trim();
                    let result = if status == "OK" {
                        ScanResult::Clean
                    } else if status.ends_with("FOUND") {
                        ThreatDetail::from_clamscan_line(line, &def_ver, "daily.cvd")
                            .map(ScanResult::Threat)
                            .unwrap_or(ScanResult::Clean)
                    } else {
                        ScanResult::Error(status.to_string())
                    };
                    results.push((file_path, result));
                }
                results
            }
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

/// Returns true if the system clamav-freshclam service is currently active.
/// Used to avoid conflicting with system-managed definition updates.
pub fn system_freshclam_running() -> bool {
    Command::new("systemctl")
        .args(["is-active", "clamav-freshclam"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false)
}

/// Runs freshclam directly — called only via pkexec from the UpdateDefinitions
/// handler in main.rs. Requires polkit authorisation — never called silently.
pub fn run_freshclam_update() -> Result<String> {
    let out = Command::new("freshclam")
        .output()
        .context("freshclam not found — is ClamAV installed?")?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if out.status.success() {
        Ok(stdout)
    } else {
        Err(anyhow::anyhow!(
            "freshclam failed: {}",
            if !stderr.is_empty() { stderr } else { stdout }
        ))
    }
}

/// True if `path` looks like a Debian package by extension.
fn is_deb(path: &Path) -> bool {
    path.extension().map(|e| e.eq_ignore_ascii_case("deb")).unwrap_or(false)
}

// ─────────────────────────────────────────────────────────────────────────────
// Single-scan temp-extract support (footprint: transient only — write, scan, rm)
// ─────────────────────────────────────────────────────────────────────────────

/// Free-space safety factor applied to the predicted extract size before the
/// fast path is taken. Covers tar block padding plus clamscan's own descent
/// temps, which share the same dir.
const SPACE_MARGIN: u64 = 2;

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

/// Removes a temp dir (and its contents) when dropped, so a partial extract from
/// a mid-write ENOSPC is cleaned immediately rather than left for the user.
struct TempDirGuard(PathBuf);
impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
