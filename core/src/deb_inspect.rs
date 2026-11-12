// core/src/deb_inspect.rs — v1.1.0 — Thursday 12 November 2026
// Unprivileged pre-install inspection of a .deb. Pure `dpkg-deb` / `dpkg` / apt
// simulation — NO root, NO GTK. Produces a DebReport the GUI renders on the
// review screen BEFORE the single polkit elevation, so the user authorises a
// root install only after seeing what it contains.
//
// This is the substance of the GDebi replacement (P4): metadata, action class
// (install/upgrade/downgrade/reinstall), the packages apt would pull, a flagged
// file manifest, setuid/apt-source/key detection, and the four maintainer
// scripts shown verbatim with a SCORED HEURISTIC scan. None of it executes
// anything from the package — extraction is metadata only.
//
// Heuristic rationale: ClamAV signature-scans the package ARTIFACT. The dominant
// real-world Linux supply-chain attack ships a clean artifact and a malicious
// maintainer script that fetches a poisoned payload at install time (e.g. the
// 2026 AUR wave). The payload is not on disk until the script runs, so signature
// scanning structurally misses it. The heuristic catches the *technique*
// (remote-fetch-piped-to-shell, obfuscated decode-and-exec, remote package
// installs, apt-source injection, setuid drops, network beacons) on day zero.
// It WARNS, it does not block — legitimate scripts use some of these patterns;
// the user decides with the evidence in front of them.

use anyhow::{anyhow, Result};
use regex::Regex;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// What kind of change installing this package represents on this machine.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InstallAction {
    Install,
    Upgrade,
    Downgrade,
    Reinstall,
}

impl InstallAction {
    pub fn label(&self) -> &'static str {
        match self {
            InstallAction::Install => "Install (new package)",
            InstallAction::Upgrade => "Upgrade",
            InstallAction::Downgrade => "Downgrade",
            InstallAction::Reinstall => "Reinstall (same version)",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Heuristic findings model
// ─────────────────────────────────────────────────────────────────────────────

/// Severity of a single maintainer-script finding. Declared low → high so the
/// `as u8` discriminant is a usable rank. `weight()` feeds the package score;
/// `Info` carries weight 0 — it is shown to the user but never moves the risk
/// band, so a normal package that only runs `systemctl enable` does not raise a
/// warning banner (over-warning trains users to click through).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn weight(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Medium => 20,
            Severity::High => 50,
            Severity::Critical => 100,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// The class of behaviour a rule detects. Used to group findings (one finding
/// per family per line is kept, at its highest severity) and to label the UI.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RuleFamily {
    RemoteFetch,
    RemotePkgInstall,
    Obfuscation,
    AptSourceInjection,
    PrivilegePersistence,
    NetworkBeacon,
    Destructive,
    RoutineRootOp,
}

impl RuleFamily {
    pub fn label(self) -> &'static str {
        match self {
            RuleFamily::RemoteFetch => "Remote fetch / exec",
            RuleFamily::RemotePkgInstall => "Remote package install",
            RuleFamily::Obfuscation => "Obfuscation",
            RuleFamily::AptSourceInjection => "APT source / key injection",
            RuleFamily::PrivilegePersistence => "Privilege / persistence",
            RuleFamily::NetworkBeacon => "Network beacon",
            RuleFamily::Destructive => "Destructive operation",
            RuleFamily::RoutineRootOp => "Routine root operation",
        }
    }
}

/// One heuristic hit inside a maintainer script. `line` is 1-based into the
/// script body (0 only if a future whole-body rule has no single line). `excerpt`
/// is the offending logical line, trimmed and length-capped for display.
pub struct ScriptFinding {
    pub family: RuleFamily,
    pub severity: Severity,
    pub line: usize,
    pub excerpt: String,
    pub message: String,
}

/// Overall script-risk band for the package, derived from the summed weights of
/// all Medium-and-above findings across the four scripts. Clean = nothing worth
/// a banner (Info-only or no scripts); Suspicious = some weight, no single
/// serious hit; HighRisk = at least one High/Critical, or a stack of Mediums.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RiskBand {
    Clean,
    Suspicious,
    HighRisk,
}

impl RiskBand {
    fn from_score(score: u32) -> RiskBand {
        if score == 0 {
            RiskBand::Clean
        } else if score < 50 {
            RiskBand::Suspicious
        } else {
            RiskBand::HighRisk
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            RiskBand::Clean => "Clean",
            RiskBand::Suspicious => "Suspicious",
            RiskBand::HighRisk => "High risk",
        }
    }
}

/// One maintainer script (preinst/postinst/prerm/postrm) shipped in the package.
/// `body` is shown verbatim; `findings` are the heuristic hits worth the user's
/// eye before authorising root.
pub struct MaintainerScript {
    pub name: String,
    pub body: String,
    pub findings: Vec<ScriptFinding>,
}

/// A packaged file that lands somewhere sensitive, with the reason it's flagged.
pub struct FlaggedFile {
    pub path: String,
    pub reason: String,
}

/// Full inspection result. Everything the review screen needs in one struct.
pub struct DebReport {
    // Identity / metadata
    pub package: String,
    pub version: String,
    pub architecture: String,
    pub maintainer: String,
    pub description: String,
    pub installed_size_kb: Option<u64>,
    pub homepage: Option<String>,
    pub depends: Vec<String>,
    pub conflicts: Vec<String>,
    pub breaks: Vec<String>,
    pub replaces: Vec<String>,

    // Provenance signal — the .deb file's own mtime, formatted local time.
    // INFORMATIONAL ONLY: this is when the file was written/downloaded, not when
    // it was built. A loose .deb carries no trustworthy build date, and repo
    // trust (main-repo vs PPA/third-party) only exists on the apt path, which is
    // not yet wired end-to-end. So this is surfaced plainly, with no risk weight.
    pub file_modified: Option<String>,

    // Host fit
    pub host_arch: String,
    pub arch_compatible: bool,

    // Action vs installed state
    pub action: InstallAction,
    pub installed_version: Option<String>,

    // apt dependency simulation
    pub apt_pulls: Vec<String>,
    pub apt_simulation_ok: bool,
    pub apt_note: Option<String>,
    pub unmet_dependencies: bool,

    // Payload inspection
    pub flagged_files: Vec<FlaggedFile>,
    pub setuid_files: Vec<String>,
    pub adds_apt_source: bool,
    pub adds_gpg_key: bool,
    pub maintainer_scripts: Vec<MaintainerScript>,

    // Heuristic verdict over the maintainer scripts.
    pub script_score: u32,
    pub script_risk: RiskBand,

    // Human-readable security advisories, assembled from the above.
    pub advisories: Vec<String>,
}

impl DebReport {
    /// Hard gate. Only two conditions actually prevent installation: the package
    /// can't run on this architecture, or apt says its dependencies are
    /// unsatisfiable. Everything else — INCLUDING the heuristic risk band — is
    /// advisory; the user decides.
    pub fn installable(&self) -> bool {
        self.arch_compatible && !self.unmet_dependencies
    }
}

/// Inspect a .deb at `path`. Best-effort: a failure in any one probe degrades
/// that section rather than aborting the whole review (fail-open — the worker's
/// ClamAV scan and apt itself remain the backstops).
pub fn inspect(path: &Path) -> Result<DebReport> {
    if !path.exists() {
        return Err(anyhow!("package not found: {}", path.display()));
    }

    let fields = read_control_fields(path)?;
    let description = read_description(path);

    let package = fields.get("Package").cloned().unwrap_or_default();
    let version = fields.get("Version").cloned().unwrap_or_default();
    let architecture = fields.get("Architecture").cloned().unwrap_or_default();
    let maintainer = fields.get("Maintainer").cloned().unwrap_or_default();
    let installed_size_kb = fields.get("Installed-Size").and_then(|s| s.trim().parse::<u64>().ok());
    let homepage = fields.get("Homepage").cloned().filter(|s| !s.is_empty());
    let depends = split_relations(fields.get("Depends"));
    let conflicts = split_relations(fields.get("Conflicts"));
    let breaks = split_relations(fields.get("Breaks"));
    let replaces = split_relations(fields.get("Replaces"));

    let file_modified = read_file_modified(path);

    let host_arch = host_architecture();
    let arch_compatible = arch_is_compatible(&architecture, &host_arch);

    let installed_version = installed_version_of(&package);
    let action = classify_action(&version, installed_version.as_deref());

    let (apt_pulls, apt_simulation_ok, apt_note, unmet_dependencies) =
        simulate_apt(path, &package);

    let (flagged_files, setuid_files, adds_apt_source, adds_gpg_key) = inspect_contents(path);
    let maintainer_scripts = read_maintainer_scripts(path);

    let script_score = score_scripts(&maintainer_scripts);
    let script_risk = RiskBand::from_score(script_score);

    let advisories = build_advisories(
        &setuid_files,
        adds_apt_source,
        adds_gpg_key,
        script_risk,
        &conflicts,
        &breaks,
    );

    Ok(DebReport {
        package,
        version,
        architecture,
        maintainer,
        description,
        installed_size_kb,
        homepage,
        depends,
        conflicts,
        breaks,
        replaces,
        file_modified,
        host_arch,
        arch_compatible,
        action,
        installed_version,
        apt_pulls,
        apt_simulation_ok,
        apt_note,
        unmet_dependencies,
        flagged_files,
        setuid_files,
        adds_apt_source,
        adds_gpg_key,
        maintainer_scripts,
        script_score,
        script_risk,
        advisories,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Control metadata
// ─────────────────────────────────────────────────────────────────────────────

/// Single-line control fields via `dpkg-deb -f`. Description is fetched
/// separately (it's multi-line) so this parse stays trivial.
fn read_control_fields(path: &Path) -> Result<std::collections::HashMap<String, String>> {
    let out = Command::new("dpkg-deb")
        .args(["-f"])
        .arg(path)
        .args([
            "Package",
            "Version",
            "Architecture",
            "Maintainer",
            "Installed-Size",
            "Homepage",
            "Depends",
            "Conflicts",
            "Breaks",
            "Replaces",
        ])
        .output()
        .map_err(|e| anyhow!("dpkg-deb not available: {e}"))?;

    if !out.status.success() {
        return Err(anyhow!(
            "dpkg-deb could not read the package (it may be corrupt or not a .deb)"
        ));
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut map = std::collections::HashMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    Ok(map)
}

/// First line of the Description field as a short summary.
fn read_description(path: &Path) -> String {
    let out = Command::new("dpkg-deb").args(["-f"]).arg(path).arg("Description").output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string(),
        _ => String::new(),
    }
}

/// The .deb file's own last-modified time, formatted as local `YYYY-MM-DD HH:MM`.
/// Informational provenance only — see `DebReport::file_modified`.
fn read_file_modified(path: &Path) -> Option<String> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let dt: chrono::DateTime<chrono::Local> = modified.into();
    Some(dt.format("%Y-%m-%d %H:%M").to_string())
}

/// Split a Debian relationship field ("a (>= 1), b | c, d") into trimmed atoms.
fn split_relations(field: Option<&String>) -> Vec<String> {
    match field {
        Some(s) if !s.is_empty() => s
            .split(',')
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Host fit + action classification
// ─────────────────────────────────────────────────────────────────────────────

fn host_architecture() -> String {
    run_stdout("dpkg", &["--print-architecture"]).trim().to_string()
}

/// `all` runs anywhere; native matches; a foreign (multiarch-enabled) arch is
/// acceptable too. Anything else is a genuine "won't install here".
fn arch_is_compatible(deb_arch: &str, host: &str) -> bool {
    if deb_arch.is_empty() || deb_arch == "all" || deb_arch == host {
        return true;
    }
    let foreign = run_stdout("dpkg", &["--print-foreign-architectures"]);
    foreign.split_whitespace().any(|a| a == deb_arch)
}

/// Installed version of a package, or None if not installed. `dpkg-query`
/// returns non-zero for not-installed and for config-only states.
fn installed_version_of(package: &str) -> Option<String> {
    if package.is_empty() {
        return None;
    }
    let out = Command::new("dpkg-query")
        .args(["-W", "-f=${Status}|${Version}", package])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let (status, ver) = text.split_once('|')?;
    // Only treat as installed when dpkg says so ("install ok installed").
    if status.contains("installed") && !ver.trim().is_empty() {
        Some(ver.trim().to_string())
    } else {
        None
    }
}

fn classify_action(new_version: &str, installed: Option<&str>) -> InstallAction {
    match installed {
        None => InstallAction::Install,
        Some(old) => {
            if dpkg_compare(new_version, "eq", old) {
                InstallAction::Reinstall
            } else if dpkg_compare(new_version, "gt", old) {
                InstallAction::Upgrade
            } else {
                InstallAction::Downgrade
            }
        }
    }
}

/// `dpkg --compare-versions a OP b` — exit 0 means the relation holds.
fn dpkg_compare(a: &str, op: &str, b: &str) -> bool {
    Command::new("dpkg")
        .args(["--compare-versions", a, op, b])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ─────────────────────────────────────────────────────────────────────────────
// apt dependency simulation (unprivileged)
// ─────────────────────────────────────────────────────────────────────────────

/// Returns (extra_pulls, simulation_ok, note, unmet_dependencies).
/// `apt-get install -s` needs no root. We read the "newly installed" set and
/// subtract the target; we flag unmet deps from apt's own error language.
fn simulate_apt(path: &Path, package: &str) -> (Vec<String>, bool, Option<String>, bool) {
    let abs = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string();

    let out = match Command::new("apt-get")
        .args(["install", "-s", "--no-install-recommends", &abs])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return (
                Vec::new(),
                false,
                Some(format!("Dependency simulation unavailable: {e}")),
                false,
            )
        }
    };

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}\n{stderr}");

    let unmet = combined.contains("but it is not installable")
        || combined.contains("but it is not going to be installed")
        || combined.contains("Unable to correct problems")
        || combined.contains("held broken packages")
        || combined.contains("Depends:") && combined.contains("not installable")
        || combined.to_lowercase().contains("unmet dependencies");

    if unmet {
        return (
            Vec::new(),
            true,
            Some("apt reports unsatisfiable dependencies for this package.".to_string()),
            true,
        );
    }

    if !out.status.success() {
        return (
            Vec::new(),
            false,
            Some("apt could not complete the simulation; it will resolve dependencies at install time.".to_string()),
            false,
        );
    }

    let pulls = parse_newly_installed(&stdout, package);
    (pulls, true, None, false)
}

/// Parse the indented package list under "The following NEW packages will be
/// installed:" and drop the target package itself.
fn parse_newly_installed(stdout: &str, package: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_block = false;
    for line in stdout.lines() {
        if line.starts_with("The following NEW packages will be installed") {
            in_block = true;
            continue;
        }
        if in_block {
            // The block is indented; the first non-indented line ends it.
            if line.starts_with(' ') {
                for tok in line.split_whitespace() {
                    if tok != package {
                        names.push(tok.to_string());
                    }
                }
            } else {
                break;
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

// ─────────────────────────────────────────────────────────────────────────────
// Payload manifest: sensitive paths, setuid, apt sources/keys
// ─────────────────────────────────────────────────────────────────────────────

/// Returns (flagged_files, setuid_files, adds_apt_source, adds_gpg_key).
fn inspect_contents(path: &Path) -> (Vec<FlaggedFile>, Vec<String>, bool, bool) {
    let out = Command::new("dpkg-deb").args(["-c"]).arg(path).output();
    let text = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => return (Vec::new(), Vec::new(), false, false),
    };

    let mut flagged = Vec::new();
    let mut setuid = Vec::new();
    let mut adds_apt_source = false;
    let mut adds_gpg_key = false;

    for line in text.lines() {
        let Some((mode, fpath)) = parse_contents_line(line) else { continue };
        // Normalise "./usr/bin/x" -> "/usr/bin/x"
        let norm = fpath.trim_start_matches('.').to_string();
        if norm.is_empty() || norm.ends_with('/') {
            // directories: still useful for source/key detection below
        }

        // setuid / setgid bit (mode chars: -rwsrwsrwx)
        let bytes = mode.as_bytes();
        let is_suid = bytes.get(3).map(|c| *c == b's' || *c == b'S').unwrap_or(false);
        let is_sgid = bytes.get(6).map(|c| *c == b's' || *c == b'S').unwrap_or(false);
        if is_suid || is_sgid {
            setuid.push(norm.clone());
            flagged.push(FlaggedFile {
                path: norm.clone(),
                reason: if is_suid { "setuid root executable".into() } else { "setgid executable".into() },
            });
        }

        if let Some(reason) = sensitive_reason(&norm) {
            flagged.push(FlaggedFile { path: norm.clone(), reason: reason.to_string() });
        }
        if norm.starts_with("/etc/apt/sources.list.d/") {
            adds_apt_source = true;
        }
        if norm.starts_with("/etc/apt/trusted.gpg.d/") || norm.starts_with("/usr/share/keyrings/") {
            adds_gpg_key = true;
        }
    }

    flagged.sort_by(|a, b| a.path.cmp(&b.path));
    flagged.dedup_by(|a, b| a.path == b.path && a.reason == b.reason);
    setuid.sort();
    setuid.dedup();
    (flagged, setuid, adds_apt_source, adds_gpg_key)
}

/// dpkg-deb -c line: `perms owner size date time ./path [-> target]`.
/// Returns (mode, path) — path with any symlink target stripped.
fn parse_contents_line(line: &str) -> Option<(String, String)> {
    let mut it = line.split_whitespace();
    let mode = it.next()?.to_string();
    if mode.len() < 10 {
        return None;
    }
    // skip owner, size, date, time
    let _owner = it.next()?;
    let _size = it.next()?;
    let _date = it.next()?;
    let _time = it.next()?;
    let rest: Vec<&str> = it.collect();
    if rest.is_empty() {
        return None;
    }
    let joined = rest.join(" ");
    let pathpart = joined.split(" -> ").next().unwrap_or(&joined).to_string();
    Some((mode, pathpart))
}

/// Why a path is worth showing the user, or None if it's unremarkable.
fn sensitive_reason(p: &str) -> Option<&'static str> {
    let sensitive: &[(&str, &str)] = &[
        ("/etc/sudoers.d/", "grants sudo privileges"),
        ("/etc/sudoers", "modifies sudo configuration"),
        ("/etc/polkit-1/", "modifies polkit authorisation"),
        ("/usr/share/polkit-1/", "installs a polkit policy/rule"),
        ("/etc/apt/sources.list.d/", "adds an APT software source"),
        ("/etc/apt/trusted.gpg.d/", "installs an APT signing key"),
        ("/usr/share/keyrings/", "installs an APT signing key"),
        ("/lib/systemd/system/", "installs a systemd service"),
        ("/usr/lib/systemd/system/", "installs a systemd service"),
        ("/etc/systemd/", "modifies systemd configuration"),
        ("/etc/cron.d/", "installs a scheduled task"),
        ("/etc/cron.daily/", "installs a scheduled task"),
        ("/etc/cron.hourly/", "installs a scheduled task"),
        ("/etc/init.d/", "installs a init service"),
        ("/usr/bin/", "installs an executable on PATH"),
        ("/usr/sbin/", "installs a system executable"),
        ("/bin/", "installs an executable on PATH"),
        ("/sbin/", "installs a system executable"),
        ("/etc/", "writes system configuration"),
    ];
    for (prefix, reason) in sensitive {
        if p.starts_with(prefix) {
            return Some(reason);
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Maintainer scripts (run as root at install/remove time)
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the control archive to a temp dir and read the four maintainer
/// scripts verbatim, each with a heuristic scan. The temp dir is removed on exit.
fn read_maintainer_scripts(path: &Path) -> Vec<MaintainerScript> {
    let tmp = unique_tmp_dir();
    if std::fs::create_dir_all(&tmp).is_err() {
        return Vec::new();
    }
    let _guard = TmpGuard(tmp.clone());

    let status = Command::new("dpkg-deb").args(["-e"]).arg(path).arg(&tmp).status();
    if status.map(|s| !s.success()).unwrap_or(true) {
        return Vec::new();
    }

    let mut scripts = Vec::new();
    for name in ["preinst", "postinst", "prerm", "postrm"] {
        let f = tmp.join(name);
        if let Ok(body) = std::fs::read_to_string(&f) {
            let findings = scan_script(&body);
            scripts.push(MaintainerScript { name: name.to_string(), body, findings });
        }
    }
    scripts
}

// ─────────────────────────────────────────────────────────────────────────────
// Heuristic rule engine
// ─────────────────────────────────────────────────────────────────────────────

/// A compiled heuristic rule. The Rust `regex` crate has no backreferences or
/// lookaround — every pattern below is linear-time safe by construction.
struct Rule {
    family: RuleFamily,
    severity: Severity,
    re: Regex,
    message: &'static str,
}

/// Compile the rule table once. Ordered roughly high → low severity for readable
/// per-line output; the (line, family) max-severity dedup makes order irrelevant
/// to the final result.
fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let r = |family, severity, pat: &str, message| Rule {
            family,
            severity,
            re: Regex::new(pat).expect("heuristic rule regex must compile"),
            message,
        };
        use RuleFamily::*;
        use Severity::*;
        vec![
            // ── Remote fetch piped/substituted into a shell — the headline class ──
            r(RemoteFetch, Critical,
              r"(?:curl|wget|fetch)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|da|z|t?c|k)?sh\b",
              "downloads from the network and pipes it straight to a shell"),
            r(RemoteFetch, Critical,
              r#"(?:ba|da|z|t?c|k)?sh\b\s+-c\s+["']?\$\((?:curl|wget|fetch)\b"#,
              "executes the output of a network download in a shell"),
            r(RemoteFetch, Critical,
              r"\beval\b[^\n]*\$\((?:curl|wget|fetch)\b",
              "evaluates the output of a network download"),
            r(RemoteFetch, Critical,
              r"\$\((?:curl|wget|fetch)\b[^)\n]*\)\s*\|\s*(?:ba|da|z|t?c|k)?sh\b",
              "pipes a network download to a shell"),
            // bare network fetch (no pipe) — same family, lower severity
            r(RemoteFetch, Medium,
              r"\b(?:curl|wget)\s",
              "downloads from the network"),

            // ── Obfuscated decode-and-exec / encoded blobs ──
            r(Obfuscation, Critical,
              r"\bbase64\s+(?:-d|--decode)\b[^|\n]*\|\s*(?:ba|da|z|t?c|k)?sh\b",
              "decodes embedded data and pipes it to a shell"),
            r(Obfuscation, Medium,
              r"\bbase64\s+(?:-d|--decode)\b",
              "decodes embedded data"),
            r(Obfuscation, Medium,
              r"\bprintf\b[^\n]*(?:\\x[0-9A-Fa-f]{2}){4,}",
              "constructs data or commands from hex escapes"),
            r(Obfuscation, Medium,
              r"\bxxd\s+-r\b",
              "reverses a hex dump into binary"),
            r(Obfuscation, Medium,
              r"[A-Za-z0-9+/]{160,}={0,2}",
              "contains a long base64-encoded blob"),
            r(Obfuscation, Medium,
              r"\beval\b",
              "evaluates a dynamically constructed command"),

            // ── Remote package installs from a maintainer script ──
            r(RemotePkgInstall, High,
              r"\bnpm\s+(?:install|i|add|exec|ci)\b[^\n]*(?:https?://|git\+|github\.com[:/]|\.tgz|\.tar\.gz)",
              "installs an npm package from a remote/URL source"),
            r(RemotePkgInstall, High,
              r"\bnpx\s+[^\n]*(?:https?://|github\.com[:/])",
              "runs a remote npx package"),
            r(RemotePkgInstall, High,
              r"\bpip[0-9]?\s+install\b[^\n]*(?:https?://|git\+)",
              "installs a Python package from a remote/URL source"),
            r(RemotePkgInstall, High,
              r"\bgem\s+install\b[^\n]*(?:--source|https?://)",
              "installs a Ruby gem from a remote source"),
            r(RemotePkgInstall, High,
              r"\b(?:go\s+(?:install|get)|cargo\s+install)\b[^\n]*(?:https?://|git\+|--git)",
              "installs a Go/Rust package from a remote source"),

            // ── APT source / signing-key injection ──
            r(AptSourceInjection, High,
              r"\badd-apt-repository\b",
              "adds an APT repository"),
            r(AptSourceInjection, High,
              r"(?:>>?|tee)\s+[^\n]*/etc/apt/sources\.list",
              "writes to the APT sources list"),
            r(AptSourceInjection, High,
              r"\bapt-key\s+add\b",
              "installs an APT signing key (deprecated, high-trust)"),
            r(AptSourceInjection, High,
              r"/etc/apt/preferences",
              "edits APT pinning/preferences"),
            r(AptSourceInjection, High,
              r"(?:curl|wget|gpg)[^\n]*/(?:usr/share/keyrings|etc/apt/trusted\.gpg\.d)",
              "installs an APT signing key"),

            // ── Privilege escalation / persistence ──
            r(PrivilegePersistence, High,
              r"\bchmod\s+(?:[0-7]*[4-7][0-7]{3}|u\+s|g\+s|\+s)\b",
              "sets a setuid/setgid bit"),
            r(PrivilegePersistence, High,
              r"\bchmod\s+(?:\+x|0?[0-7]*7[0-7]{2})\s+[^\n]*(?:/tmp/|/var/tmp/|/dev/shm/)",
              "makes a file in a temp directory executable"),
            r(PrivilegePersistence, High,
              r"(?:>>?|tee|cp|mv|echo)[^\n]*/etc/sudoers",
              "modifies sudo configuration"),
            r(PrivilegePersistence, High,
              r"\bvisudo\b",
              "edits the sudoers file"),
            r(PrivilegePersistence, Medium,
              r"(?:>>?|tee)\s+[^\n]*(?:\.bashrc|\.bash_profile|\.profile|\.zshrc|/etc/profile\.d)",
              "adds shell-startup persistence"),
            r(PrivilegePersistence, Medium,
              r"(?:>>?|tee|cp|install)\b[^\n]*/(?:etc|lib|usr/lib)/systemd/system",
              "installs or edits a systemd unit from the script"),
            r(PrivilegePersistence, Medium,
              r"\bcrontab\b|/etc/cron|\bat\s+(?:now|[0-9])",
              "installs a scheduled task"),

            // ── Network beacons / reverse shells ──
            r(NetworkBeacon, High,
              r"/dev/tcp/",
              "opens a raw TCP socket (reverse-shell pattern)"),
            r(NetworkBeacon, High,
              r"\b(?:nc|ncat|netcat)\s+[^\n]*\s[0-9]{1,5}\b",
              "uses netcat (exfiltration / shell pattern)"),
            r(NetworkBeacon, High,
              r"[a-z2-7]{16,56}\.onion\b",
              "contacts a Tor hidden service"),

            // ── Destructive operations ──
            r(Destructive, High,
              r#"\brm\s+-[a-zA-Z]*\s+/(?:\s|$|["'*])"#,
              "recursive delete targeting the filesystem root"),
            r(Destructive, High,
              r"--no-preserve-root",
              "disables rm's root-deletion guard"),
            r(Destructive, High,
              r"\bdd\s+if=",
              "performs a raw disk read/write"),
            r(Destructive, High,
              r"\bmkfs(?:\.\w+)?\b",
              "formats a filesystem"),
            r(Destructive, High,
              r">\s*/dev/(?:sd[a-z]|nvme[0-9]|vd[a-z])\b",
              "writes directly to a block device"),

            // ── Routine root operations — shown, but Info (no band weight) ──
            r(RoutineRootOp, Info,
              r"\bsystemctl\s+(?:enable|disable|start|stop|restart|daemon-reload)\b",
              "manages a systemd service"),
            r(RoutineRootOp, Info,
              r"\b(?:useradd|usermod|userdel)\b",
              "manages a system user"),
            r(RoutineRootOp, Info,
              r"\b(?:groupadd|groupmod|groupdel)\b",
              "manages a system group"),
            r(RoutineRootOp, Info,
              r"\bsetcap\b",
              "grants Linux capabilities"),
            r(RoutineRootOp, Info,
              r"\bchmod\s+\+x\b",
              "makes a file executable"),
            r(RoutineRootOp, Info,
              r"\bln\s+-s[a-z]*\s+[^\n]*/(?:usr/(?:local/)?)?s?bin\b",
              "creates a symlink on PATH"),
        ]
    })
}

/// Run the rule table over a script body. Lines are joined on `\` continuations
/// so a fetch split across `curl … \` / `| bash` is caught; comment-only lines
/// are skipped so a `# curl x | bash` note doesn't flag. At most one finding per
/// (line, family) survives, kept at its highest severity.
fn scan_script(body: &str) -> Vec<ScriptFinding> {
    let mut found: Vec<ScriptFinding> = Vec::new();

    for (lineno, text) in join_continuations(body) {
        let trimmed = text.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        for rule in rules() {
            if rule.re.is_match(&text) {
                found.push(ScriptFinding {
                    family: rule.family,
                    severity: rule.severity,
                    line: lineno,
                    excerpt: truncate(text.trim(), 200),
                    message: rule.message.to_string(),
                });
            }
        }
    }

    dedup_max_per_family(found)
}

/// Fold shell line-continuations (`\` at end of line) into single logical lines,
/// tagged with the 1-based number of the line they START on.
fn join_continuations(body: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut start = 0usize;
    for (i, raw) in body.lines().enumerate() {
        let lineno = i + 1;
        if cur.is_empty() {
            start = lineno;
        }
        if let Some(stripped) = raw.strip_suffix('\\') {
            cur.push_str(stripped);
            cur.push(' ');
        } else {
            cur.push_str(raw);
            out.push((start, std::mem::take(&mut cur)));
        }
    }
    if !cur.is_empty() {
        out.push((start, cur));
    }
    out
}

/// Keep the highest-severity finding per (line, family); sort by line, then
/// severity descending for display.
fn dedup_max_per_family(mut v: Vec<ScriptFinding>) -> Vec<ScriptFinding> {
    v.sort_by(|a, b| {
        a.line
            .cmp(&b.line)
            .then((b.severity as u8).cmp(&(a.severity as u8)))
    });
    let mut out: Vec<ScriptFinding> = Vec::new();
    for f in v {
        let dup = out
            .iter()
            .any(|k| k.line == f.line && k.family == f.family);
        if !dup {
            out.push(f);
        }
    }
    out.sort_by(|a, b| {
        a.line
            .cmp(&b.line)
            .then((b.severity as u8).cmp(&(a.severity as u8)))
    });
    out
}

/// Package script score = sum of Medium-and-above finding weights across all
/// four scripts. Info findings are deliberately excluded (weight 0).
fn score_scripts(scripts: &[MaintainerScript]) -> u32 {
    scripts
        .iter()
        .flat_map(|s| s.findings.iter())
        .filter(|f| (f.severity as u8) >= (Severity::Medium as u8))
        .map(|f| f.severity.weight())
        .sum()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Advisory assembly
// ─────────────────────────────────────────────────────────────────────────────

fn build_advisories(
    setuid: &[String],
    adds_apt_source: bool,
    adds_gpg_key: bool,
    script_risk: RiskBand,
    conflicts: &[String],
    breaks: &[String],
) -> Vec<String> {
    let mut a = Vec::new();
    if !setuid.is_empty() {
        a.push(format!(
            "Installs {} setuid/setgid executable(s) — these run with elevated privileges.",
            setuid.len()
        ));
    }
    if adds_apt_source {
        a.push("Adds an APT software source — this publisher could push future updates to your system.".to_string());
    }
    if adds_gpg_key {
        a.push("Installs an APT signing key — extends trust to a new package signer.".to_string());
    }
    match script_risk {
        RiskBand::HighRisk => a.push(
            "Maintainer scripts run as root and contain HIGH-RISK patterns (see the highlighted findings below) — review them carefully before proceeding.".to_string(),
        ),
        RiskBand::Suspicious => a.push(
            "Maintainer scripts run as root and contain operations worth reviewing (see the findings below) before proceeding.".to_string(),
        ),
        RiskBand::Clean => {}
    }
    if !conflicts.is_empty() {
        a.push(format!("Declares conflicts with: {}.", conflicts.join(", ")));
    }
    if !breaks.is_empty() {
        a.push(format!("Declares it breaks: {}.", breaks.join(", ")));
    }
    a
}

// ─────────────────────────────────────────────────────────────────────────────
// Small helpers
// ─────────────────────────────────────────────────────────────────────────────

fn run_stdout(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

fn unique_tmp_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("ghost-sentri-inspect-{}-{}", std::process::id(), nanos))
}

/// Removes the temp control-extraction dir when the inspection returns.
struct TmpGuard(PathBuf);
impl Drop for TmpGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
