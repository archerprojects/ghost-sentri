// ghost-sentri-dpkg-shim — v1.1.0 — Thursday 12 November 2026
// PATH shim installed at /usr/local/sbin/dpkg (ahead of /usr/bin in sudoers
// secure_path). It catches LOCAL .deb installs that bypass apt's
// Pre-Install-Pkgs hook — notably `nala install ./x.deb` and direct
// `dpkg -i x.deb`, both of which resolve `dpkg` by name and so hit us first.
//
// It does NOT re-implement scanning or review. It collects the .deb operands and
// hands them to the proven apt-hook path — `ghost-sentri-daemon --apt-hook`, the
// exact program apt drives, fed the same newline-separated paths on stdin — then
// maps that program's exit code: 0 → run dpkg, non-zero → block.
//
// SAFETY (the whole point): every path that is NOT an explicit Ghost Sentri block
// ends in exec(/usr/bin/dpkg). A bypass marker, no .deb on the line, a parse miss,
// a missing/unrunnable hook binary — all fall through to the real dpkg. The ONLY
// thing that stops dpkg is the hook returning a block. exec uses the absolute
// /usr/bin/dpkg, which cannot re-enter this shim, so there is no recursion.

use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

const REAL_DPKG: &str = "/usr/bin/dpkg";
const HOOK_BIN: &str = "/usr/libexec/ghost-sentri-daemon";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // 1) Ghost Sentri's own worker sets this on its installs — never self-intercept.
    if std::env::var("GS_HOOK_BYPASS").is_ok() {
        exec_real_dpkg(&args);
    }

    // 2) Only an install action carries a .deb to scan. Everything else (configure,
    //    remove, query, status-fd churn, …) passes straight through.
    let debs = deb_targets(&args);
    if debs.is_empty() {
        exec_real_dpkg(&args);
    }

    // 3) Scan + review via the existing apt-hook path. Fail OPEN on any inability
    //    to run it; block ONLY on an explicit non-zero (a Ghost Sentri verdict).
    match run_hook(&debs) {
        HookOutcome::Block => std::process::exit(1), // do NOT run dpkg
        HookOutcome::Proceed | HookOutcome::FailOpen => exec_real_dpkg(&args),
    }
}

enum HookOutcome {
    Proceed,
    Block,
    FailOpen,
}

/// `.deb` operands on an INSTALL action. Conservative on purpose: only existing
/// files ending in `.deb`, and only when an install/unpack action is present.
/// This sidesteps re-implementing dpkg's option parser — e.g. it will not mistake
/// the `69` in `--status-fd 69` for a package, and it ignores non-install actions
/// entirely.
fn deb_targets(args: &[String]) -> Vec<String> {
    let install_action = args.iter().any(|a| {
        matches!(a.as_str(), "-i" | "--install" | "--unpack" | "--auto-deconfigure")
            || a.starts_with("--install")
            || a.starts_with("--unpack")
    });
    if !install_action {
        return vec![];
    }
    args.iter()
        .filter(|a| a.ends_with(".deb") && Path::new(a).is_file())
        .cloned()
        .collect()
}

/// Feed the .deb paths to `ghost-sentri-daemon --apt-hook` (the same stdin format
/// apt uses) and map its exit code. Any failure to launch it → FailOpen, so a
/// missing or broken monitor never breaks dpkg.
fn run_hook(debs: &[String]) -> HookOutcome {
    if !Path::new(HOOK_BIN).exists() {
        return HookOutcome::FailOpen;
    }
    let mut child = match Command::new(HOOK_BIN)
        .arg("--apt-hook")
        // The hook prints a scan indicator; tell it to use a static line, not an
        // animated spinner, since the frontend that invoked us (nala) draws its
        // own live progress bar and the two would fight the cursor.
        .env("GS_NO_SPINNER", "1")
        .stdin(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return HookOutcome::FailOpen,
    };
    if let Some(mut stdin) = child.stdin.take() {
        let mut payload = debs.join("\n");
        payload.push('\n');
        let _ = stdin.write_all(payload.as_bytes());
        // stdin drops here → EOF, so the hook stops reading paths.
    }
    match child.wait() {
        Ok(s) if s.success() => HookOutcome::Proceed, // exit 0 → allow
        Ok(_) => HookOutcome::Block,                  // non-zero → Ghost Sentri block
        Err(_) => HookOutcome::FailOpen,
    }
}

/// Replace this process with the real dpkg, argv preserved. Absolute path → can
/// never re-enter the shim. Returns only if exec fails, in which case we report
/// and exit non-zero rather than silently doing nothing.
fn exec_real_dpkg(args: &[String]) -> ! {
    let err = Command::new(REAL_DPKG).args(args).exec();
    eprintln!("ghost-sentri-dpkg-shim: cannot exec {REAL_DPKG}: {err}");
    std::process::exit(2);
}
