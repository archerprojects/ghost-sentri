// gui/src/installer.rs — v1.1.0 — Thursday 12 November 2026
// Installer UI — UNPRIVILEGED. Drives the privileged worker.
//
// Split flow (architecture B):
//   1. REVIEW screen (P4) — unprivileged. Inspects the .deb (dpkg-deb / apt -s),
//      shows metadata, the install action (install/upgrade/downgrade/reinstall),
//      the packages apt will pull, a flagged file manifest, and the four
//      maintainer scripts verbatim. Carries the three choices:
//        Cancel / Install Without Scan / Scan First.
//      The chosen action is remembered and dispatched once the worker is Ready,
//      so there is still exactly ONE polkit prompt and no second dialog.
//   2. The chosen non-cancel action -> pkexec the headless worker. The pkexec
//      IS the polkit prompt; the worker then holds root for the sequence.
//   3. Worker emits Ready -> the remembered Choice is sent over stdin.
//   4. Worker streams WorkerOutbound (scan/threat/install progress) over stdout;
//      this GUI renders it. A threat prompt sends a ThreatDecision back.
//   5. Worker emits Done -> result dialog -> process::exit with the mapped code.
//
//   apt-hook   => evaluate-only          (worker approves; apt performs the install).
//   standalone => evaluate-and-install   (worker performs the install).
//
// Exit code (read by the daemon for the apt-hook decision):
//   0 = approved / installed   1 = cancelled / blocked / failed
//
// v7.0:
//  - P4 GDebi-replacement review screen replaces the old plain elevation dialog
//    and folds in the old three-choice dialog. Inspection is unprivileged and
//    runs before elevation; the user authorises root only after seeing the
//    package contents. Hard block (Cancel only) on arch mismatch or apt-reported
//    unsatisfiable deps; every other finding is advisory.
//
// v6.2:
//  - One-shot response guard on every dialog. In GTK4, dialog.close() RE-EMITS
//    `response` with DeleteEvent; without the guard the second emission fell
//    through to the catch-all and process::exit(1) killed the whole flow.
// v6.1:
//  - worker_path(): installed location first, dev-tree sibling fallback.
//  - EOF sentinel from the stdout reader so a worker that dies without a
//    terminal message surfaces an error instead of hanging.
//  - Hidden owner window as a transient parent for all dialogs.

use ghost_sentri_core::deb_inspect::{DebReport, RiskBand, Severity};
use ghost_sentri_core::protocol::{from_line, to_line, InterceptChoice, WorkerInbound, WorkerOutbound};
use gtk::glib;
use relm4::adw;
use adw::prelude::*;
use relm4::gtk;
use relm4::RelmWidgetExt;
use std::cell::{Cell, RefCell};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::rc::Rc;
use std::sync::mpsc::Receiver;

const LAYOUT_CSS: &str = "
    progressbar > trough > progress {
        background-color: #4b8bd4;
        background-image: linear-gradient(to bottom, #6baad4, #3d7ab5);
        border: 1px solid #1f3a6e;
        border-radius: 3px;
    }
    .scan-log { font-family: 'Monospace'; font-size: 0.82rem; }
    .script-body { font-family: 'Monospace'; font-size: 0.80rem; }
";

/// What the stdout reader thread hands to the GTK thread. `Eof` is sent once when
/// the worker's stdout closes — strictly after any real message.
enum WorkerMsg {
    Out(WorkerOutbound),
    Eof,
}

thread_local! {
    static WORKER_STDIN:    RefCell<Option<ChildStdin>>      = RefCell::new(None);
    static WORKER_CHILD:    RefCell<Option<Child>>           = RefCell::new(None);
    static PROGRESS_WINDOW: RefCell<Option<gtk::Window>>     = RefCell::new(None);
    static PROGRESS_BAR:    RefCell<Option<gtk::ProgressBar>>= RefCell::new(None);
    static PROGRESS_LOG:    RefCell<Option<gtk::TextBuffer>> = RefCell::new(None);
    static OWNER:           RefCell<Option<gtk::Window>>     = RefCell::new(None);
    static APT_HOOK:        RefCell<bool>                    = RefCell::new(false);
    // Set once a terminal state (Done/Error) is handled — makes the EOF sentinel a no-op.
    static WORKER_DONE:     RefCell<bool>                    = RefCell::new(false);
    // The action chosen on the review screen, dispatched when the worker is Ready.
    static PENDING_CHOICE:  RefCell<Option<InterceptChoice>> = RefCell::new(None);
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry
// ─────────────────────────────────────────────────────────────────────────────

pub fn run_installer(deb_path: PathBuf, apt_hook: bool) -> i32 {
    if gtk::init().is_err() {
        eprintln!("[installer] GTK init failed");
        return 1;
    }
    APT_HOOK.with(|c| *c.borrow_mut() = apt_hook);

    if let Some(display) = gtk::gdk::Display::default() {
        let theme = gtk::IconTheme::for_display(&display);
        theme.add_search_path("/usr/share/icons/hicolor");
        theme.add_search_path("/usr/share/icons/lean-icons");

        let css = gtk::CssProvider::new();
        css.load_from_data(LAYOUT_CSS);
        gtk::style_context_add_provider_for_display(
            &display, &css, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }

    // Unprivileged inspection up front. On failure the review screen runs in a
    // degraded mode (filename + advisory) rather than blocking the user.
    let report = ghost_sentri_core::deb_inspect::inspect(&deb_path).ok();
    show_review_window(deb_path, apt_hook, report);

    loop {
        glib::MainContext::default().iteration(true);
    }
}

/// Resolve the privileged worker binary.
///   1. Installed location (post-packaging).
///   2. Sibling of the running GUI binary (dev tree / standalone testing).
///   3. Fall back to the installed path so pkexec surfaces a clear error.
fn worker_path() -> PathBuf {
    let installed = PathBuf::from("/usr/libexec/ghost-sentri-installer");
    if installed.exists() {
        return installed;
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(sib) = exe.parent().map(|d| d.join("ghost-sentri-installer")) {
            if sib.exists() {
                return sib;
            }
        }
    }
    installed
}

/// A never-presented 1×1 window that exists only to be a transient parent for the
/// installer's dialogs. Created lazily, kept for the process lifetime.
fn owner_window() -> gtk::Window {
    OWNER.with(|c| {
        if c.borrow().is_none() {
            let w = gtk::Window::builder()
                .default_width(1)
                .default_height(1)
                .decorated(false)
                .build();
            *c.borrow_mut() = Some(w);
        }
        c.borrow().as_ref().unwrap().clone()
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 1 — REVIEW screen (P4). Unprivileged. Replaces the old elevation dialog
// and the old three-choice dialog.
// ─────────────────────────────────────────────────────────────────────────────

fn show_review_window(path: PathBuf, apt_hook: bool, report: Option<DebReport>) {
    let window = gtk::Window::builder()
        .title("Ghost Sentri — Package Review")
        .default_width(660)
        .default_height(620)
        .modal(true)
        .transient_for(&owner_window())
        .build();
    window.set_icon_name(Some("ghost-sentri"));

    let outer = gtk::Box::new(gtk::Orientation::Vertical, 12);
    outer.set_margin_all(18);

    // Header — name, version, action class.
    let name = file_name(&path);
    let header = gtk::Label::new(None);
    header.set_xalign(0.0);
    header.set_wrap(true);
    match &report {
        Some(r) => header.set_markup(&format!(
            "<big><b>{}</b></big>  <span size='small'>{}</span>",
            escape(&r.package), escape(&r.version),
        )),
        None => header.set_markup(&format!("<big><b>{}</b></big>", escape(&name))),
    }
    outer.append(&header);

    let installable = report.as_ref().map(|r| r.installable()).unwrap_or(true);

    // Hard-block banner (arch mismatch / unsatisfiable deps).
    if let Some(r) = &report {
        if !r.installable() {
            let why = if !r.arch_compatible {
                format!(
                    "This package targets architecture “{}”, which this system (“{}”) cannot install.",
                    escape(&r.architecture), escape(&r.host_arch),
                )
            } else {
                "apt reports this package's dependencies cannot be satisfied on this system.".to_string()
            };
            let banner = gtk::Label::new(None);
            banner.set_xalign(0.0);
            banner.set_wrap(true);
            banner.set_markup(&format!("<span foreground='#e35d4f'><b>Cannot install. </b>{}</span>", why));
            outer.append(&banner);
        }
    }

    // Heuristic script-risk banner. Shown only for Suspicious / HighRisk — a
    // Clean band is silence by design (the absence of a warning IS the signal;
    // banner-on-everything trains users to click through).
    if let Some(r) = &report {
        let banner_spec = match r.script_risk {
            RiskBand::HighRisk => Some((
                "#d71a23",
                "Maintainer scripts contain high-severity patterns. Review the highlighted findings below before proceeding.",
            )),
            RiskBand::Suspicious => Some((
                "#f27e3f",
                "Maintainer scripts contain patterns worth reviewing in the findings below before proceeding.",
            )),
            RiskBand::Clean => None,
        };
        if let Some((col, msg)) = banner_spec {
            let banner = gtk::Label::new(None);
            banner.set_xalign(0.0);
            banner.set_wrap(true);
            banner.set_markup(&format!(
                "<span foreground='{}'><b>Script risk: {}. </b></span>{}",
                col, r.script_risk.label(), escape(msg),
            ));
            outer.append(&banner);
        }
    }

    // Scrollable body.
    let body = gtk::Box::new(gtk::Orientation::Vertical, 14);
    if let Some(r) = &report {
        append_metadata_section(&body, r);
        append_advisories_section(&body, r);
        append_dependencies_section(&body, r);
        append_files_section(&body, r);
        append_scripts_section(&body, r);
    } else {
        let note = gtk::Label::new(Some(
            "Package inspection is unavailable (dpkg-deb could not read this file). \
             You can still proceed; Ghost Sentri's scan and apt will validate it.",
        ));
        note.set_xalign(0.0);
        note.set_wrap(true);
        body.append(&note);
    }

    let scroll = gtk::ScrolledWindow::builder().vexpand(true).child(&body).build();
    outer.append(&scroll);

    // Action row.
    let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    buttons.set_halign(gtk::Align::End);

    let cancel = gtk::Button::with_label("Cancel");
    let install_raw = gtk::Button::with_label("Install Without Scan");
    install_raw.add_css_class("destructive-action");
    let scan = gtk::Button::with_label("Scan First");
    scan.add_css_class("suggested-action");

    if !installable {
        install_raw.set_sensitive(false);
        scan.set_sensitive(false);
    }

    buttons.append(&cancel);
    buttons.append(&install_raw);
    buttons.append(&scan);
    outer.append(&buttons);

    window.set_child(Some(&outer));

    // Wiring. Guards prevent a double-fire if a click and close race.
    let guard = Rc::new(Cell::new(false));

    {
        let g = guard.clone();
        cancel.connect_clicked(move |_| {
            if g.replace(true) { return; }
            std::process::exit(1);
        });
    }
    {
        let g = guard.clone();
        let w = window.clone();
        let p = path.clone();
        install_raw.connect_clicked(move |_| {
            if g.replace(true) { return; }
            PENDING_CHOICE.with(|c| *c.borrow_mut() = Some(InterceptChoice::InstallWithoutScan));
            w.close();
            start_worker(p.clone(), apt_hook);
        });
    }
    {
        let g = guard.clone();
        let w = window.clone();
        let p = path.clone();
        scan.connect_clicked(move |_| {
            if g.replace(true) { return; }
            PENDING_CHOICE.with(|c| *c.borrow_mut() = Some(InterceptChoice::ScanThenInstall));
            w.close();
            start_worker(p.clone(), apt_hook);
        });
    }

    // Window-manager close == Cancel.
    {
        let g = guard.clone();
        window.connect_close_request(move |_| {
            if !g.replace(true) {
                std::process::exit(1);
            }
            glib::Propagation::Proceed
        });
    }

    window.present();
}

fn append_section_heading(parent: &gtk::Box, text: &str) {
    let h = gtk::Label::new(None);
    h.set_xalign(0.0);
    h.set_markup(&format!("<b>{}</b>", escape(text)));
    h.set_margin_top(4);
    parent.append(&h);
}

fn append_kv(parent: &gtk::Box, key: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    let l = gtk::Label::new(None);
    l.set_xalign(0.0);
    l.set_wrap(true);
    l.set_selectable(true);
    l.set_markup(&format!("<b>{}:</b>  {}", escape(key), escape(value)));
    parent.append(&l);
}

fn append_metadata_section(parent: &gtk::Box, r: &DebReport) {
    append_section_heading(parent, "Package");
    append_kv(parent, "Action", r.action.label());
    if let Some(installed) = &r.installed_version {
        append_kv(parent, "Installed version", installed);
    }
    append_kv(parent, "New version", &r.version);
    append_kv(parent, "Architecture", &r.architecture);
    append_kv(parent, "Maintainer", &r.maintainer);
    if let Some(modified) = &r.file_modified {
        append_kv(parent, "File last modified", modified);
    }
    if let Some(kb) = r.installed_size_kb {
        append_kv(parent, "Installed size", &human_size(kb));
    }
    if let Some(home) = &r.homepage {
        append_kv(parent, "Homepage", home);
    }
    if !r.description.is_empty() {
        append_kv(parent, "Description", &r.description);
    }
}

fn append_advisories_section(parent: &gtk::Box, r: &DebReport) {
    if r.advisories.is_empty() {
        return;
    }
    append_section_heading(parent, "Security advisories");
    for a in &r.advisories {
        let l = gtk::Label::new(None);
        l.set_xalign(0.0);
        l.set_wrap(true);
        l.set_markup(&format!("<span foreground='#f27e3f'>⚠</span>  {}", escape(a)));
        parent.append(&l);
    }
}

fn append_dependencies_section(parent: &gtk::Box, r: &DebReport) {
    append_section_heading(parent, "Dependencies");
    if !r.apt_simulation_ok {
        if let Some(note) = &r.apt_note {
            let l = gtk::Label::new(Some(note));
            l.set_xalign(0.0);
            l.set_wrap(true);
            parent.append(&l);
        }
        return;
    }
    if r.apt_pulls.is_empty() {
        let l = gtk::Label::new(Some("No additional packages required — all dependencies are already installed."));
        l.set_xalign(0.0);
        l.set_wrap(true);
        parent.append(&l);
    } else {
        let l = gtk::Label::new(None);
        l.set_xalign(0.0);
        l.set_wrap(true);
        l.set_markup(&format!(
            "apt will also install {} package(s):\n{}",
            r.apt_pulls.len(),
            escape(&r.apt_pulls.join(", ")),
        ));
        parent.append(&l);
    }
}

fn append_files_section(parent: &gtk::Box, r: &DebReport) {
    if r.flagged_files.is_empty() {
        return;
    }
    append_section_heading(parent, "Files of interest");
    for f in &r.flagged_files {
        let l = gtk::Label::new(None);
        l.set_xalign(0.0);
        l.set_wrap(true);
        l.set_selectable(true);
        l.set_markup(&format!(
            "<tt>{}</tt>  <span size='small' foreground='#888888'>— {}</span>",
            escape(&f.path), escape(&f.reason),
        ));
        parent.append(&l);
    }
}

/// Theme-token foreground for a finding severity. Info returns None — it renders
/// in default text colour, no alarm. The three alarm colours are the directive's
/// fixed semantic palette (identical in dark and light), so hardcoding them here
/// is correct: they are not surface colours.
fn severity_color(sev: Severity) -> Option<&'static str> {
    match sev {
        Severity::Critical => Some("#d71a23"), // destructive
        Severity::High => Some("#e35d4f"),     // error
        Severity::Medium => Some("#f27e3f"),   // warning
        Severity::Info => None,                // calm — default foreground
    }
}

fn append_scripts_section(parent: &gtk::Box, r: &DebReport) {
    if r.maintainer_scripts.is_empty() {
        return;
    }
    append_section_heading(parent, "Maintainer scripts (run as root)");
    let medium = Severity::Medium as u8;
    for s in &r.maintainer_scripts {
        let serious = s.findings.iter().filter(|f| (f.severity as u8) >= medium).count();
        let title = if serious > 0 {
            format!("{}  ⚠ {} finding(s)", s.name, serious)
        } else if !s.findings.is_empty() {
            format!("{}  · {} note(s)", s.name, s.findings.len())
        } else {
            s.name.clone()
        };
        let expander = gtk::Expander::new(Some(&title));
        // Auto-expand anything with a serious finding so it isn't missed.
        expander.set_expanded(serious > 0);

        let inner = gtk::Box::new(gtk::Orientation::Vertical, 6);
        inner.set_margin_all(6);

        for f in &s.findings {
            let fl = gtk::Label::new(None);
            fl.set_xalign(0.0);
            fl.set_wrap(true);
            let loc = format!("line {}", f.line);
            match severity_color(f.severity) {
                Some(col) => fl.set_markup(&format!(
                    "<span foreground='{c}'>⚠</span>  <tt>{l}</tt>  {m} \
                     <span foreground='{c}' size='small'>[{s}]</span>",
                    c = col,
                    l = escape(&loc),
                    m = escape(&f.message),
                    s = f.severity.label(),
                )),
                None => fl.set_markup(&format!(
                    "·  <tt>{l}</tt>  {m} <span size='small'>[{s}]</span>",
                    l = escape(&loc),
                    m = escape(&f.message),
                    s = f.severity.label(),
                )),
            }
            inner.append(&fl);
        }

        let view = gtk::TextView::new();
        view.set_editable(false);
        view.set_monospace(true);
        view.add_css_class("script-body");
        view.buffer().set_text(&s.body);
        let sc = gtk::ScrolledWindow::builder()
            .min_content_height(160)
            .max_content_height(280)
            .child(&view)
            .build();
        inner.append(&sc);

        expander.set_child(Some(&inner));
        parent.append(&expander);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 2 — launch the worker via pkexec, wire stdout -> GTK
// ─────────────────────────────────────────────────────────────────────────────

fn start_worker(path: PathBuf, apt_hook: bool) {
    let mode = if apt_hook { "evaluate-only" } else { "evaluate-and-install" };
    let worker = worker_path();

    let mut child = match Command::new("pkexec")
        .arg(&worker)
        .arg(mode)
        .arg(path.to_string_lossy().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            show_result_dialog(false, &format!(
                "Could not start the privileged helper ({}): {e}",
                worker.display()
            ));
            return;
        }
    };

    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    WORKER_STDIN.with(|c| *c.borrow_mut() = stdin);

    // Reader thread: worker stdout -> mpsc -> GTK timeout. Emits Eof when the
    // stream closes so the GUI can detect a worker that died without finishing.
    let (tx, rx) = std::sync::mpsc::channel::<WorkerMsg>();
    if let Some(out) = stdout {
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if let Ok(msg) = from_line::<WorkerOutbound>(&line) {
                    if tx.send(WorkerMsg::Out(msg)).is_err() { return; }
                }
            }
            let _ = tx.send(WorkerMsg::Eof);
        });
    } else {
        let _ = tx.send(WorkerMsg::Eof);
    }
    WORKER_CHILD.with(|c| *c.borrow_mut() = Some(child));

    // Drain worker events on the GTK thread.
    let rx = Rc::new(RefCell::new(rx));
    glib::timeout_add_local(std::time::Duration::from_millis(50), move || {
        drain_worker(&rx.borrow());
        glib::ControlFlow::Continue
    });
}

fn drain_worker(rx: &Receiver<WorkerMsg>) {
    while let Ok(m) = rx.try_recv() {
        match m {
            WorkerMsg::Out(msg) => handle_worker_msg(msg),
            WorkerMsg::Eof => {
                let done = WORKER_DONE.with(|c| *c.borrow());
                if !done {
                    WORKER_DONE.with(|c| *c.borrow_mut() = true);
                    close_progress_window();
                    show_result_dialog(false,
                        "The privileged helper exited unexpectedly before completing. \
                         It may not be installed at /usr/libexec/ghost-sentri-installer, \
                         or authorization was declined.");
                }
            }
        }
    }
}

fn handle_worker_msg(msg: WorkerOutbound) {
    match msg {
        // Worker is elevated and waiting. Dispatch the action chosen on review.
        WorkerOutbound::Ready => send_pending_choice(),
        WorkerOutbound::ScanStarted => show_progress_window("Scanning package…"),
        WorkerOutbound::ScanProgress { message } => append_progress(&message),
        WorkerOutbound::ScanClean => append_progress("Scan clean."),
        WorkerOutbound::ScanError { message } => append_progress(&format!("Scan error: {message}")),
        WorkerOutbound::ScanThreat { name, plain_english } => show_threat_dialog(&name, &plain_english),
        WorkerOutbound::InstallProgress { message } => {
            ensure_progress_window("Installing…");
            append_progress(&message);
        }
        WorkerOutbound::Done { approved, installed, message } => {
            WORKER_DONE.with(|c| *c.borrow_mut() = true);
            let apt_hook = APT_HOOK.with(|c| *c.borrow());
            let ok = if apt_hook { approved } else { installed };
            close_progress_window();
            show_result_dialog(ok, &message);
        }
        WorkerOutbound::Error { message } => {
            WORKER_DONE.with(|c| *c.borrow_mut() = true);
            close_progress_window();
            show_result_dialog(false, &message);
        }
    }
}

/// Send the action chosen on the review screen. If none was recorded (should not
/// happen), cancel safely.
fn send_pending_choice() {
    let choice = PENDING_CHOICE.with(|c| c.borrow_mut().take());
    match choice {
        Some(c) => {
            send_to_worker(&WorkerInbound::Choice { choice: c });
            if matches!(c, InterceptChoice::Cancel) {
                std::process::exit(1);
            }
        }
        None => {
            send_to_worker(&WorkerInbound::Choice { choice: InterceptChoice::Cancel });
            std::process::exit(1);
        }
    }
}

fn send_to_worker(msg: &WorkerInbound) {
    WORKER_STDIN.with(|c| {
        if let Some(stdin) = c.borrow_mut().as_mut() {
            if let Ok(line) = to_line(msg) {
                let _ = stdin.write_all(line.as_bytes());
                let _ = stdin.flush();
            }
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Threat prompt
// ─────────────────────────────────────────────────────────────────────────────

fn show_threat_dialog(name: &str, plain_english: &str) {
    let dialog = adw::AlertDialog::new(
        Some(&format!("Threat detected: {name}")),
        Some(plain_english),
    );
    dialog.add_response("abort", "Abort");
    dialog.add_response("install", "Install Anyway");
    dialog.set_response_appearance("install", adw::ResponseAppearance::Destructive);
    dialog.set_default_response(Some("abort"));
    dialog.set_close_response("abort");

    let guard = Rc::new(Cell::new(false));
    dialog.connect_response(None, move |_d, resp| {
        if guard.replace(true) { return; }
        let install_anyway = resp == "install";
        send_to_worker(&WorkerInbound::ThreatDecision { install_anyway });
        if !install_anyway {
            std::process::exit(1);
        }
    });
    dialog.present(Some(&owner_window()));
}

// ─────────────────────────────────────────────────────────────────────────────
// Progress window
// ─────────────────────────────────────────────────────────────────────────────

fn ensure_progress_window(title: &str) {
    let exists = PROGRESS_WINDOW.with(|c| c.borrow().is_some());
    if !exists {
        show_progress_window(title);
    }
}

fn show_progress_window(title: &str) {
    let window = gtk::Window::builder()
        .title("Ghost Sentri")
        .default_width(460)
        .default_height(220)
        .modal(true)
        .transient_for(&owner_window())
        .build();

    let vbox = gtk::Box::new(gtk::Orientation::Vertical, 10);
    vbox.set_margin_all(16);

    let label = gtk::Label::new(Some(title));
    label.set_halign(gtk::Align::Start);
    vbox.append(&label);

    let bar = gtk::ProgressBar::new();
    bar.set_pulse_step(0.1);
    vbox.append(&bar);

    let log = gtk::TextView::new();
    log.set_editable(false);
    log.add_css_class("scan-log");
    let buf = log.buffer();
    let scroll = gtk::ScrolledWindow::builder().vexpand(true).child(&log).build();
    vbox.append(&scroll);

    window.set_child(Some(&vbox));
    window.present();

    let bar_c = bar.clone();
    glib::timeout_add_local(std::time::Duration::from_millis(90), move || {
        bar_c.pulse();
        glib::ControlFlow::Continue
    });

    PROGRESS_WINDOW.with(|c| *c.borrow_mut() = Some(window));
    PROGRESS_BAR.with(|c| *c.borrow_mut() = Some(bar));
    PROGRESS_LOG.with(|c| *c.borrow_mut() = Some(buf));
}

fn append_progress(text: &str) {
    PROGRESS_LOG.with(|c| {
        if let Some(buf) = c.borrow().as_ref() {
            let mut end = buf.end_iter();
            if buf.char_count() > 0 { buf.insert(&mut end, "\n"); }
            buf.insert(&mut end, text);
        }
    });
}

fn close_progress_window() {
    PROGRESS_WINDOW.with(|c| {
        if let Some(w) = c.borrow_mut().take() { w.close(); }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Result dialog
// ─────────────────────────────────────────────────────────────────────────────

fn show_result_dialog(success: bool, message: &str) {
    let dialog = adw::AlertDialog::new(
        Some(if success { "Installation Complete" } else { "Installation Failed" }),
        Some(message),
    );
    dialog.add_response("close", "Close");
    dialog.set_default_response(Some("close"));
    dialog.set_close_response("close");

    let guard = Rc::new(Cell::new(false));
    dialog.connect_response(None, move |_d, _| {
        if guard.replace(true) { return; }
        std::process::exit(if success { 0 } else { 1 });
    });
    dialog.present(Some(&owner_window()));
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn file_name(path: &std::path::Path) -> String {
    path.file_name().and_then(|n| n.to_str()).unwrap_or("package").to_string()
}

/// Escape text destined for Pango markup labels.
fn escape(s: &str) -> String {
    glib::markup_escape_text(s).to_string()
}

fn human_size(kb: u64) -> String {
    if kb >= 1024 {
        format!("{:.1} MB", kb as f64 / 1024.0)
    } else {
        format!("{} KB", kb)
    }
}
