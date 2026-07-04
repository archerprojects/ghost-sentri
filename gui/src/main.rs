// gui/src/main.rs
// On-demand GTK4/libadwaita dashboard. Tabs: Dashboard, Scan, Quarantine, Settings, Help.
// Dashboard is a read-only situation report (install-handler / monitor status,
// definition freshness, memory, event log). Settings holds the controls: the
// staged monitor toggle grid (Confirm Selections runs the root --apply via pkexec),
// the definition-update button, and info blocks.
// --check-definitions arg: stat .cvd mtime, push DefinitionStatus to the daemon.
// GDebi-style progress windows with Details expander. Lean blue progress bar via
// app-level CSS. adw::init() before RelmApp::new().


mod control;
mod installer;

use chrono::Local;
use ghost_sentri_core::clam::{DefinitionStatus, ScanResult, SystemClamBackend};
use ghost_sentri_core::config::Config;
use ghost_sentri_core::protocol::{ControlEvent, ControlRequest};
use ghost_sentri_core::quarantine::QuarantineRecord;
use gtk::gio::prelude::ApplicationExt;
use relm4::adw::prelude::*;
use relm4::gtk::glib;
use relm4::prelude::*;
use relm4::{adw, gtk};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::mpsc;

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

const LAYOUT_CSS: &str = "
    .log-view {
        font-family: 'Monospace';
        font-size: 0.85rem;
    }
    .scan-log {
        font-family: 'Monospace';
        font-size: 0.82rem;
    }
    progressbar > trough > progress {
        background-color: #4b8bd4;
        background-image: linear-gradient(to bottom, #6baad4, #3d7ab5);
        border: 1px solid #1f3a6e;
        border-radius: 3px;
    }
    progressbar > trough > progress:hover {
        background-color: #3d7ab5;
        background-image: linear-gradient(to bottom, #5a9fd4, #2d5a9e);
    }
    button.scan-on {
        background-color: #33aa33;
        background-image: linear-gradient(to bottom, #3cbf3c, #2c922c);
        color: #ffffff;
        font-weight: bold;
        padding: 10px 18px;
        border: 1px solid #1f5f1f;
        border-radius: 4px;
    }
    button.scan-on:hover {
        background-image: linear-gradient(to bottom, #45cf45, #339a33);
    }
    button.scan-off {
        background-color: #cc3333;
        background-image: linear-gradient(to bottom, #d94c4c, #b22a2a);
        color: #ffffff;
        font-weight: bold;
        padding: 10px 18px;
        border: 1px solid #7a1f1f;
        border-radius: 4px;
    }
    button.scan-off:hover {
        background-image: linear-gradient(to bottom, #e15a5a, #c23030);
    }
";

// ── Log buffer ────────────────────────────────────────────────────────────────

thread_local! {
    static MAIN_LOG_BUF: std::cell::RefCell<Option<gtk::TextBuffer>> =
        std::cell::RefCell::new(None);
    static MAIN_LOG_SCROLL: std::cell::RefCell<Option<gtk::ScrolledWindow>> =
        std::cell::RefCell::new(None);
}

fn append_log(text: &str) {
    MAIN_LOG_BUF.with(|cell| {
        if let Some(buf) = cell.borrow().as_ref() {
            let mut end = buf.end_iter();
            if buf.char_count() > 0 { buf.insert(&mut end, "\n"); }
            buf.insert(&mut end, text);
        }
    });
    MAIN_LOG_SCROLL.with(|cell| {
        if let Some(scroll) = cell.borrow().as_ref() {
            let adj = scroll.vadjustment();
            glib::idle_add_local_once(move || {
                adj.set_value(adj.upper() - adj.page_size());
            });
        }
    });
}

thread_local! {
    static CONFIRM_BTN: std::cell::RefCell<Option<gtk::Button>> = std::cell::RefCell::new(None);
    static DEFS_DOT:    std::cell::RefCell<Option<gtk::Label>>  = std::cell::RefCell::new(None);
    static DEFS_STATE:  std::cell::RefCell<Option<gtk::Label>>  = std::cell::RefCell::new(None);
}

/// Confirm Selections is active only when something is staged.
fn set_confirm_sensitive(pending: bool) {
    CONFIRM_BTN.with(|c| { if let Some(b) = c.borrow().as_ref() { b.set_sensitive(pending); } });
}

/// Render the Virus Definitions status row. green = current, red = stale,
/// blue = staged for update on the next Confirm.
fn update_defs_row(stale: bool, pending: bool) {
    let (colour, markup) = if pending {
        ("#4b8bd4", "<span foreground='#4b8bd4'>[UPDATE PENDING]</span>")
    } else if stale {
        ("#cc3333", "<span foreground='#cc3333'>[OUTDATED]</span>")
    } else {
        ("#33aa33", "<span foreground='#33aa33'>[CURRENT]</span>")
    };
    DEFS_DOT.with(|c| { if let Some(l) = c.borrow().as_ref() {
        l.set_markup(&format!("<span foreground='{}'>⬤</span>", colour)); } });
    DEFS_STATE.with(|c| { if let Some(l) = c.borrow().as_ref() { l.set_markup(markup); } });
}

// ── Definition update progress window ────────────────────────────────────────

thread_local! {
    static DEF_UPDATE_WINDOW: std::cell::RefCell<Option<gtk::Window>> =
        std::cell::RefCell::new(None);
    static DEF_UPDATE_BAR: std::cell::RefCell<Option<gtk::ProgressBar>> =
        std::cell::RefCell::new(None);
    static DEF_UPDATE_LABEL: std::cell::RefCell<Option<gtk::Label>> =
        std::cell::RefCell::new(None);
    static DEF_UPDATE_LOG: std::cell::RefCell<Option<gtk::TextBuffer>> =
        std::cell::RefCell::new(None);
    static DEF_UPDATE_PULSE: std::cell::RefCell<Option<glib::SourceId>> =
        std::cell::RefCell::new(None);
}

fn show_def_update_progress_dialog() {
    let window = gtk::Window::builder()
        .title("Ghost Sentri — Updating Definitions")
        .default_width(520)
        .default_height(340)
        .deletable(false)
        .resizable(true)
        .build();

    let outer = gtk::Box::new(gtk::Orientation::Vertical, 12);
    outer.set_margin_all(20);

    let row = gtk::Box::new(gtk::Orientation::Horizontal, 16);
    row.set_valign(gtk::Align::Start);

    let icon = gtk::Image::from_icon_name("ghost-sentri");
    icon.set_pixel_size(48);
    icon.set_valign(gtk::Align::Start);
    icon.set_margin_top(4);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 8);
    content.set_hexpand(true);

    let heading = gtk::Label::new(None);
    heading.set_markup("<b>Updating virus definitions…</b>");
    heading.set_halign(gtk::Align::Start);

    let bar = gtk::ProgressBar::new();
    bar.set_pulse_step(0.04);
    bar.set_show_text(false);

    let status = gtk::Label::new(Some("Starting freshclam…"));
    status.set_halign(gtk::Align::Start);

    content.append(&heading);
    content.append(&bar);
    content.append(&status);
    row.append(&icon);
    row.append(&content);
    outer.append(&row);

    let expander = gtk::Expander::new(Some("Details"));
    let scroll = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .height_request(140)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::Automatic)
        .build();
    let text_view = gtk::TextView::new();
    text_view.set_editable(false);
    text_view.set_monospace(true);
    text_view.set_wrap_mode(gtk::WrapMode::WordChar);
    text_view.set_left_margin(6);
    text_view.set_top_margin(4);
    text_view.add_css_class("scan-log");
    let log_buf = text_view.buffer();
    scroll.set_child(Some(&text_view));
    expander.set_child(Some(&scroll));
    outer.append(&expander);

    window.set_child(Some(&outer));

    DEF_UPDATE_BAR.with(|cell| { *cell.borrow_mut() = Some(bar.clone()); });
    DEF_UPDATE_LABEL.with(|cell| { *cell.borrow_mut() = Some(status); });
    DEF_UPDATE_WINDOW.with(|cell| { *cell.borrow_mut() = Some(window.clone()); });
    DEF_UPDATE_LOG.with(|cell| { *cell.borrow_mut() = Some(log_buf); });

    let source_id = glib::timeout_add_local(std::time::Duration::from_millis(80), move || {
        DEF_UPDATE_BAR.with(|cell| {
            if let Some(b) = cell.borrow().as_ref() { b.pulse(); }
        });
        glib::ControlFlow::Continue
    });
    DEF_UPDATE_PULSE.with(|cell| { *cell.borrow_mut() = Some(source_id); });

    window.present();
}

fn dismiss_def_update_dialog() {
    DEF_UPDATE_PULSE.with(|cell| {
        if let Some(id) = cell.borrow_mut().take() { id.remove(); }
    });
    DEF_UPDATE_BAR.with(|cell|   { *cell.borrow_mut() = None; });
    DEF_UPDATE_LABEL.with(|cell| { *cell.borrow_mut() = None; });
    DEF_UPDATE_LOG.with(|cell|   { *cell.borrow_mut() = None; });
    DEF_UPDATE_WINDOW.with(|cell| {
        if let Some(w) = cell.borrow_mut().take() { w.close(); }
    });
}


// ─────────────────────────────────────────────────────────────────────────────
// Monitor kinds — user-toggled backend monitors
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MonitorKind {
    PackagedApps,   // APT hook + MIME handler (.deb, .AppImage)
    FlatpakApps,    // Flatpak bundle intercept
    WineWindows,    // Wine .exe/.msi intercept
    TerminalBuilds, // Shell wrapper (pip, npm, cargo, make, etc)
    Snap,           // Snap — not yet built
}

impl MonitorKind {
    fn label(&self) -> &'static str {
        match self {
            MonitorKind::PackagedApps   => "Packaged Apps",
            MonitorKind::FlatpakApps    => "Flatpak Apps",
            MonitorKind::WineWindows    => "Wine / Windows",
            MonitorKind::TerminalBuilds => "Terminal Builds",
            MonitorKind::Snap           => "Snap",
        }
    }

    #[allow(dead_code)] // monitor build-state check — wired into the bulk view later
    fn is_built(&self) -> bool { true } // every monitor is built

    /// Stable backend id used on the control socket (matches daemon BackendKind::id()).
    fn backend_id(&self) -> &'static str {
        match self {
            MonitorKind::PackagedApps   => "apt",
            MonitorKind::FlatpakApps    => "flatpak",
            MonitorKind::WineWindows    => "wine",
            MonitorKind::TerminalBuilds => "source",
            MonitorKind::Snap           => "snap",
        }
    }

    fn from_backend_id(id: &str) -> Option<MonitorKind> {
        Some(match id {
            "apt"     => MonitorKind::PackagedApps,
            "flatpak" => MonitorKind::FlatpakApps,
            "wine"    => MonitorKind::WineWindows,
            "source"  => MonitorKind::TerminalBuilds,
            "snap"    => MonitorKind::Snap,
            _ => return None,
        })
    }

    fn all() -> Vec<MonitorKind> {
        vec![
            MonitorKind::PackagedApps,
            MonitorKind::FlatpakApps,
            MonitorKind::WineWindows,
            MonitorKind::TerminalBuilds,
            MonitorKind::Snap,
        ]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Live PSS memory reading from /proc/self/smaps_rollup
// ─────────────────────────────────────────────────────────────────────────────

/// This process's private (unshared) resident memory in kB —
/// `Private_Clean + Private_Dirty` from smaps_rollup. This is the figure the
/// system monitor's memory column reports: it excludes shared-library pages
/// entirely (PSS counts a fair share of them and reads ~2x higher; VmRSS counts
/// them in full and reads ~3x higher). Falls back to VmRSS if the kernel lacks
/// smaps_rollup.
fn read_pss_kb() -> u64 {
    if let Ok(rollup) = std::fs::read_to_string("/proc/self/smaps_rollup") {
        let mut sum = 0u64;
        let mut found = false;
        for l in rollup.lines() {
            for key in ["Private_Clean:", "Private_Dirty:"] {
                if let Some(v) = l.strip_prefix(key)
                    .and_then(|v| v.split_whitespace().next())
                    .and_then(|n| n.parse::<u64>().ok())
                {
                    sum += v;
                    found = true;
                }
            }
        }
        if found {
            return sum;
        }
    }
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:").and_then(|v| v.split_whitespace().next()).and_then(|n| n.parse().ok()))
        .unwrap_or(0)
}

thread_local! {
    /// Latest daemon-reported resident memory (kB), from snapshot / ResidentMemory.
    static DAEMON_RESIDENT_KB: std::cell::Cell<u64> = std::cell::Cell::new(0);
}

/// Two independent readouts (no sum): the GUI's own PSS, and the daemon's.
fn memory_overhead_text() -> String {
    let gui_mb = read_pss_kb() as f64 / 1024.0;
    let daemon_mb = DAEMON_RESIDENT_KB.with(|c| c.get()) as f64 / 1024.0;
    format!(
        "Dashboard memory overhead: {:.0} MB\n\
         Tray Resident Daemon memory overhead: {:.1} MB\n\
         Refreshes every 300 sec. — protection stays active when dashboard closes",
        gui_mb, daemon_mb
    )
}

// ── Monitor strip thread-local widgets ───────────────────────────────────────

thread_local! {
    static MONITOR_MEMORY_LABEL: std::cell::RefCell<Option<gtk::Label>> =
        std::cell::RefCell::new(None);
    static MONITOR_WIDGETS: std::cell::RefCell<
        std::collections::HashMap<String, (gtk::Label, gtk::Label)>
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}


fn update_monitor_widget(label: &str, active: bool) {
    MONITOR_WIDGETS.with(|map| {
        if let Some((dot, state)) = map.borrow().get(label) {
            if active {
                dot.set_markup("<span foreground='#33aa33'>⬤</span>");
                state.set_markup("<span foreground='#33aa33'>[ACTIVE]</span>");
            } else {
                dot.set_markup("<span foreground='#cc3333'>⬤</span>");
                state.set_markup("<span foreground='#cc3333'>[OFF]</span>");
            }
        }
    });
}

fn update_memory_label() {
    MONITOR_MEMORY_LABEL.with(|cell| {
        if let Some(lbl) = cell.borrow().as_ref() {
            lbl.set_label(&memory_overhead_text());
        }
    });
}

// ── Dashboard situation-report widgets (read-only status lines) ───────────────

thread_local! {
    /// id → (single status label, base text) for each install-path report row.
    /// One line per path; the whole line recolours and the trailing word flips
    /// between "enabled" (green) and "disabled" (grey).
    static REPORT_ROWS: std::cell::RefCell<
        std::collections::HashMap<String, (gtk::Label, String)>
    > = std::cell::RefCell::new(std::collections::HashMap::new());
    /// Virus-definition status line on the dashboard.
    static REPORT_DEF_LABEL: std::cell::RefCell<Option<gtk::Label>> =
        std::cell::RefCell::new(None);
}

/// Render one situation-report line: green "enabled" or grey "disabled", whole
/// line coloured to match.
fn update_report_row(id: &str, enabled: bool) {
    REPORT_ROWS.with(|map| {
        if let Some((label, base)) = map.borrow().get(id) {
            let (col, word) = if enabled { ("#33aa33", "enabled") } else { ("#888888", "disabled") };
            label.set_markup(&format!(
                "<span foreground='{}'>{}  {}</span>",
                col, glib::markup_escape_text(base), word,
            ));
        }
    });
}

/// Map a daemon backend id to its report row(s). The apt monitor drives BOTH the
/// terminal apt hook and the .deb file-manager handler, so it updates two lines.
fn apply_monitor_to_report(backend_id: &str, enabled: bool) {
    match backend_id {
        "apt" => { update_report_row("deb", enabled); update_report_row("apt", enabled); }
        other => update_report_row(other, enabled),
    }
}

/// Render the dashboard virus-definition status line (version + freshness).
fn update_report_def(version: &str, age: &str, stale: bool) {
    REPORT_DEF_LABEL.with(|c| {
        if let Some(l) = c.borrow().as_ref() {
            let (col, word) = if stale { ("#cc3333", "OUTDATED") } else { ("#33aa33", "CURRENT") };
            l.set_markup(&format!(
                "Virus definitions — {}  ·  <span foreground='{}'>{}</span>  ({})",
                glib::markup_escape_text(version), col, word, glib::markup_escape_text(age),
            ));
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp:   String,
    pub message:     String,
    pub is_threat:   bool,
    pub is_override: bool,
}

impl LogEntry {
    fn new(message: String) -> Self {
        Self { timestamp: Local::now().format("%H:%M:%S").to_string(), message, is_threat: false, is_override: false }
    }
    fn threat(message: String) -> Self { Self { is_threat: true, ..Self::new(message) } }
    #[allow(dead_code)] // Install-Without-Scan override logging — wired in later
    fn override_entry(message: String) -> Self { Self { is_override: true, ..Self::new(message) } }
}

/// Dedicated multi-thread tokio runtime for the GUI's background I/O (control
/// socket, freshclam, scans). relm4 itself must NOT run inside a tokio runtime —
/// its shutdown path calls blocking_send, which panics if the calling thread is a
/// runtime thread. So `fn main()` stays plain and async work is spawned HERE,
/// on this runtime's own worker threads, off the GTK/relm4 thread.
static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();

pub(crate) fn rt() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build GUI tokio runtime")
    })
}

pub struct DashboardModel {
    sentry_active:             bool,
    log_entries:               Vec<LogEntry>,
    #[allow(dead_code)] // virus-definition freshness — surfaced in the dashboard later
    definition_status:         Option<DefinitionStatus>,
    quarantine_items:          Vec<QuarantineRecord>,
    config:                    Config,
    window:                    Option<adw::Window>,
    scan_cancel:               Option<Arc<AtomicBool>>,
    monitor_states:            HashMap<MonitorKind, bool>,
    /// Staged (uncommitted) monitor toggles — desired state, applied on Confirm.
    pending_monitors:          HashMap<MonitorKind, bool>,
    /// Whether a definition update is staged for the next Confirm.
    pending_defs:              bool,
    /// Latest known definition staleness.
    defs_stale:                bool,
    app_pss_kb:                u64,
    /// Sender for ControlRequests to the daemon (None until connected).
    control_tx:                Option<mpsc::Sender<ControlRequest>>,
}

#[derive(Debug)]
pub enum DashboardMsg {
    ControlEvent(ControlEvent),
    // Intercept
    InterceptScanNow,
    InterceptProceedWithoutScan,
    InterceptCancel,
    // Threat
    ThreatQuarantine,
    ThreatProceedWithCaution,
    ThreatProceedConfirmed,
    ThreatCancel,
    // User scan
    StartUserScan,
    ScanPath(PathBuf),
    ScanProgress { done: usize, total: usize, line: Option<String> },
    ScanComplete(PathBuf, Vec<(PathBuf, ScanResult)>),
    CancelScan,
    // Quarantine
    OpenQuarantineViewer,
    PurgeAll,
    // Install (daemon-routed — from installer.rs via socket)
    InstallProgress(String),
    InstallComplete { success: bool },
    // Definitions
    UpdateDefinitions,
    DefUpdateProgress(String),
    DefUpdateComplete(bool),
    // Settings
    ResetFirstRun,
    // Monitors
    ToggleMonitor(MonitorKind),
    MonitorToggleConfirmed(MonitorKind, bool),
    MonitorToggleDenied(String),
    ToggleDefsUpdate,
    ConfirmSelections,
    ResetSelections,
    // UI
    ToggleSentry,
    ShowWindow,
    Quit,
}

// Tray lives in the daemon now (it is the always-resident process).

// ── File collection ───────────────────────────────────────────────────────────

fn collect_files_recursive(path: &Path, files: &mut Vec<PathBuf>) {
    if path.is_file() {
        files.push(path.to_path_buf());
    } else if path.is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                collect_files_recursive(&entry.path(), files);
            }
        }
    }
}

// ── Component ─────────────────────────────────────────────────────────────────

#[relm4::component(pub)]
impl SimpleComponent for DashboardModel {
    type Init  = Config;
    type Input = DashboardMsg;
    type Output = ();

    view! {
        #[name = "main_window"]
        adw::Window {
            set_title: Some("Ghost Sentri"),
            set_default_size: (820, 700),

            #[wrap(Some)]
            set_content = &gtk::Box {
                set_orientation: gtk::Orientation::Vertical,

                #[name = "header_bar"]
                adw::HeaderBar {
                    #[wrap(Some)]
                    set_title_widget = &gtk::Label {
                        set_label: "Ghost Sentri",
                    },
                },

                gtk::Box {
                    set_orientation: gtk::Orientation::Horizontal,
                    set_spacing: 12,
                    set_margin_start: 12,
                    set_margin_end: 12,
                    set_margin_top: 6,
                    set_margin_bottom: 6,

                    gtk::Label {
                        #[watch]
                        set_label: &format!(
                            "Sentry: {}",
                            if model.sentry_active { "Active" } else { "Suspended" }
                        ),
                    },
                },

                gtk::Separator { set_orientation: gtk::Orientation::Horizontal },

                #[name = "notebook"]
                gtk::Notebook {
                    set_vexpand: true,
                    set_tab_pos: gtk::PositionType::Top,
                },

                gtk::Separator { set_orientation: gtk::Orientation::Horizontal },

                gtk::Box {
                    set_orientation: gtk::Orientation::Horizontal,
                    set_spacing: 14,
                    set_margin_all: 10,
                    set_valign: gtk::Align::Center,

                    gtk::Button {
                        #[watch]
                        set_label: &if model.sentry_active {
                            "Install Scans Active".to_string()
                        } else {
                            "Install Scans Suspended".to_string()
                        },
                        #[watch]
                        set_css_classes: &[if model.sentry_active { "scan-on" } else { "scan-off" }],
                        set_size_request: (260, 56),
                        connect_clicked => DashboardMsg::ToggleSentry,
                    },

                    gtk::Label {
                        set_wrap: true,
                        set_xalign: 0.0,
                        add_css_class: "dim-label",
                        set_label: "Green = install scanning enabled · Red = install scanning temporarily disabled (this session)",
                    },
                },
            }
        }
    }

    fn init(config: Self::Init, root: Self::Root, sender: ComponentSender<Self>) -> ComponentParts<Self> {
        let stored_window = root.clone();

        // On-demand GUI: exits when the window closes. The resident daemon is a
        // separate process, so no application-hold is needed (this also removes
        // the old Box::leak hold-guard hack).

        let css = gtk::CssProvider::new();
        css.load_from_data(LAYOUT_CSS);
        gtk::style_context_add_provider_for_display(
            &gtk::gdk::Display::default().expect("no display"),
            &css,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );

        stored_window.connect_close_request(|_| {
            relm4::main_application().quit();
            glib::Propagation::Proceed
        });

        // Connect to the resident daemon's control socket. The dashboard is a
        // viewer/controller; the daemon owns state and the tray.
        let control_tx = control::connect(
            config.sentry.control_socket_path.clone(),
            sender.clone(),
        );

        let model = DashboardModel {
            sentry_active:             true,
            log_entries:               vec![LogEntry::new(format!("Ghost Sentri v{} — initialising…", APP_VERSION))],
            definition_status:         None,
            quarantine_items:          vec![],
            config: config.clone(),
            window:                    Some(stored_window),
            scan_cancel:               None,
            monitor_states:            monitor_states_from_config(&config),
            app_pss_kb:                read_pss_kb(),
            control_tx:                Some(control_tx),
            pending_monitors:          HashMap::new(),
            pending_defs:              false,
            defs_stale:                false,
        };

        let widgets = view_output!();

        // ── Tab: Dashboard — situation report (read-only) ─────────────────────
        // Status lines reflect the daemon's machine-policy snapshot (apt hook
        // present, monitors enabled). The controls that CHANGE these live on the
        // Settings tab; this tab only reports.
        let report_frame = gtk::Frame::builder()
            .margin_start(8).margin_end(8).margin_top(8).margin_bottom(0)
            .build();
        let report_outer = gtk::Box::new(gtk::Orientation::Vertical, 6);
        report_outer.set_margin_all(10);

        let report_title = gtk::Label::new(None);
        report_title.set_markup("<b>SYSTEM STATUS</b>");
        report_title.set_halign(gtk::Align::Start);
        report_outer.append(&report_title);

        // Two columns under SYSTEM STATUS: install handlers on the left, install
        // monitors on the right. Each line is a single recolouring label (green
        // "enabled" / grey "disabled") held in REPORT_ROWS, so the live-update
        // path (apply_monitor_to_report → update_report_row) is unchanged.
        let handler_rows: [(&str, &str); 2] = [
            ("deb", ".deb install handler"),
            ("apt", "apt install handler"),
        ];
        let monitor_rows: [(&str, &str); 4] = [
            ("flatpak", "Flatpak monitor"),
            ("snap",    "Snap monitor"),
            ("wine",    "Wine / Windows monitor"),
            ("source",  "Terminal Builds monitor"),
        ];

        let build_col = |heading: &str, rows: &[(&str, &str)]| -> gtk::Box {
            let col = gtk::Box::new(gtk::Orientation::Vertical, 4);
            col.set_valign(gtk::Align::Start);
            let head = gtk::Label::new(None);
            head.set_markup(&format!(
                "<span foreground='#9a9a9a' size='small' weight='bold'>{}</span>",
                glib::markup_escape_text(heading),
            ));
            head.set_halign(gtk::Align::Start);
            head.set_margin_bottom(2);
            col.append(&head);
            for (id, label_text) in rows.iter() {
                let line = gtk::Label::new(None);
                line.set_halign(gtk::Align::Start);
                line.set_xalign(0.0);
                line.set_markup(&format!(
                    "<span foreground='#888888'>{}  …</span>",
                    glib::markup_escape_text(label_text),
                ));
                col.append(&line);
                REPORT_ROWS.with(|m| { m.borrow_mut().insert(id.to_string(), (line, label_text.to_string())); });
            }
            col
        };

        let report_cols = gtk::Box::new(gtk::Orientation::Horizontal, 40);
        report_cols.set_margin_top(4);
        let handler_col = build_col("Install Handler Status", &handler_rows);
        handler_col.set_size_request(260, -1);
        report_cols.append(&handler_col);
        report_cols.append(&build_col("Install Monitor Status", &monitor_rows));
        report_outer.append(&report_cols);

        // Seed from whatever state we already have; the daemon snapshot refreshes
        // it on connect.
        apply_monitor_to_report("apt",     *model.monitor_states.get(&MonitorKind::PackagedApps).unwrap_or(&false));
        apply_monitor_to_report("flatpak", *model.monitor_states.get(&MonitorKind::FlatpakApps).unwrap_or(&false));
        apply_monitor_to_report("wine",    *model.monitor_states.get(&MonitorKind::WineWindows).unwrap_or(&false));
        apply_monitor_to_report("source",  *model.monitor_states.get(&MonitorKind::TerminalBuilds).unwrap_or(&false));
        apply_monitor_to_report("snap",    *model.monitor_states.get(&MonitorKind::Snap).unwrap_or(&false));

        let report_sep1 = gtk::Separator::new(gtk::Orientation::Horizontal);
        report_sep1.set_margin_top(6);
        report_outer.append(&report_sep1);

        let report_def = gtk::Label::new(None);
        report_def.set_markup("Virus definitions — <span foreground='#888888'>checking…</span>");
        report_def.set_halign(gtk::Align::Start);
        report_def.set_xalign(0.0);
        report_def.set_selectable(true);
        report_outer.append(&report_def);
        REPORT_DEF_LABEL.with(|c| { *c.borrow_mut() = Some(report_def); });

        let report_sep2 = gtk::Separator::new(gtk::Orientation::Horizontal);
        report_sep2.set_margin_top(6);
        report_outer.append(&report_sep2);

        let mem_label = gtk::Label::new(Some(&memory_overhead_text()));
        mem_label.set_halign(gtk::Align::Start);
        mem_label.set_justify(gtk::Justification::Left);
        mem_label.set_css_classes(&["dim-label"]);
        report_outer.append(&mem_label);
        MONITOR_MEMORY_LABEL.with(|cell| { *cell.borrow_mut() = Some(mem_label); });

        // Refresh the GUI's own line every 300s (daemon line arrives via ResidentMemory).
        gtk::glib::timeout_add_seconds_local(300, || {
            update_memory_label();
            gtk::glib::ControlFlow::Continue
        });

        report_frame.set_child(Some(&report_outer));

        let log_scroll = gtk::ScrolledWindow::builder()
            .vexpand(true)
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vscrollbar_policy(gtk::PolicyType::Automatic)
            .build();
        let log_view = gtk::TextView::builder()
            .editable(false).cursor_visible(false).monospace(true)
            .left_margin(8).right_margin(8).top_margin(4).bottom_margin(4)
            .build();
        log_view.add_css_class("log-view");
        let log_buf = log_view.buffer();
        let initial = model.log_entries.iter()
            .map(|e| format!("[{}] {}", e.timestamp, e.message))
            .collect::<Vec<_>>().join("\n");
        log_buf.set_text(&initial);
        MAIN_LOG_BUF.with(|cell| { *cell.borrow_mut() = Some(log_buf); });
        log_scroll.set_child(Some(&log_view));
        MAIN_LOG_SCROLL.with(|cell| { *cell.borrow_mut() = Some(log_scroll.clone()); });
        let dashboard_box = gtk::Box::builder().orientation(gtk::Orientation::Vertical).build();
        dashboard_box.append(&report_frame);
        dashboard_box.append(&log_scroll);
        widgets.notebook.append_page(&dashboard_box, Some(&gtk::Label::new(Some("Dashboard"))));


        // ── Tab: Scan ─────────────────────────────────────────────────────────
        let scan_box  = gtk::Box::new(gtk::Orientation::Vertical, 12);
        scan_box.set_margin_all(16);
        scan_box.set_valign(gtk::Align::Start);
        let scan_desc = gtk::Label::new(Some("Select a folder or drive to scan for threats."));
        scan_desc.set_halign(gtk::Align::Start);
        scan_desc.set_margin_bottom(4);
        let scan_btn = gtk::Button::with_label("Choose Folder to Scan");
        scan_btn.set_halign(gtk::Align::Start);
        scan_btn.add_css_class("suggested-action");
        let s = sender.clone();
        scan_btn.connect_clicked(move |_| s.input(DashboardMsg::StartUserScan));
        scan_box.append(&scan_desc);
        scan_box.append(&scan_btn);
        widgets.notebook.append_page(&scan_box, Some(&gtk::Label::new(Some("Scan"))));

        // ── Tab: Quarantine ───────────────────────────────────────────────────
        let q_box  = gtk::Box::new(gtk::Orientation::Vertical, 12);
        q_box.set_margin_all(16);
        q_box.set_valign(gtk::Align::Start);
        let q_desc = gtk::Label::new(Some("Quarantined files are isolated and cannot execute."));
        q_desc.set_halign(gtk::Align::Start);
        q_desc.set_margin_bottom(4);
        let q_btn  = gtk::Button::with_label("View Quarantine");
        q_btn.set_halign(gtk::Align::Start);
        let s2 = sender.clone();
        q_btn.connect_clicked(move |_| s2.input(DashboardMsg::OpenQuarantineViewer));
        q_box.append(&q_desc);
        q_box.append(&q_btn);
        widgets.notebook.append_page(&q_box, Some(&gtk::Label::new(Some("Quarantine"))));

        // ── Tab: Settings — the controls ──────────────────────────────────────
        let settings_scroll = gtk::ScrolledWindow::builder()
            .vexpand(true)
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vscrollbar_policy(gtk::PolicyType::Automatic)
            .build();
        let settings_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
        settings_box.set_margin_all(20);
        settings_box.set_spacing(20);

        // ── Section: Install Monitors ─────────────────────────────────────────
        let mon_heading = gtk::Label::new(None);
        mon_heading.set_markup("<b>Install Monitors</b>");
        mon_heading.set_halign(gtk::Align::Start);

        let mon_sub = gtk::Label::new(Some(
            "Select which install paths Ghost Sentri manages, then press Confirm \
             Selections. Changes are system-wide and require administrator \
             authorisation. Flatpak and Snap are monitor-and-log only — the \
             dedicated installer performs those installs.",
        ));
        mon_sub.set_halign(gtk::Align::Start);
        mon_sub.set_wrap(true);
        mon_sub.add_css_class("dim-label");

        // Grid of staged toggles (select-then-commit). Clicking stages a change;
        // nothing is sent until Confirm Selections runs the root --apply.
        let monitor_grid = gtk::Grid::builder().row_spacing(6).column_spacing(24).build();
        let monitor_kinds = MonitorKind::all();
        for (i, kind) in monitor_kinds.iter().enumerate() {
            let row = (i / 2) as i32;
            let col = (i % 2) as i32;

            let row_box = gtk::Box::new(gtk::Orientation::Horizontal, 8);
            row_box.set_valign(gtk::Align::Center);

            let dot = gtk::Label::new(None);
            let initially_on = model.monitor_states.get(kind).copied().unwrap_or(false);
            if initially_on {
                dot.set_markup("<span foreground='#33aa33'>⬤</span>");
            } else {
                dot.set_markup("<span foreground='#cc3333'>⬤</span>");
            }

            let name_label = gtk::Label::new(Some(kind.label()));
            name_label.set_halign(gtk::Align::Start);

            let state_label = gtk::Label::new(None);
            if initially_on {
                state_label.set_markup("<span foreground='#33aa33'>[ACTIVE]</span>");
            } else {
                state_label.set_markup("<span foreground='#cc3333'>[OFF]</span>");
            }
            state_label.set_halign(gtk::Align::Start);

            row_box.append(&dot);
            row_box.append(&name_label);
            row_box.append(&state_label);

            let kind_clone = kind.clone();
            let s_mon = sender.clone();
            let gesture = gtk::GestureClick::new();
            gesture.connect_released(move |_, _, _, _| {
                s_mon.input(DashboardMsg::ToggleMonitor(kind_clone.clone()));
            });
            row_box.add_controller(gesture);
            row_box.set_cursor_from_name(Some("pointer"));

            let key = kind.label().to_string();
            MONITOR_WIDGETS.with(|map| {
                map.borrow_mut().insert(key, (dot.clone(), state_label.clone()));
            });

            monitor_grid.attach(&row_box, col, row, 1, 1);
        }

        let action_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        action_row.set_margin_top(6);
        let confirm_btn = gtk::Button::with_label("Confirm Selections");
        confirm_btn.add_css_class("suggested-action");
        confirm_btn.set_sensitive(false);
        let reset_btn = gtk::Button::with_label("Reset");
        {
            let s_c = sender.clone();
            confirm_btn.connect_clicked(move |_| s_c.input(DashboardMsg::ConfirmSelections));
            let s_r = sender.clone();
            reset_btn.connect_clicked(move |_| s_r.input(DashboardMsg::ResetSelections));
        }
        CONFIRM_BTN.with(|c| { *c.borrow_mut() = Some(confirm_btn.clone()); });
        action_row.append(&confirm_btn);
        action_row.append(&reset_btn);

        let mon_section = gtk::Box::new(gtk::Orientation::Vertical, 8);
        mon_section.append(&mon_heading);
        mon_section.append(&mon_sub);
        mon_section.append(&monitor_grid);
        mon_section.append(&action_row);
        settings_box.append(&mon_section);

        settings_box.append(&gtk::Separator::new(gtk::Orientation::Horizontal));

        // ── Section: Virus Definitions ────────────────────────────────────────
        let def_heading = gtk::Label::new(None);
        def_heading.set_markup("<b>Virus Definitions</b>");
        def_heading.set_halign(gtk::Align::Start);

        let def_info = gtk::Label::new(Some(
            "Update the ClamAV virus definitions. This runs freshclam under a single \
             administrator authorisation prompt. The current version and freshness are \
             shown on the Dashboard.",
        ));
        def_info.set_halign(gtk::Align::Start);
        def_info.set_wrap(true);
        def_info.add_css_class("dim-label");

        let def_update_btn = gtk::Button::with_label("Update Definitions Now");
        def_update_btn.set_halign(gtk::Align::Start);
        def_update_btn.add_css_class("suggested-action");
        let s3 = sender.clone();
        def_update_btn.connect_clicked(move |_| s3.input(DashboardMsg::UpdateDefinitions));

        let def_section = gtk::Box::new(gtk::Orientation::Vertical, 8);
        def_section.append(&def_heading);
        def_section.append(&def_info);
        def_section.append(&def_update_btn);
        settings_box.append(&def_section);

        settings_box.append(&gtk::Separator::new(gtk::Orientation::Horizontal));

        // ── Section: Scheduled Definition Checks ──────────────────────────────
        let sched_heading = gtk::Label::new(None);
        sched_heading.set_markup("<b>Scheduled Definition Checks</b>");
        sched_heading.set_halign(gtk::Align::Start);

        let sched_info = gtk::Label::new(Some(
            "Ghost Sentri checks definition staleness once daily from the resident daemon — \
             no network access, a filesystem timestamp check only. When definitions are \
             outdated, the Dashboard status turns red; update them with the button above.",
        ));
        sched_info.set_halign(gtk::Align::Start);
        sched_info.set_wrap(true);
        sched_info.add_css_class("dim-label");

        let sched_section = gtk::Box::new(gtk::Orientation::Vertical, 8);
        sched_section.append(&sched_heading);
        sched_section.append(&sched_info);
        settings_box.append(&sched_section);

        settings_box.append(&gtk::Separator::new(gtk::Orientation::Horizontal));

        // ── Section: Whitelist ────────────────────────────────────────────────
        let wl_heading = gtk::Label::new(None);
        wl_heading.set_markup("<b>Whitelist</b>");
        wl_heading.set_halign(gtk::Align::Start);

        let trusted_keys = &model.config.sentry.trusted_gpg_keys;
        let wl_text = if trusted_keys.is_empty() {
            "No trusted GPG keys configured.\nWhitelist path and package entries coming in a future release.".to_string()
        } else {
            format!(
                "Trusted GPG keys: {}\n\nWhitelist path and package entries coming in a future release.",
                trusted_keys.join(", ")
            )
        };
        let wl_info = gtk::Label::new(Some(&wl_text));
        wl_info.set_halign(gtk::Align::Start);
        wl_info.set_wrap(true);
        wl_info.add_css_class("dim-label");

        let wl_section = gtk::Box::new(gtk::Orientation::Vertical, 8);
        wl_section.append(&wl_heading);
        wl_section.append(&wl_info);
        settings_box.append(&wl_section);

        // ── Section: Setup guide + config path ────────────────────────────────
        settings_box.append(&gtk::Separator::new(gtk::Orientation::Horizontal));
        let guide_btn = gtk::Button::with_label("Show Setup Guide");
        guide_btn.set_halign(gtk::Align::Start);
        let s_guide = sender.clone();
        guide_btn.connect_clicked(move |_| s_guide.input(DashboardMsg::ResetFirstRun));
        settings_box.append(&guide_btn);

        let cfg_label = gtk::Label::new(Some(&format!(
            "Config: {}",
            Config::config_path().display(),
        )));
        cfg_label.set_halign(gtk::Align::Start);
        cfg_label.set_selectable(true);
        cfg_label.add_css_class("dim-label");
        settings_box.append(&cfg_label);

        settings_scroll.set_child(Some(&settings_box));
        widgets.notebook.append_page(&settings_scroll, Some(&gtk::Label::new(Some("Settings"))));


        // ── Tab: Help ─────────────────────────────────────────────────────────
        let help_scroll = gtk::ScrolledWindow::builder()
            .vexpand(true)
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vscrollbar_policy(gtk::PolicyType::Automatic)
            .build();
        let help_box = gtk::Box::new(gtk::Orientation::Vertical, 12);
        help_box.set_margin_all(16);
        help_box.set_valign(gtk::Align::Start);

        let help_text = gtk::Label::new(Some(&format!(
            "Ghost Sentri (GS) v{} — Security monitor for Linux operating systems.\n\
             This application requires current ClamAV virus definitions to be installed \
             to function optimally.\n\n\
             (GS) monitors package installations across several paths on your system. The \
             application functions in several ways.\n\n\
             A) After scanner activation, (GS) becomes the default install handler for \
             distro package installations system-wide. Install files can be scanned for \
             malicious code before installation.\n\
             B) Flatpak, Snap, Wine and Build installations are monitored and logged for \
             reference.\n\
             The scanners and monitors are enabled independently from the Settings tab in \
             the application Dashboard.\n\
             C) Targeted drive, folder or file scans.\n\
             D) Quarantine separation for install packages that trigger virus response.\n\n\
             The application dashboard front page displays the current status of package \
             handlers, virus definitions, daemon connection and other system status \
             information.\n\n\
             Scanner Activity:\n\n\
             apt / .deb installs — Intercepts apt / apt-get installs before dpkg executes, \
             and handles .deb files opened from the file manager. The install is blocked \
             until it is approved or scanned.\n\n\
             Terminal Builds — Monitors and logs source / script installs (make install, \
             curl | bash, pip, npm).\n\n\
             Wine — Monitors Wine prefixes for incoming Windows executables (.exe, .msi).\n\n\
             Flatpak and Snap — monitors and logs only — the dedicated installer performs \
             the install.\n\n\
             When a distro package install is detected, a dialog allows you to select:\n\
             • Scan Now — ClamAV scans the file before install proceeds\n\
             • Proceed Without Scan — bypass for trusted sources\n\
             • Cancel Install — block immediately\n\n\
             Developed for Lean Linux by archerprojects (archer.projects@proton.me) — \n\
             https://github.com/archerprojects/Ghost-Sentri",
            APP_VERSION
        )));
        help_text.set_halign(gtk::Align::Start);
        help_text.set_wrap(true);
        help_text.set_selectable(true);
        help_text.set_margin_bottom(12);

        help_box.append(&help_text);
        help_scroll.set_child(Some(&help_box));
        widgets.notebook.append_page(&help_scroll, Some(&gtk::Label::new(Some("Help"))));

        // ── Welcome dialog — shown each launch (per version) until dismissed ──
        if !welcome_dismissed() {
            let s = sender.clone();
            let w = model.window.clone();
            // Short one-shot delay so the dashboard window is mapped first and the
            // welcome lands on top of it, not behind.
            glib::timeout_add_local_once(std::time::Duration::from_millis(250), move || {
                show_first_run_dialog(&s, w.as_ref());
            });
        }

        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        match msg {
            DashboardMsg::ControlEvent(event) => { self.handle_control_event(event); }

            // Intercept decisions handled by installer subprocess — no dashboard UI needed
            DashboardMsg::InterceptScanNow | DashboardMsg::InterceptProceedWithoutScan | DashboardMsg::InterceptCancel => {}
            // Threat decisions are owned by the installer/worker now; these arms
            // remain only for the dashboard's own user-scan flow (informational).
            DashboardMsg::ThreatQuarantine
            | DashboardMsg::ThreatProceedWithCaution
            | DashboardMsg::ThreatProceedConfirmed
            | DashboardMsg::ThreatCancel => {}

            DashboardMsg::StartUserScan => {
                show_scan_target_chooser(&sender, self.window.as_ref());
            }

            DashboardMsg::ScanPath(path) => {
                let cancel = Arc::new(AtomicBool::new(false));
                self.scan_cancel = Some(cancel.clone());
                show_progress_dialog(&sender);

                let s        = sender.clone();
                let clamscan = self.config.resolve_clamscan();
                let def_path = self.config.resolve_definition_path();
                let scan_root = path.clone();

                rt().spawn(async move {
                    let cancel_flag = cancel.clone();
                    let s_clone     = s.clone();
                    let results = tokio::task::spawn_blocking(move || {
                        let mut files: Vec<PathBuf> = vec![];
                        collect_files_recursive(&scan_root, &mut files);
                        let total  = files.len();
                        let engine = SystemClamBackend::new(clamscan, def_path);
                        let mut results: Vec<(PathBuf, ScanResult)> = vec![];
                        for (i, file) in files.iter().enumerate() {
                            if cancel_flag.load(Ordering::Relaxed) { break; }
                            let result = engine.scan_file(file);
                            let line = match &result {
                                ScanResult::Threat(detail) => Some(format!("⚠ THREAT: {}", detail.name)),
                                ScanResult::Error(e)       => Some(format!("✗ ERROR: {}", e)),
                                ScanResult::Clean          => None,
                            };
                            results.push((file.clone(), result));
                            s_clone.input(DashboardMsg::ScanProgress { done: i + 1, total, line });
                        }
                        results
                    }).await.unwrap_or_default();
                    s.input(DashboardMsg::ScanComplete(path, results));
                });
            }

            DashboardMsg::ScanProgress { done, total, line } => {
                let fraction = if total > 0 { done as f64 / total as f64 } else { 0.0 };
                PROGRESS_BAR.with(|cell| {
                    if let Some(bar) = cell.borrow().as_ref() {
                        bar.set_fraction(fraction);
                        bar.set_text(Some(&format!("{} / {}", done, total)));
                    }
                });
                if let Some(text) = line {
                    PROGRESS_BUF.with(|cell| {
                        if let Some(buf) = cell.borrow().as_ref() {
                            let mut end = buf.end_iter();
                            if buf.char_count() > 0 { buf.insert(&mut end, "\n"); }
                            buf.insert(&mut end, &text);
                            PROGRESS_SCROLL.with(|sc| {
                                if let Some(scroll) = sc.borrow().as_ref() {
                                    let adj = scroll.vadjustment();
                                    glib::idle_add_local_once(move || {
                                        adj.set_value(adj.upper() - adj.page_size());
                                    });
                                }
                            });
                        }
                    });
                }
            }

            DashboardMsg::CancelScan => {
                if let Some(cancel) = &self.scan_cancel { cancel.store(true, Ordering::Relaxed); }
                self.scan_cancel = None;
                dismiss_progress_dialog();
                self.log("Scan cancelled".to_string());
            }

            DashboardMsg::ScanComplete(_, results) => {
                dismiss_progress_dialog();
                self.scan_cancel = None;
                let total   = results.len();
                let mut threats = 0usize;
                for (_, result) in &results {
                    match result {
                        ScanResult::Threat(detail) => {
                            self.log_threat(format!("[THREAT] {}", detail.name));
                            threats += 1;
                        }
                        ScanResult::Error(e) => { self.log(format!("[ERROR] {}", e)); }
                        ScanResult::Clean    => {}
                    }
                }
                let summary = if threats == 0 {
                    format!("Scan complete — {} file{} scanned, no threats found.",
                        total, if total == 1 { "" } else { "s" })
                } else {
                    format!("Scan complete — {} file{} scanned, {} threat{} found.",
                        total, if total == 1 { "" } else { "s" },
                        threats, if threats == 1 { "" } else { "s" })
                };
                self.log(summary.clone());
                show_scan_summary_dialog(&summary, threats, self.window.as_ref());
            }

            DashboardMsg::OpenQuarantineViewer => {
                show_quarantine_dialog(&self.quarantine_items, self.window.as_ref());
            }
            DashboardMsg::PurgeAll => { self.log("Purge initiated...".to_string()); }

            DashboardMsg::UpdateDefinitions => {
                // The GUI is unprivileged; the root daemon runs freshclam after a
                // polkit prompt. Show the progress dialog and drive it from the
                // daemon's DefinitionUpdateProgress / DefinitionUpdateComplete events.
                if let Some(tx) = &self.control_tx {
                    show_def_update_progress_dialog();
                    let _ = tx.try_send(ControlRequest::RequestDefinitionUpdate);
                    self.log("Requesting definition update — administrator authorisation required…".to_string());
                } else {
                    self.log("Not connected to the daemon — cannot update definitions.".to_string());
                }
            }

            DashboardMsg::DefUpdateProgress(text) => {
                DEF_UPDATE_LABEL.with(|cell| {
                    if let Some(lbl) = cell.borrow().as_ref() { lbl.set_label(&text); }
                });
                DEF_UPDATE_LOG.with(|cell| {
                    if let Some(buf) = cell.borrow().as_ref() {
                        let mut end = buf.end_iter();
                        if buf.char_count() > 0 { buf.insert(&mut end, "\n"); }
                        buf.insert(&mut end, &text);
                    }
                });
            }

            DashboardMsg::DefUpdateComplete(success) => {
                dismiss_def_update_dialog();
                if success {
                    self.log("Virus definitions updated successfully".to_string());
                } else {
                    self.log("[ERROR] Definition update failed — check pkexec authorisation".to_string());
                }
            }

            DashboardMsg::ResetFirstRun => {
                // Re-run the setup wizard immediately. (Config is daemon-owned, so
                // the dashboard no longer persists first_run here.)
                self.log("Re-running setup wizard…".to_string());
                let s = sender.clone();
                let w = self.window.clone();
                glib::idle_add_local_once(move || {
                    show_first_run_dialog(&s, w.as_ref());
                });
            }


            DashboardMsg::ToggleMonitor(kind) => {
                // Staged select-then-commit: flip the DISPLAYED state (pending if set,
                // else applied). Nothing is sent until Confirm Selections.
                let applied = *self.monitor_states.get(&kind).unwrap_or(&false);
                let shown   = *self.pending_monitors.get(&kind).unwrap_or(&applied);
                let desired = !shown;
                if desired == applied {
                    self.pending_monitors.remove(&kind);
                } else {
                    self.pending_monitors.insert(kind.clone(), desired);
                }
                update_monitor_widget(kind.label(), desired);
                self.refresh_confirm();
            }

            DashboardMsg::ToggleDefsUpdate => {
                if self.defs_stale {
                    self.pending_defs = !self.pending_defs;
                    update_defs_row(self.defs_stale, self.pending_defs);
                    self.refresh_confirm();
                }
            }

            DashboardMsg::ConfirmSelections => {
                let mut enable = Vec::new();
                let mut disable = Vec::new();
                for (kind, &want) in &self.pending_monitors {
                    if want { enable.push(kind.backend_id().to_string()); }
                    else    { disable.push(kind.backend_id().to_string()); }
                }
                if enable.is_empty() && disable.is_empty() { return; }
                // The root system daemon owns machine policy. Send the batch over
                // the control socket; the daemon authorises via polkit, writes /etc,
                // and reconciles live — broadcasting MonitorChanged for each, which
                // commits the displayed state (no relogin, no pkexec from here).
                if let Some(tx) = &self.control_tx {
                    let _ = tx.try_send(ControlRequest::ApplyChanges {
                        enable, disable, update_defs: false,
                    });
                    self.log("Applying selections — administrator authorisation required…".to_string());
                } else {
                    self.log("Not connected to the daemon — cannot apply selections.".to_string());
                }
            }

            DashboardMsg::ResetSelections => {
                let kinds: Vec<MonitorKind> = self.pending_monitors.keys().cloned().collect();
                for kind in kinds {
                    let applied = *self.monitor_states.get(&kind).unwrap_or(&false);
                    update_monitor_widget(kind.label(), applied);
                }
                self.pending_monitors.clear();
                self.pending_defs = false;
                update_defs_row(self.defs_stale, false);
                self.refresh_confirm();
            }

            // Legacy per-toggle echo path — unused under the staged model.
            DashboardMsg::MonitorToggleConfirmed(_, _) => {}
            DashboardMsg::MonitorToggleDenied(_) => {}

            DashboardMsg::InstallProgress(line) => {
                self.log(format!("[INSTALL] {}", line));
            }
            DashboardMsg::InstallComplete { success } => {
                if success {
                    self.log("[INSTALL] Installation complete.".to_string());
                } else {
                    self.log_threat("[INSTALL] Installation failed.".to_string());
                }
            }

            DashboardMsg::ToggleSentry => {
                let want = !self.sentry_active;
                if let Some(tx) = &self.control_tx {
                    let _ = tx.try_send(ControlRequest::SetActive { active: want });
                    self.sentry_active = want; // confirmed by ActiveChanged echo
                } else {
                    self.log("Not connected to the daemon — cannot change scan state.".to_string());
                }
            }
            DashboardMsg::ShowWindow => {
                if let Some(w) = &self.window { w.set_visible(true); w.present(); }
            }
            DashboardMsg::Quit      => { relm4::main_application().quit(); }
        }
    }
}

impl DashboardModel {
    fn log(&mut self, msg: String) {
        let entry = LogEntry::new(msg);
        append_log(&format!("[{}] {}", entry.timestamp, entry.message));
        self.log_entries.push(entry);
    }
    fn log_threat(&mut self, msg: String) {
        let entry = LogEntry::threat(msg);
        append_log(&format!("[{}] {}", entry.timestamp, entry.message));
        self.log_entries.push(entry);
    }
    #[allow(dead_code)] // Install-Without-Scan override logging — wired in later
    fn log_override(&mut self, msg: String) {
        let entry = LogEntry::override_entry(msg);
        append_log(&format!("[{}] {}", entry.timestamp, entry.message));
        self.log_entries.push(entry);
    }

    fn refresh_confirm(&self) {
        set_confirm_sensitive(!self.pending_monitors.is_empty() || self.pending_defs);
    }

    fn handle_control_event(&mut self, event: ControlEvent) {
        match event {
            ControlEvent::StateSnapshot { monitors, definition, recent_log, resident_kb, active } => {
                // Replay recent daemon log into the dashboard view.
                for line in recent_log {
                    self.log(line);
                }
                // Apply monitor states to BOTH the Settings toggles (baseline) and
                // the read-only Dashboard situation report.
                for m in monitors {
                    if let Some(kind) = MonitorKind::from_backend_id(&m.monitor) {
                        self.monitor_states.insert(kind.clone(), m.enabled);
                        update_monitor_widget(kind.label(), m.enabled);
                    }
                    apply_monitor_to_report(&m.monitor, m.enabled);
                }
                // Definition status line on the Dashboard.
                self.defs_stale = definition.stale;
                update_report_def(&definition.version, &definition.age, definition.stale);
                DAEMON_RESIDENT_KB.with(|c| c.set(resident_kb));
                update_memory_label();
                self.sentry_active = active;
                self.log("Connected to daemon.".to_string());
            }

            ControlEvent::LogLine { line } => { self.log(line); }

            ControlEvent::ActiveChanged { active } => {
                self.sentry_active = active;
            }

            ControlEvent::ResidentMemory { resident_kb } => {
                DAEMON_RESIDENT_KB.with(|c| c.set(resident_kb));
                update_memory_label();
            }

            ControlEvent::MonitorChanged { monitor, enable } => {
                if let Some(kind) = MonitorKind::from_backend_id(&monitor) {
                    self.monitor_states.insert(kind.clone(), enable);
                    self.pending_monitors.remove(&kind);
                    update_monitor_widget(kind.label(), enable);
                    self.refresh_confirm();
                    self.log(format!("{} monitor {}.",
                        kind.label(), if enable { "enabled" } else { "disabled" }));
                }
                apply_monitor_to_report(&monitor, enable);
                self.app_pss_kb = read_pss_kb();
                update_memory_label();
            }

            ControlEvent::DefinitionStatus(snap) => {
                self.defs_stale = snap.stale;
                if snap.stale {
                    self.log(format!("[DEFS] Definitions outdated ({}) — update from Settings", snap.age));
                }
                update_report_def(&snap.version, &snap.age, snap.stale);
                self.refresh_confirm();
            }

            ControlEvent::DefinitionUpdateProgress { message } => {
                DEF_UPDATE_LABEL.with(|cell| {
                    if let Some(lbl) = cell.borrow().as_ref() { lbl.set_label(&message); }
                });
                DEF_UPDATE_LOG.with(|cell| {
                    if let Some(buf) = cell.borrow().as_ref() {
                        let mut end = buf.end_iter();
                        if buf.char_count() > 0 { buf.insert(&mut end, "\n"); }
                        buf.insert(&mut end, &message);
                    }
                });
                self.log(message);
            }
            ControlEvent::DefinitionUpdateComplete { success } => {
                dismiss_def_update_dialog();
                self.pending_defs = false;
                if success { self.defs_stale = false; }   // stays red on failure
                self.refresh_confirm();
                self.log(if success { "[DEFS] Update complete.".into() }
                         else { "[DEFS] Update failed — definitions still outdated.".to_string() });
            }

            ControlEvent::WrappersInstalled { ok, message } => {
                if ok { self.log(message); } else { self.log_threat(message); }
            }
        }
    }
}

// ── Directory scan progress window ────────────────────────────────────────────

thread_local! {
    static PROGRESS_WINDOW: std::cell::RefCell<Option<gtk::Window>> =
        std::cell::RefCell::new(None);
    static PROGRESS_BAR: std::cell::RefCell<Option<gtk::ProgressBar>> =
        std::cell::RefCell::new(None);
    static PROGRESS_BUF: std::cell::RefCell<Option<gtk::TextBuffer>> =
        std::cell::RefCell::new(None);
    static PROGRESS_SCROLL: std::cell::RefCell<Option<gtk::ScrolledWindow>> =
        std::cell::RefCell::new(None);
}

fn show_progress_dialog(sender: &ComponentSender<DashboardModel>) {
    let window = gtk::Window::builder()
        .title("Ghost Sentri — Scanning")
        .default_width(520).default_height(360)
        .modal(false).deletable(false).resizable(true)
        .build();

    let outer = gtk::Box::new(gtk::Orientation::Vertical, 12);
    outer.set_margin_all(20);

    let row = gtk::Box::new(gtk::Orientation::Horizontal, 16);
    row.set_valign(gtk::Align::Start);

    let icon = gtk::Image::from_icon_name("ghost-sentri");
    icon.set_pixel_size(48);
    icon.set_valign(gtk::Align::Start);
    icon.set_margin_top(4);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 8);
    content.set_hexpand(true);

    let heading = gtk::Label::new(None);
    heading.set_markup("<b>Scanning files…</b>");
    heading.set_halign(gtk::Align::Start);

    let bar = gtk::ProgressBar::new();
    bar.set_fraction(0.0);
    bar.set_show_text(true);
    bar.set_text(Some("Counting files…"));

    let status = gtk::Label::new(Some(""));
    status.set_halign(gtk::Align::Start);

    content.append(&heading);
    content.append(&bar);
    content.append(&status);
    row.append(&icon);
    row.append(&content);
    outer.append(&row);

    let expander = gtk::Expander::new(Some("Details"));
    let scroll = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .height_request(160)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::Automatic)
        .build();
    let text_view = gtk::TextView::new();
    text_view.set_editable(false);
    text_view.set_monospace(true);
    text_view.set_wrap_mode(gtk::WrapMode::WordChar);
    text_view.set_left_margin(6);
    text_view.set_top_margin(4);
    text_view.set_bottom_margin(4);
    text_view.add_css_class("scan-log");
    let buf = text_view.buffer();
    scroll.set_child(Some(&text_view));
    expander.set_child(Some(&scroll));
    outer.append(&expander);

    let btn_row = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    btn_row.set_halign(gtk::Align::End);
    let cancel_btn = gtk::Button::with_label("Cancel");
    let s = sender.clone();
    cancel_btn.connect_clicked(move |_| { s.input(DashboardMsg::CancelScan); });
    btn_row.append(&cancel_btn);
    outer.append(&btn_row);

    window.set_child(Some(&outer));

    PROGRESS_BAR.with(|cell| { *cell.borrow_mut() = Some(bar); });
    PROGRESS_BUF.with(|cell| { *cell.borrow_mut() = Some(buf); });
    PROGRESS_SCROLL.with(|cell| { *cell.borrow_mut() = Some(scroll); });
    PROGRESS_WINDOW.with(|cell| { *cell.borrow_mut() = Some(window.clone()); });

    window.present();
}

fn dismiss_progress_dialog() {
    PROGRESS_BAR.with(|cell|    { *cell.borrow_mut() = None; });
    PROGRESS_BUF.with(|cell|    { *cell.borrow_mut() = None; });
    PROGRESS_SCROLL.with(|cell| { *cell.borrow_mut() = None; });
    PROGRESS_WINDOW.with(|cell| {
        if let Some(w) = cell.borrow_mut().take() { w.close(); }
    });
}

// ── Dialogs ───────────────────────────────────────────────────────────────────

fn welcome_marker_path() -> std::path::PathBuf {
    let base = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    std::path::PathBuf::from(base).join(".config/ghost-sentri/welcome_seen")
}

/// True only when the welcome has been dismissed FOR THIS VERSION. The marker
/// stores the version it was dismissed at; a new install (new version) re-shows
/// the dialog so the enable-your-scanners guidance is seen again.
fn welcome_dismissed() -> bool {
    std::fs::read_to_string(welcome_marker_path())
        .map(|s| s.trim() == APP_VERSION)
        .unwrap_or(false)
}

fn dismiss_welcome() {
    let path = welcome_marker_path();
    if let Some(dir) = path.parent() { let _ = std::fs::create_dir_all(dir); }
    let _ = std::fs::write(&path, APP_VERSION.as_bytes());
}


fn show_first_run_dialog(sender: &ComponentSender<DashboardModel>, window: Option<&adw::Window>) {
    let _ = sender;
    let dialog = gtk::Window::builder()
        .title("Ghost Sentri")
        .default_width(820)
        .modal(true)
        .resizable(true)
        .deletable(false)
        .build();
    dialog.set_transient_for(window);
    dialog.set_icon_name(Some("ghost-sentri"));
    // Cover the dashboard exactly: size to the dashboard window's LIVE dimensions
    // when this opens — its content can stretch it wider than the nominal 820, so
    // a hardcoded width leaves the dash protruding at the sides. Match whatever it
    // actually is. Height still floats taller if the text needs it; falls back to
    // 820×700 only if the window isn't mapped yet.
    let (dw, dh) = match window {
        Some(w) if w.width() > 0 && w.height() > 0 => (w.width(), w.height()),
        _ => (820, 700),
    };
    dialog.set_size_request(dw, dh);

    let vbox = gtk::Box::new(gtk::Orientation::Vertical, 16);
    vbox.set_margin_all(24);

    let title = gtk::Label::new(None);
    title.set_markup(&format!(
        "<span foreground=\"#4b8bd4\" weight=\"bold\" size=\"x-large\">Welcome to Ghost Sentri (GS) v{}</span>",
        APP_VERSION
    ));
    title.set_halign(gtk::Align::Start);

    let body = gtk::Label::new(Some(
        "Ghost Sentri (GS) is an end-to-end install manager and threat sentri that uses \
         ClamAV virus definitions for scanning distribution install packages and files. \
         (GS) requires current ClamAV virus definitions installed to function. (GS) can be \
         selected to manage installations and scan for possible threats or malicious code \
         in the install packages; targeted to scan drives, folders or files for malicious \
         content and quarantine suspicious files when requested. For Flatpak and Snap \
         installations, (GS) acts as a monitor and logger only while the dedicated system \
         install application performs the install. On initial installation, all scanners \
         are disabled and require enabling in the application dashboard settings tab to \
         allow the (GS) daemon monitor to detect and manage installs on the system. This is \
         a system-wide activation requiring root privileges.\n\n\
         For maximum protection, (GS) scanners must be enabled in the dashboard after \
         installation; activation is immediate following elevated privilege confirmation \
         that enables protection. Virus definitions also must be updated periodically \
         through the (GS) settings tab. Once scanners are enabled in settings, (GS) becomes \
         the install manager or monitor for those paths going forward. All settings can be \
         reversed at any time through the settings tab. Please proceed to the (GS) dashboard \
         settings tab to configure protection as required.",
    ));
    body.set_wrap(true);
    body.set_xalign(0.0);
    body.set_max_width_chars(92);
    body.set_vexpand(true);
    body.set_valign(gtk::Align::Start);

    let sep = gtk::Separator::new(gtk::Orientation::Horizontal);

    let dont_show = gtk::CheckButton::with_label("Don't show this again");
    dont_show.set_active(false);
    dont_show.set_halign(gtk::Align::Start);

    let btn_box = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    btn_box.set_halign(gtk::Align::End);
    let open_btn = gtk::Button::with_label("Proceed to Dashboard");
    open_btn.add_css_class("suggested-action");
    btn_box.append(&open_btn);

    vbox.append(&title);
    vbox.append(&body);
    vbox.append(&sep);
    vbox.append(&dont_show);
    vbox.append(&btn_box);
    dialog.set_child(Some(&vbox));

    let d = dialog.clone();
    open_btn.connect_clicked(move |_| {
        if dont_show.is_active() { dismiss_welcome(); }
        d.close();
    });

    dialog.present();
}

fn show_scan_target_chooser(sender: &ComponentSender<DashboardModel>, window: Option<&adw::Window>) {
    // Portal-backed picker (GTK 4.10+). Rendered by xdg-desktop-portal, so it is
    // themed correctly regardless of the system GTK theme — replaces the
    // deprecated GtkFileChooserDialog, which rendered with an unpainted
    // background under libadwaita.
    let dialog = gtk::FileDialog::builder()
        .title("Select Folder or Drive to Scan")
        .modal(true)
        .build();
    let s = sender.clone();
    dialog.select_folder(window, gtk::gio::Cancellable::NONE, move |result| {
        // Dismiss/Cancel yields Err(Dismissed); act only on a real selection.
        if let Ok(file) = result {
            if let Some(path) = file.path() {
                s.input(DashboardMsg::ScanPath(path));
            }
        }
    });
}

fn show_scan_summary_dialog(summary: &str, threats: usize, window: Option<&adw::Window>) {
    let title    = if threats > 0 { "⚠ Threats Found" } else { "Scan Complete" };
    let dialog   = adw::AlertDialog::new(Some(title), Some(summary));
    dialog.add_response("close", "Close");
    dialog.set_default_response(Some("close"));
    dialog.set_close_response("close");
    dialog.present(window);
}

fn show_quarantine_dialog(items: &[QuarantineRecord], window: Option<&adw::Window>) {
    let body = if items.is_empty() {
        "Quarantine is empty.".to_string()
    } else {
        items.iter()
            .map(|r| format!("{} — {} — {}", r.filename, r.threat_name,
                r.timestamp.format("%Y-%m-%d %H:%M")))
            .collect::<Vec<_>>().join("\n")
    };
    let dialog = adw::AlertDialog::new(Some("Quarantine Contents"), Some(&body));
    dialog.add_response("close", "Close");
    dialog.set_default_response(Some("close"));
    dialog.set_close_response("close");
    dialog.present(window);
}


// ─────────────────────────────────────────────────────────────────────────────
// Monitor state helpers — map MonitorKind ↔ BackendConfig fields
// ─────────────────────────────────────────────────────────────────────────────

fn monitor_states_from_config(config: &Config) -> HashMap<MonitorKind, bool> {
    let mut map = HashMap::new();
    map.insert(MonitorKind::PackagedApps,   config.backends.enable_apt);
    map.insert(MonitorKind::FlatpakApps,    config.backends.enable_flatpak);
    map.insert(MonitorKind::WineWindows,    config.backends.enable_wine);
    map.insert(MonitorKind::TerminalBuilds, config.backends.enable_build_source);
    map.insert(MonitorKind::Snap,           config.backends.enable_snap);
    map
}

// ── Entry point ───────────────────────────────────────────────────────────────
//
// GUI personalities (the daemon owns --apt-hook / --wrapper-hook / def checks):
//   --install <path> [--apt-hook]   run the installer UI (apt-hook ⇒ evaluate-only)
//   <file.deb>                       MIME handler (Nemo) ⇒ installer, evaluate-and-install
//   (default)                        the dashboard

fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();

    // Installer UI. Daemon launches `--install <path> --apt-hook`; Nemo passes a
    // bare path (handled below). --apt-hook ⇒ evaluate-only (apt does the install).
    if args.get(1).map(|s| s == "--install").unwrap_or(false) {
        if let Some(path) = args.get(2) {
            let apt_hook = args.iter().any(|a| a == "--apt-hook");
            adw::init().ok();
            let code = installer::run_installer(PathBuf::from(path), apt_hook);
            std::process::exit(code);
        }
        std::process::exit(2);
    }

    // .deb MIME handler — Nemo passes file:///path. Standalone ⇒ evaluate-and-install.
    if args.len() > 1 && !args[1].starts_with("--") {
        let raw  = args[1].trim_start_matches("file://");
        let path = PathBuf::from(raw);
        if path.extension().and_then(|e| e.to_str()) == Some("deb") {
            adw::init().ok();
            let code = installer::run_installer(path, false);
            std::process::exit(code);
        }
    }

    // Default: the dashboard.
    let config = Config::load().unwrap_or_else(|e| {
        log::error!("Config load failed: {} — using defaults", e);
        Config::default()
    });

    adw::init().ok();
    let app = RelmApp::new("org.ghost.Sentri");
    app.run::<DashboardModel>(config);
}
