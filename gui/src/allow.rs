// gui/src/allow.rs — v1.1.0 — Thursday 12 November 2026
// The allow-by-hash override outside the dashboard.
//
//   ghost-sentri --allow <sha256> [threat] [name]
//       Terminal command printed by the apt block message. Starts a text polkit
//       agent (pkttyagent --fallback) so the administrator prompt works in a
//       terminal, asks the daemon to allow that exact file, prints the outcome.
//
//   ghost-sentri --blocked <sha256> <threat> <name>
//       "Install blocked" dialog the apt hook opens in the live session, with
//       "Allow and retry…". Allowing needs administrator approval; the user then
//       re-runs the install (apt cannot be resumed from here).
//
// Only an exact SHA256 is ever allowed — never a name, path or source.

use ghost_sentri_core::allowlist::is_valid_sha256;
use ghost_sentri_core::config::Config;
use relm4::adw::prelude::*;
use relm4::gtk::glib;
use relm4::{adw, gtk};
use std::io::IsTerminal;
use std::process::Command;

fn socket() -> std::path::PathBuf {
    Config::load()
        .unwrap_or_default()
        .sentry
        .control_socket_path
}

/// `--allow`. Returns the process exit code.
pub fn cli_allow(args: &[String]) -> i32 {
    let Some(sha) = args.first().filter(|s| is_valid_sha256(s)).cloned() else {
        eprintln!("usage: ghost-sentri --allow <sha256> [threat] [name]");
        return 2;
    };
    let threat = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "(allowed from the command line)".into());
    let name = args.get(2).cloned().unwrap_or_default();

    // A text agent so polkit can ask for the password in this terminal. With
    // --fallback it steps aside when a graphical agent already serves the session.
    let mut agent = if std::io::stdin().is_terminal() {
        let a = Command::new("pkttyagent")
            .args(["--process", &std::process::id().to_string(), "--fallback"])
            .spawn()
            .ok();
        std::thread::sleep(std::time::Duration::from_millis(500));
        a
    } else {
        None
    };

    println!("Ghost Sentri: requesting administrator approval to allow sha256 {sha}…");
    let res = crate::rt().block_on(crate::control::request_allow(&socket(), sha, threat, name));
    if let Some(a) = agent.as_mut() {
        let _ = a.kill();
        let _ = a.wait();
    }
    match res {
        Ok((true, msg)) => {
            println!("{msg}");
            0
        }
        Ok((false, msg)) => {
            eprintln!("{msg}");
            1
        }
        Err(e) => {
            eprintln!("Ghost Sentri: {e}");
            1
        }
    }
}

/// `--blocked`. Shows the dialog and exits when it closes.
pub fn run_blocked_dialog(args: &[String]) -> i32 {
    let (Some(sha), Some(threat), Some(name)) = (args.first(), args.get(1), args.get(2)) else {
        return 2;
    };
    if !is_valid_sha256(sha) {
        return 2;
    }
    if gtk::init().is_err() {
        eprintln!("[blocked] GTK init failed");
        return 1;
    }
    adw::init().ok();
    if let Some(display) = gtk::gdk::Display::default() {
        gtk::IconTheme::for_display(&display).add_search_path("/usr/share/icons/hicolor");
    }

    let window = gtk::Window::builder()
        .title("Ghost Sentri — Install blocked")
        .default_width(520)
        .resizable(false)
        .build();
    window.set_icon_name(Some("ghost-sentri"));

    let vbox = gtk::Box::new(gtk::Orientation::Vertical, 14);
    vbox.set_margin_top(22);
    vbox.set_margin_bottom(18);
    vbox.set_margin_start(22);
    vbox.set_margin_end(22);

    let heading = gtk::Label::new(None);
    heading.set_markup(
        "<span size='large' weight='bold'>Install blocked — malware signature detected</span>",
    );
    heading.set_halign(gtk::Align::Start);

    let body = gtk::Label::new(Some(&format!(
        "{name} matched the signature {threat}. Nothing was installed.\n\n\
         If you are sure this is a false positive, you can allow this exact file. \
         It will then skip the virus scan everywhere on this computer, from any \
         source, until the entry is removed in Settings. Allowing needs \
         administrator approval. Afterwards, run your install again.\n\n\
         sha256 {sha}"
    )));
    body.set_wrap(true);
    body.set_xalign(0.0);
    body.set_max_width_chars(64);
    body.set_selectable(true);

    let status = gtk::Label::new(None);
    status.set_wrap(true);
    status.set_xalign(0.0);

    let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    buttons.set_halign(gtk::Align::End);
    let close = gtk::Button::with_label("Close");
    let allow = gtk::Button::with_label("Allow and retry…");
    allow.add_css_class("destructive-action");
    buttons.append(&close);
    buttons.append(&allow);

    vbox.append(&heading);
    vbox.append(&body);
    vbox.append(&status);
    vbox.append(&buttons);
    window.set_child(Some(&vbox));

    close.connect_clicked(|_| std::process::exit(0));
    window.connect_close_request(|_| std::process::exit(0));

    let (tx, rx) = std::sync::mpsc::channel::<AllowReply>();
    {
        let (sha, threat, name) = (sha.clone(), threat.clone(), name.clone());
        let status = status.clone();
        allow.connect_clicked(move |b| {
            b.set_sensitive(false);
            status.set_label("Waiting for administrator approval…");
            let tx = tx.clone();
            let (sha, threat, name) = (sha.clone(), threat.clone(), name.clone());
            crate::rt().spawn(async move {
                let r = crate::control::request_allow(&socket(), sha, threat, name).await;
                let _ = tx.send(r);
            });
        });
    }
    {
        let status = status.clone();
        let allow = allow.clone();
        glib::timeout_add_local(std::time::Duration::from_millis(200), move || {
            if let Ok(r) = rx.try_recv() {
                match r {
                    Ok((true, msg)) => {
                        status.set_markup(&format!(
                            "<span foreground='#33aa33'>{}</span>",
                            glib::markup_escape_text(&msg)
                        ));
                        allow.set_visible(false);
                    }
                    Ok((false, msg)) | Err(msg) => {
                        status.set_markup(&format!(
                            "<span foreground='#cc3333'>{}</span>",
                            glib::markup_escape_text(&msg)
                        ));
                        allow.set_sensitive(true);
                    }
                }
            }
            glib::ControlFlow::Continue
        });
    }

    window.present();
    loop {
        glib::MainContext::default().iteration(true);
    }
}

type AllowReply = Result<(bool, String), String>;
