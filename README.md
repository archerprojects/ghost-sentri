# Ghost Sentri (GS)

**Version 1.1.0 — Thursday 12 November 2026 — testing release.** Built and unit
tested; the end-to-end on-screen test of the new Downloads watch is still
pending. Install it on a machine you can test on.

Security monitor and install interceptor for Linux Operating Systems using the Debian/apt/dpkg stack - debian version.
(GS) sits in front of package installs — it intercepts `.deb` installs
at the dpkg level (terminal apt and file-manager double-click), scans them with
ClamAV before they reach the system, and keeps a machine-wide audit trail of
what was installed. It also watches each user's download folders, scans new
programs and archives, and quarantines threats.

---

**Developer**

```
Developed for Lean Linux by:
archerprojects
archer.projects@proton.me
https://github.com/archerprojects/ghost-sentri
```

Developed for Lean Linux. Not exclusive to Lean Linux — runs on any standard
Linux desktop.

---

## Screenshots

| Welcome | Dashboard | Settings |
|---|---|---|
| ![Welcome](screenshots/GS_1.jpg) | ![Dashboard](screenshots/GS_2.jpg) | ![Settings](screenshots/GS_3.jpg) |

*First-run welcome, the read-only status Dashboard, and the monitor toggle grid in Settings.*
*These screenshots predate 1.1.0: they still show the retired Wine and Flatpak
monitors, which the Downloads watch replaced.*

---

## Architecture

(GS) is a Cargo **workspace** of three crates, separated so the
always-resident process never links a GUI toolkit (the source of its former
memory footprint):

| Crate    | Binary                     | Role                                                              |
|----------|----------------------------|-------------------------------------------------------------------|
| `core`   | _(library)_                | Shared config, ClamAV scan, wire protocol, audit-event types. No GTK. |
| `daemon` | `ghost-sentri-daemon`      | Resident, **headless** root systemd service. Backends, sockets, Downloads watch, audit, root `--apply`. `/usr/libexec`. |
| `daemon` | `ghost-sentri-installer`   | Privileged headless install **worker** (pkexec'd on demand).      |
| `daemon` | `ghost-sentri-dpkg-shim`   | Local `.deb` PATH-shim at `/usr/local/sbin/dpkg`; delegates to the apt-hook, fails open to the real dpkg. `/usr/libexec`. |
| `gui`    | `ghost-sentri`             | On-demand dashboard + installer UI. GTK4/libadwaita. `/usr/bin`.   |

At idle, only the headless daemon is resident — no GTK is mapped. The GUI is
launched on demand (tray, dashboard, or an intercepted install) and exits when
closed.

### Machine-policy model

Configuration is system-wide, root-owned policy at
`/etc/ghost-sentri/config.toml`. The daemon runs as a root systemd system
service (`ghost-sentri-daemon.service`). The install ships **inert** — no `.deb`
handler, no apt hook, no monitors — until a monitor is enabled. Each change made
from the dashboard is authorised through polkit (one administrator prompt per
Confirm), and the daemon then writes the config, the apt hook and the `.deb`
MIME default itself. `ghost-sentri-daemon --apply` remains for scripted or
offline use.

### Dashboard vs Settings

- **Dashboard** is a read-only situation report: which install handlers and
  monitors are active, the virus-definition version and freshness, memory
  overhead, and a live event log.
- **Settings** holds the controls: the monitor toggle grid (select, then Confirm
  Selections under one authorisation), the definition-update button, the
  Downloads watch folders and quarantine location, and the allow list.
- **Quarantine** lists the files the Downloads watch quarantined for you.

### Monitored install paths

- **Packaged Apps (apt / `.deb`)** — intercepted before dpkg executes; blocks
  until you approve or scan. Covers terminal `apt`, `nala` (repo **and** local
  `.deb`), `aptitude`, direct `dpkg -i`, and file-manager double-click. Local
  `.deb` installs that bypass the apt hook are caught by a `dpkg` PATH-shim
  resolved ahead of the real dpkg.
- **Downloads** — see *Downloads watch* below. Replaces the Wine / Windows and
  Flatpak monitors of earlier versions: a `.exe`, `.msi` or `.flatpak` saved to
  a download folder is scanned there.
- **Terminal Builds** — source/script installs (`make install`, `curl | bash`).
- **Snap** — **monitor and log only.** Snap exposes no pre-install gate a third
  party can hold, so (GS) detects and records its installs rather than blocking
  them; the dedicated installer performs the install.

### Downloads watch

- **Who and where:** every real user account (uid between `UID_MIN` and
  `UID_MAX` in `/etc/login.defs`, home under `/home`, a login shell). For each,
  the XDG download folder plus `~/Downloads` and any extra folders set in
  Settings — top level only, always inside that user's home.
- **What is scanned:** Linux packages and installers, scripts, Windows programs,
  Java archives, archives and disc images (the extension list is in the config),
  plus any file whose first bytes show it is a program (`ELF`, `MZ`, `#!`),
  whatever its name.
- **When:** after a download finishes (close-after-write or rename into the
  folder). Files arriving together are scanned in one ClamAV run after 5 s of
  quiet, at most 60 s after the first. A file already scanned clean is skipped.
  Downloads scans run at low CPU and disk priority, and an install scan always
  goes first.
- **Threats** are moved to that user's quarantine and the user gets a desktop
  notice (when logged in graphically; otherwise the dashboard shows the new
  items).
- **Never a silent pass:** files over 512 MB, archives whose contents exceed the
  scan limits, and files that fail to scan are left in place with a notice and
  a log line; a failed scan is retried once. RAR archives are scanned only when
  `libclamunrar` matches the installed ClamAV version.
- Every result is written to the audit log, `/var/log/ghost-sentri/events.jsonl`.

### Quarantine

Each user's quarantine is a folder in their own home (default `~/.quarantine`,
mode 0700). Quarantined files are kept at 0600 with execute permission removed,
alongside a `.manifest.json`. The file moves are made by a helper running as
that user, never as root. In the Quarantine tab you can **Restore** a file to
its folder (without the execute bit), **Restore and allow** it, or **Delete**
it — no password, since it is your own folder. A restored file is not
re-quarantined from your download folders.

### Allow list (false positives)

If ClamAV flags a file you trust, you can allow that **exact file** by its
SHA256 hash. It then skips the virus scan everywhere on the machine —
downloads, apt and double-click installs — from any source. Any other version,
rebuild or tampered copy has a different hash and is scanned as usual; package
script checks still run. Adding or removing an entry needs administrator
approval. The list is `/etc/ghost-sentri/allowlist.toml`, shown and editable in
Settings, and every change is written to the audit log.

When an apt install is blocked, the terminal message prints the command, and in
a graphical session an *Install blocked* dialog offers **Allow and retry**:

```bash
ghost-sentri --allow <sha256> <threat> <package>
```

Then run the install again.

---

## Prerequisites

- **ClamAV** — `clamav` and `clamav-base` ((GS) shells out to
  `clamscan`). Offered for install on first use if absent.
- **polkit** — for the authorisation prompts (monitor changes, definition
  updates, allow list, privileged install).
- **libnotify-bin** (recommended) — desktop notices from the Downloads watch.
  Without it, new quarantine items still show in the dashboard.
- A graphical desktop session for the dashboard and the authorisation prompts.
  The daemon itself is a system service and needs no session.

Runtime dependencies are declared in the `DEBIAN/control` that `build.sh`
generates.

---

## Compatibility

Built and tested against Linux Mint 21–22 / Ubuntu 24.04 (GTK4 + libadwaita),
packaged as a native `.deb`. The interceptor backends are apt/dpkg-based today;
the privileged `--apply` path is structured by role so `dnf`/`pacman` support
can slot in later — multi-distro is on the roadmap, not in this build.

---

## Building

```bash
chmod +x build.sh && ./build.sh
```

Produces `dist/ghost-sentri_<version>_amd64.deb` and installs it (uses sudo).
The version is `MAJOR.MINOR` from `gui/Cargo.toml` plus a build-counter patch,
stamped back into `gui/Cargo.toml` so the About/welcome version always matches
the `.deb`. A fresh checkout has no counter and continues from the version in
`gui/Cargo.toml`.

---

## License

GPL-3.0-only. See [`COPYING`](./COPYING).

Copyright (C) 2026 archerprojects (archer.projects@proton.me)
