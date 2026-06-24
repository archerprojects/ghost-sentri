# FLATPAK_NOTES.md — Ghost Sentri Flatpak Build Handoff
# Session: Flatpak build deferred from v2.0 session
# Status: .deb build complete. Flatpak build is the next session objective.

## What is complete

Everything in `src/` is written to be Flatpak-aware:

- `config.rs` — `resolve_definition_path()` checks for bundled path, falls back to `/var/lib/clamav`
- `config.rs` — `resolve_clamscan()` checks config override, falls back to `/usr/bin/clamscan`
- `clam/mod.rs` — `BundledClamBackend` stub is present and ready to activate
- `backends/mod.rs` — all backends conditional via `config.backends.*` flags
- `.cargo/config.toml` — vendor block is commented, uncomment for Flatpak offline build

## What the Flatpak session needs to produce

1. `org.ghost.Sentri.yml` — Flatpak manifest
2. `vendor/` — vendored crates (`cargo vendor`)
3. Activated `BundledClamBackend` in `src/clam/mod.rs`
4. Updated `.cargo/config.toml` (uncomment vendor block)
5. Definition download logic (first-launch, ~230MB)
6. Updated `CLAUDE.md`

---

## Flatpak manifest decisions (pre-decided, load into next session)

### Runtime
```yaml
runtime: org.gnome.Platform
runtime-version: "47"   # Verify Flathub availability at session start
sdk: org.gnome.Sdk
sdk-extensions:
  - org.freedesktop.Sdk.Extension.rust-stable
```

> **Note:** We were on `//49` (dev track) during architecture discussion.
> Verify Flathub availability before committing. If 49 is not on Flathub,
> use the highest stable available. Do NOT use dev track in production manifest.

### Finish args (required)
```yaml
finish-args:
  - --filesystem=home                  # quarantine at ~/.quarantine
  - --share=network                    # definition downloads
  - --socket=fallback-x11              # GTK4 fallback
  - --socket=wayland                   # primary display
  - --talk-name=org.freedesktop.Notifications
  - --system-talk-name=org.freedesktop.PackageKit  # PackageKit backend
  - --talk-name=org.kde.StatusNotifierWatcher      # tray icon
  - --talk-name=org.ayatana.indicator              # Ayatana tray
```

### Modules (order matters)
1. `libclamav` — built from source as Flatpak module
2. `ghost-sentri` — Rust build using the `rust-stable` SDK extension

### ClamAV as Flatpak module
```yaml
- name: clamav
  buildsystem: cmake-ninja
  config-opts:
    - -DENABLE_CLAMONACC=OFF
    - -DENABLE_MILTER=OFF
    - -DENABLE_FRESHCLAM=ON
    - -DCMAKE_INSTALL_PREFIX=/app
  sources:
    - type: archive
      url: https://www.clamav.net/downloads/production/clamav-1.4.0.tar.gz
      sha256: <sha256 at session time>
```

### Rust build module
```yaml
- name: ghost-sentri
  buildsystem: simple
  build-commands:
    - cargo --offline build --release
    - install -Dm755 target/release/ghost-sentri /app/bin/ghost-sentri
  sources:
    - type: dir
      path: .
    - type: dir
      path: vendor
      dest: vendor
  build-options:
    append-path: /usr/lib/sdk/rust-stable/bin
    env:
      CARGO_HOME: /run/build/ghost-sentri/cargo-home
```

---

## BundledClamBackend activation steps

In `src/clam/mod.rs`, `BundledClamBackend::is_available()` currently returns `false`.

For Flatpak:
1. Set `clamscan_path` in config to `/app/bin/clamscan` (bundled)
2. OR activate the bundled backend to call libclamav directly via FFI

**Recommended for v2.0 Flatpak**: use bundled `clamscan` binary path (simpler than FFI):
```rust
// config.rs resolve_clamscan() — add Flatpak detection
if std::path::Path::new("/app/bin/clamscan").exists() {
    return PathBuf::from("/app/bin/clamscan");
}
```

**v2.1 option**: FFI to libclamav directly (eliminates subprocess overhead):
- Add `libclamav-sys` or write bindgen bindings
- `BundledClamBackend::scan_file()` calls `cl_scanfile()` directly

---

## Definition path for Flatpak

```
~/.var/app/org.ghost.Sentri/data/clamav/
```

In `config.rs`, `resolve_definition_path()`:
```rust
// Add before the native .deb fallback:
let flatpak_path = dirs::data_dir()  // ~/.var/app/.../data
    .map(|p| p.join("clamav"));
if let Some(p) = flatpak_path {
    if p.exists() || std::env::var("FLATPAK_ID").is_ok() {
        return p;
    }
}
```

First launch:
- Download `main.cvd` + `daily.cvd` from database.clamav.net (~230MB total)
- Show download progress dialog before first scan is attempted
- Definitions update independently of app updates via the definition management panel

---

## Tray icon in Flatpak

Ayatana AppIndicator requires `libayatana-appindicator3` which may not be in the GNOME runtime.

Options (in order of preference):
1. **StatusNotifier direct** (recommended): `tray-icon` crate supports StatusNotifier natively. Works in GNOME, KDE, Cinnamon without the AppIndicator library.
2. **Bundle Ayatana**: add `libayatana-appindicator3` as a Flatpak module (complex build, many deps).
3. **No tray in Flatpak**: run as a foreground window app with autostart `.desktop` entry.

Recommendation: go with StatusNotifier direct. The `tray-icon` crate handles this transparently on Wayland/X11.

---

## apt hook in Flatpak

The APT hook (`/etc/apt/apt.conf.d/99ghost-sentri`) **cannot be installed by a Flatpak**.
Flatpak apps cannot write to `/etc`.

Flatpak intercept strategy:
- **PackageKit backend**: works via DBus (already implemented, `--system-talk-name` in finish-args)
- **Shell wrapper backend**: still works for terminal-initiated installs
- **inotify backends**: Flatpak + `--filesystem=home` can watch `~/Downloads` etc.
- **APT hook**: document as "not available in Flatpak build — use .deb for full intercept coverage"

---

## Vendor preparation (before session)

Run this on a machine with internet access before starting the Flatpak session:
```bash
cargo vendor
# Then uncomment the [source] block in .cargo/config.toml
```

Vendor directory will be ~200-300MB. Commit it or transfer with the source tree.

---

## Session checklist

- [ ] Verify GNOME runtime version available on Flathub
- [ ] Download ClamAV source tarball + sha256
- [ ] Run `cargo vendor`
- [ ] Uncomment vendor block in `.cargo/config.toml`
- [ ] Activate BundledClamBackend / bundled clamscan path
- [ ] Write `org.ghost.Sentri.yml`
- [ ] Test build with `flatpak-builder`
- [ ] Test definition download on first launch
- [ ] Test PackageKit intercept (replaces APT hook)
- [ ] Test tray icon on Wayland and X11
- [ ] Submit to Flathub (separate session)
