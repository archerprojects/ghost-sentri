#!/usr/bin/env bash
# build.sh — v4.2
# Ghost Sentri workspace build + .deb assembly (Linux Mint target).
#
# Builds the 3-crate workspace and stages three binaries:
#   ghost-sentri            -> /usr/bin/ghost-sentri          (user GUI: dashboard + installer)
#   ghost-sentri-daemon     -> /usr/libexec/ghost-sentri-daemon     (resident, headless)
#   ghost-sentri-installer  -> /usr/libexec/ghost-sentri-installer  (privileged worker, pkexec'd)
#   ghost-sentri-dpkg-shim  -> /usr/libexec/ghost-sentri-dpkg-shim   (local .deb PATH-shim)
#
# Manual dpkg-deb assembly — the compiled binaries ARE the packaged binaries.
#
# Usage:
#   ./build.sh              build .deb and install
#   ./build.sh --build-only compile only, no .deb
#   ./build.sh --clean      cargo clean then build
#   ./build.sh --deps       install build deps only
#   ./build.sh --enable-apt build, install, then ARM the apt monitor (test loops)

set -euo pipefail

BOLD='\033[1m'; RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'; CYN='\033[0;36m'; RST='\033[0m'

PKG_NAME="ghost-sentri"
ARCH="$(dpkg --print-architecture)"
DIST_DIR="$(pwd)/dist"
STAGING="$(pwd)/.deb-staging"

BUILD_COUNTER_FILE="$(pwd)/.build_counter"
if [ -f "$BUILD_COUNTER_FILE" ]; then
    BUILD_NUM=$(($(cat "$BUILD_COUNTER_FILE") + 1))
else
    BUILD_NUM=1
fi
echo "$BUILD_NUM" > "$BUILD_COUNTER_FILE"

# Version scheme: MAJOR.MINOR is the single source of truth in gui/Cargo.toml;
# the build counter is the PATCH, so each build climbs 1.0.0, 1.0.1, 1.0.2, …
# The computed version is stamped back into gui/Cargo.toml before compiling, so
# the About/welcome version (env!("CARGO_PKG_VERSION")) always matches the .deb.
# Reset the sequence by deleting .build_counter; bump MAJOR.MINOR by editing
# gui/Cargo.toml (e.g. 1.0.x -> 1.1.0) and deleting .build_counter.
BASE_VERSION="$(grep -m1 '^version' gui/Cargo.toml | cut -d'"' -f2 | cut -d. -f1,2)"
PATCH=$((BUILD_NUM - 1))
PKG_VERSION="${BASE_VERSION}.${PATCH}"
sed -i "s/^version = \".*\"/version = \"${PKG_VERSION}\"/" gui/Cargo.toml

BUILD_ONLY=false; CLEAN=false; DEPS_ONLY=false; ENABLE_APT=false
for arg in "$@"; do
    case "$arg" in
        --build-only) BUILD_ONLY=true ;;
        --clean)      CLEAN=true ;;
        --deps)       DEPS_ONLY=true ;;
        --enable-apt) ENABLE_APT=true ;;
        --help|-h)    echo "Usage: $0 [--build-only] [--clean] [--deps] [--enable-apt]"; exit 0 ;;
    esac
done

log()  { echo -e "${CYN}[ghost-sentri]${RST} $*"; }
ok()   { echo -e "${GRN}[  OK  ]${RST} $*"; }
warn() { echo -e "${YLW}[ WARN ]${RST} $*"; }
fail() { echo -e "${RED}[ FAIL ]${RST} $*"; exit 1; }

echo -e "${BOLD}  Ghost Sentri v${PKG_VERSION} — Workspace Build${RST}"
echo -e "  Target: ${ARCH} .deb -> dist/"
echo ""

check_deps() {
    log "Checking build dependencies..."
    local missing=()
    if ! command -v cargo &>/dev/null; then
        missing+=("cargo (rustup: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh)")
    else
        log "Rust: $(cargo --version | grep -oP '\d+\.\d+' | head -1)"
    fi
    local pkgs=( "dpkg-dev" "libgtk-4-dev" "libadwaita-1-dev" "libdbus-1-dev" "pkg-config" )
    for pkg in "${pkgs[@]}"; do
        dpkg -s "$pkg" &>/dev/null || missing+=("$pkg")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        warn "Missing dependencies:"
        for dep in "${missing[@]}"; do echo "    - $dep"; done
        echo ""
        read -rp "Install missing system packages with apt? [Y/n] " answer
        if [[ "${answer,,}" != "n" ]]; then
            local apt_pkgs=()
            for dep in "${missing[@]}"; do [[ "$dep" != *"rustup"* ]] && apt_pkgs+=("$dep"); done
            [ ${#apt_pkgs[@]} -gt 0 ] && sudo apt-get install -y "${apt_pkgs[@]}"
            [[ "${missing[*]}" == *"cargo"* ]] && fail "Install Rust via rustup, then re-run."
        else
            fail "Cannot build without dependencies."
        fi
    fi
    ok "Build dependencies satisfied"
}

build_binaries() {
    [ "$CLEAN" = true ] && { log "cargo clean..."; cargo clean; }
    log "Building workspace ${PKG_VERSION} (release)..."

    # Force a fresh build of the three shipped binaries so a prior build's
    # artifact can never be packaged after a failed/short-circuited compile.
    rm -f target/release/ghost-sentri target/release/ghost-sentri-daemon \
          target/release/ghost-sentri-installer target/release/ghost-sentri-dpkg-shim

    # Abort the whole build if compilation fails — never fall through to staging
    # with a stale binary still on disk.
    cargo build --release || fail "cargo build failed — aborting (no .deb produced)."

    for b in ghost-sentri ghost-sentri-daemon ghost-sentri-installer ghost-sentri-dpkg-shim; do
        [ -f "target/release/$b" ] || fail "missing binary after build: target/release/$b"
    done
    ok "Binaries: ghost-sentri ($(du -h target/release/ghost-sentri | cut -f1)), \
daemon ($(du -h target/release/ghost-sentri-daemon | cut -f1)), \
installer ($(du -h target/release/ghost-sentri-installer | cut -f1))"
}

assemble_deb() {
    log "Assembling .deb..."
    rm -rf "$STAGING"
    mkdir -p \
        "$STAGING/DEBIAN" \
        "$STAGING/usr/bin" \
        "$STAGING/usr/libexec" \
        "$STAGING/usr/share/applications" \
        "$STAGING/usr/share/polkit-1/actions" \
        "$STAGING/lib/systemd/system" \
        "$STAGING/usr/share/ghost-sentri"

    # ── Binaries ────────────────────────────────────────────────────────────
    # User-facing command.
    install -Dm755 target/release/ghost-sentri            "$STAGING/usr/bin/ghost-sentri"
    # Internal helpers — not on the user's PATH.
    install -Dm755 target/release/ghost-sentri-daemon     "$STAGING/usr/libexec/ghost-sentri-daemon"
    install -Dm755 target/release/ghost-sentri-installer  "$STAGING/usr/libexec/ghost-sentri-installer"
    # Local .deb PATH-shim — staged into the package; the SYMLINK at
    # /usr/local/sbin/dpkg is created by the daemon when the apt monitor is armed
    # (apply.rs), never shipped here, so installs stay inert by default.
    install -Dm755 target/release/ghost-sentri-dpkg-shim   "$STAGING/usr/libexec/ghost-sentri-dpkg-shim"
    for b in usr/bin/ghost-sentri usr/libexec/ghost-sentri-daemon usr/libexec/ghost-sentri-installer usr/libexec/ghost-sentri-dpkg-shim; do
        strip "$STAGING/$b" 2>/dev/null || true
    done

    # ── Desktop entry ───────────────────────────────────────────────────────
    install -Dm644 ghost-sentri.desktop \
        "$STAGING/usr/share/applications/ghost-sentri.desktop"

    # ── systemd system service ──────────────────────────────────────────────
    # The daemon runs as a ROOT system service (always on; inert until monitors
    # are enabled). postinst enables + starts it; postrm stops + disables it.
    install -Dm644 debian/ghost-sentri-daemon.service \
        "$STAGING/lib/systemd/system/ghost-sentri-daemon.service"

    # ── Polkit policy — install prompt + manage (CheckAuthorization) action ──
    install -Dm644 com.archerprojects.ghost-sentri.policy \
        "$STAGING/usr/share/polkit-1/actions/com.archerprojects.ghost-sentri.policy"

    # ── APT hook TEMPLATE ───────────────────────────────────────────────────
    # NOT installed into /etc/apt/apt.conf.d — the apt monitor is OFF by default.
    # The daemon copies this template into place when the user enables the
    # "Packaged Apps" monitor (and removes it on disable).
    install -Dm644 debian/ghost-sentri.apt-conf \
        "$STAGING/usr/share/ghost-sentri/99ghost-sentri"

    # ── Icons ───────────────────────────────────────────────────────────────
    for sz in 16x16 22x22 24x24 32x32 48x48 64x64 128x128 256x256; do
        install -Dm644 "icons/hicolor/${sz}/apps/ghost-sentri.png" \
            "$STAGING/usr/share/icons/hicolor/${sz}/apps/ghost-sentri.png"
    done
    install -Dm644 icons/hicolor/scalable/apps/ghost-sentri.svg \
        "$STAGING/usr/share/icons/hicolor/scalable/apps/ghost-sentri.svg"
    install -Dm644 icons/lean-icons/apps/scalable/ghost-sentri.svg \
        "$STAGING/usr/share/icons/lean-icons/apps/scalable/ghost-sentri.svg"

    # ── DEBIAN/control ──────────────────────────────────────────────────────
    cat > "$STAGING/DEBIAN/control" <<EOF
Package: ghost-sentri
Version: ${PKG_VERSION}
Architecture: ${ARCH}
Maintainer: archerprojects <archer.projects@proton.me>
Depends: clamav (>= 0.103), clamav-base, clamav-freshclam, libgtk-4-1, libadwaita-1-0, libdbus-1-3, dbus, policykit-1 | polkitd
Recommends: clamav-daemon
Section: utils
Priority: optional
Homepage: https://github.com/archerprojects/Ghost-Sentri
Description: Security monitor and install interceptor using ClamAV
 Ghost Sentri intercepts package installs and scans them with ClamAV before
 they execute. A resident headless daemon watches install channels; an
 on-demand GUI provides the dashboard and the install/scan flow; a privileged
 helper performs the scan and install under a single authorization prompt.
 .
 ClamAV must be installed. Definition freshness is checked daily by the daemon;
 updates require explicit user authorisation via polkit.
EOF

    # ── DEBIAN/postinst + postrm ────────────────────────────────────────────
    sed '/^#DEBHELPER#/d' debian/postinst > "$STAGING/DEBIAN/postinst"
    chmod 755 "$STAGING/DEBIAN/postinst"
    if [ -f debian/postrm ]; then
        sed '/^#DEBHELPER#/d' debian/postrm > "$STAGING/DEBIAN/postrm"
        chmod 755 "$STAGING/DEBIAN/postrm"
    fi

    mkdir -p "$DIST_DIR"
    local deb_file="${DIST_DIR}/${PKG_NAME}_${PKG_VERSION}_${ARCH}.deb"
    dpkg-deb --build --root-owner-group "$STAGING" "$deb_file"
    rm -rf "$STAGING"
    ok ".deb ready: $deb_file"
    dpkg-deb --info "$deb_file"
}

install_deb() {
    local deb_file
    deb_file=$(find "$DIST_DIR" -name "${PKG_NAME}_*.deb" | sort | tail -1)
    [ -z "$deb_file" ] && { warn "No .deb in dist/"; return; }
    log "Installing $deb_file..."
    sudo apt-get install -y "$deb_file" || sudo dpkg -i "$deb_file"
    ok "Installed"

    # Stale-install gate: the daemon on disk must be byte-identical to the daemon
    # packaged in THIS .deb. Compares against the .deb's own copy (already stripped),
    # so stripping does not cause a false mismatch. Freshness of the .deb itself is
    # guaranteed by build_binaries (rm + rebuild + abort-on-fail).
    local deb_hash installed_hash
    deb_hash=$(dpkg-deb --fsys-tarfile "$deb_file" \
                 | tar -xO ./usr/libexec/ghost-sentri-daemon 2>/dev/null \
                 | sha256sum | cut -d' ' -f1)
    installed_hash=$(sudo sha256sum /usr/libexec/ghost-sentri-daemon 2>/dev/null | cut -d' ' -f1)
    if [ -z "$deb_hash" ] || [ "$deb_hash" != "$installed_hash" ]; then
        fail "INSTALLED DAEMON DOES NOT MATCH PACKAGED DAEMON — stale install.
       packaged:  $deb_hash
       installed: $installed_hash
       The .deb did not replace /usr/libexec/ghost-sentri-daemon. Do NOT test."
    fi
    ok "Verified: installed daemon matches packaged binary ($installed_hash)"
    echo ""
    echo -e "${GRN}  Ghost Sentri v${PKG_VERSION} installed${RST}"
    echo "  GUI:     /usr/bin/ghost-sentri"
    echo "  Daemon:  /usr/libexec/ghost-sentri-daemon   (root system service, inert until enabled)"
    echo "  Worker:  /usr/libexec/ghost-sentri-installer"
    echo ""
    echo "  Service: systemctl status ghost-sentri-daemon"
    echo "  Open the dashboard, enable monitors on the Settings tab and Confirm"
    echo "  (one authorisation). Changes apply system-wide and take effect live."
    echo ""
}

# Arm the apt monitor immediately after install, the same way a dashboard Confirm
# does — drives the daemon's own apply path (`--apply --enable apt`) so /etc config
# AND the apt.conf.d hook are written by the daemon (its sole-writer role), not
# hand-poked by this script. Without this, every ./build.sh reinstalls INERT and the
# apt hook must be re-enabled in the dashboard each test cycle. Off by default;
# --enable-apt opts in. Reports the OBSERVABLE outcome (the live hook file), not the
# config flag, so a silent apply failure can't masquerade as armed.
arm_apt() {
    log "Arming apt monitor (--apply --enable apt)..."
    if sudo /usr/libexec/ghost-sentri-daemon --apply --enable apt; then
        if [ -f /etc/apt/apt.conf.d/99ghost-sentri ]; then
            ok "apt monitor armed — Pre-Install-Pkgs hook live at /etc/apt/apt.conf.d/99ghost-sentri"
        else
            warn "apply returned success but the hook file is absent — check the daemon, the apt path is NOT armed"
        fi
    else
        warn "Could not arm apt monitor — enable 'Packaged Apps' in the dashboard instead"
    fi
}

[ "$DEPS_ONLY" = true ] && { check_deps; ok "Done."; exit 0; }
check_deps
[ "$BUILD_ONLY" = true ] && { build_binaries; exit 0; }
build_binaries
assemble_deb
install_deb
[ "$ENABLE_APT" = true ] && arm_apt
