#!/usr/bin/env bash
# ProxMenux Monitor - deploy / roll back / remove the Authentik (OIDC) build.
#
#   oidc-deploy.sh install <ProxMenux-Monitor.AppImage>   upgrade in place (backup + auto-rollback)
#   oidc-deploy.sh rollback [--restore-config]             back to the pre-upgrade build
#   oidc-deploy.sh uninstall-oidc                          remove all OIDC data, keep the new build
#   oidc-deploy.sh status
#
# Existing configuration (auth.json, notification/health settings, ...) lives in
# ~/.config/proxmenux-monitor and is never modified by `install`; the OIDC
# database is migrated automatically on first start.  Must run as root on the
# Proxmox host.  Paths can be overridden for testing (see variables below).
set -euo pipefail

BASE_DIR="${PMX_BASE_DIR:-/usr/local/share/proxmenux}"
RUNTIME_DIR="${PMX_RUNTIME_DIR:-$BASE_DIR/monitor-app}"
CONFIG_DIR="${PMX_CONFIG_DIR:-/root/.config/proxmenux-monitor}"
BACKUP_ROOT="${PMX_BACKUP_DIR:-/root/proxmenux-oidc-backup}"
SERVICE="${PMX_SERVICE:-proxmenux-monitor.service}"
PORT="${PMX_PORT:-8008}"
PREV_DIR="${RUNTIME_DIR}.pre-oidc"

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m  %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m  %s\n' "$*" >&2; exit 1; }

need_root() { [ "${PMX_ALLOW_NONROOT:-0}" = 1 ] || [ "$(id -u)" -eq 0 ] || die "run as root"; }

health_check() {
    # The Monitor answers on http or https depending on the SSL setting.
    local i url
    for i in $(seq 1 30); do
        for url in "http://127.0.0.1:$PORT" "https://127.0.0.1:$PORT"; do
            if curl -fsk --max-time 3 "$url/api/auth/oidc/info" >/dev/null 2>&1; then return 0; fi
        done
        sleep 1
    done
    return 1
}

stop_service()  { systemctl stop  "$SERVICE" 2>/dev/null || true; }
start_service() { systemctl start "$SERVICE"; }

extract_appimage() {
    local appimage="$1" tmp
    tmp="$(mktemp -d /tmp/proxmenux-oidc-extract.XXXXXX)"
    ( cd "$tmp" && chmod +x "$appimage" && "$appimage" --appimage-extract >/dev/null 2>&1 ) \
        || { rm -rf "$tmp"; die "could not extract the AppImage"; }
    [ -x "$tmp/squashfs-root/AppRun" ] || { rm -rf "$tmp"; die "AppImage has no AppRun"; }
    [ -f "$tmp/squashfs-root/usr/bin/oidc_manager.py" ] || { rm -rf "$tmp"; die "this AppImage does not contain the OIDC extension"; }
    rm -rf "${RUNTIME_DIR}.new"
    mv "$tmp/squashfs-root" "${RUNTIME_DIR}.new"
    rm -rf "$tmp"
}

cmd_install() {
    need_root
    local appimage="${1:-}"
    [ -n "$appimage" ] && [ -f "$appimage" ] || die "usage: $0 install <ProxMenux-Monitor.AppImage>"
    [ -d "$RUNTIME_DIR" ] || die "no existing installation at $RUNTIME_DIR (use install_proxmenux.sh for a fresh install)"

    local sha="${appimage}.sha256"
    if [ -f "$sha" ]; then
        say "verifying checksum"
        ( cd "$(dirname "$appimage")" && sha256sum -c "$(basename "$sha")" ) || die "checksum mismatch"
    else
        warn "no .sha256 next to the AppImage - integrity not verified"
    fi

    local ts backup
    ts="$(date +%Y%m%d-%H%M%S)"
    backup="$BACKUP_ROOT/$ts"
    mkdir -p "$backup"; chmod 700 "$BACKUP_ROOT" "$backup"
    say "backing up configuration to $backup"
    if [ -d "$CONFIG_DIR" ]; then
        tar -C "$(dirname "$CONFIG_DIR")" -czf "$backup/config.tar.gz" "$(basename "$CONFIG_DIR")"
        chmod 600 "$backup/config.tar.gz"
    fi
    echo "$backup" > "$BASE_DIR/.oidc-last-backup" 2>/dev/null || true

    say "extracting new build"
    extract_appimage "$appimage"

    say "switching runtime (previous build kept in $PREV_DIR)"
    stop_service
    rm -rf "$PREV_DIR"
    mv "$RUNTIME_DIR" "$PREV_DIR"
    mv "${RUNTIME_DIR}.new" "$RUNTIME_DIR"
    start_service

    say "waiting for the Monitor to come up (database migration runs on first start)"
    if health_check; then
        say "OK - OIDC build is running. Configure it under Security -> Identity Provider."
        say "rollback anytime:  $0 rollback"
    else
        warn "health check failed - rolling back automatically"
        cmd_rollback
        die "upgrade aborted; the previous build was restored"
    fi
}

cmd_rollback() {
    need_root
    [ -d "$PREV_DIR" ] || die "nothing to roll back to ($PREV_DIR missing)"
    local restore_cfg=0
    [ "${1:-}" = "--restore-config" ] && restore_cfg=1
    say "restoring previous build"
    stop_service
    rm -rf "${RUNTIME_DIR}.failed"
    mv "$RUNTIME_DIR" "${RUNTIME_DIR}.failed"
    mv "$PREV_DIR" "$RUNTIME_DIR"
    # The old build does not know the OIDC files; park them so nothing reads them.
    if [ -d "$CONFIG_DIR" ]; then
        mkdir -p "$BACKUP_ROOT/parked"
        for f in oidc.json oidc.key oidc.db; do
            [ -e "$CONFIG_DIR/$f" ] && mv "$CONFIG_DIR/$f" "$BACKUP_ROOT/parked/$f.$(date +%s)"
        done
    fi
    if [ "$restore_cfg" = 1 ]; then
        local last; last="$(cat "$BASE_DIR/.oidc-last-backup" 2>/dev/null || true)"
        [ -f "$last/config.tar.gz" ] || die "no config backup recorded"
        say "restoring configuration from $last"
        tar -C "$(dirname "$CONFIG_DIR")" -xzf "$last/config.tar.gz"
    fi
    start_service
    say "rollback complete (failed build kept in ${RUNTIME_DIR}.failed)"
}

cmd_uninstall_oidc() {
    need_root
    say "removing OIDC configuration, encryption key and users (local account untouched)"
    mkdir -p "$BACKUP_ROOT/parked"; chmod 700 "$BACKUP_ROOT"
    stop_service
    for f in oidc.json oidc.key oidc.db; do
        [ -e "$CONFIG_DIR/$f" ] && mv "$CONFIG_DIR/$f" "$BACKUP_ROOT/parked/$f.$(date +%s)"
    done
    rm -f "$CONFIG_DIR"/oidc.db.bak-v*
    start_service
    say "done. Parked copies are in $BACKUP_ROOT/parked - delete them when no longer needed."
}

cmd_status() {
    echo "runtime : $RUNTIME_DIR ($( [ -f "$RUNTIME_DIR/usr/bin/oidc_manager.py" ] && echo 'OIDC build' || echo 'no OIDC' ))"
    echo "previous: $( [ -d "$PREV_DIR" ] && echo "$PREV_DIR (rollback possible)" || echo none )"
    echo "oidc cfg: $( [ -f "$CONFIG_DIR/oidc.json" ] && echo present || echo absent )"
    systemctl is-active "$SERVICE" 2>/dev/null || true
}

case "${1:-}" in
    install)        shift; cmd_install "$@" ;;
    rollback)       shift; cmd_rollback "$@" ;;
    uninstall-oidc) cmd_uninstall_oidc ;;
    status)         cmd_status ;;
    *) sed -n '2,12p' "$0"; exit 2 ;;
esac
