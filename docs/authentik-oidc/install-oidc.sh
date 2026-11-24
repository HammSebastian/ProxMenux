#!/usr/bin/env bash
# One-command installer: upgrades an existing ProxMenux Monitor on this Proxmox
# host to the OIDC (Authentik) build from the latest GitHub release.
#
#   bash -c "$(curl -fsSL https://github.com/HammSebastian/ProxMenux/releases/latest/download/install-oidc.sh)"
#
# Backs up the configuration, verifies the SHA-256, switches the build, checks
# that it starts and rolls back automatically if it does not.
set -euo pipefail

REPO="${PMX_REPO:-HammSebastian/ProxMenux}"
BASE="https://github.com/${REPO}/releases/latest/download"

[ "$(id -u)" -eq 0 ] || { echo "Run as root on the Proxmox host." >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required." >&2; exit 1; }
[ -d /usr/local/share/proxmenux/monitor-app ] || {
    echo "No existing ProxMenux Monitor found. Install ProxMenux first, then run this again." >&2; exit 1; }

tmp="$(mktemp -d /root/proxmenux-oidc-dl.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

echo "==> downloading the latest OIDC build from ${REPO}"
for f in ProxMenux-Monitor.AppImage ProxMenux-Monitor.AppImage.sha256 oidc-deploy.sh; do
    curl -fSL --retry 3 -o "$f" "$BASE/$f"
done
chmod +x oidc-deploy.sh
install -m 0755 oidc-deploy.sh /usr/local/share/proxmenux/oidc-deploy.sh
./oidc-deploy.sh install "$tmp/ProxMenux-Monitor.AppImage"

echo
echo "Done. Open ProxMenux Monitor -> Security -> Identity Provider to configure Authentik."
echo "Rollback: /usr/local/share/proxmenux/oidc-deploy.sh rollback"
