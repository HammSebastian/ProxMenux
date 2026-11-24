# Installing the OIDC-enabled ProxMenux Monitor

Everything below runs as **root on the Proxmox host**. Existing settings
(`/root/.config/proxmenux-monitor/*`: local account, 2FA, API tokens, notifications, …) are kept; nothing in
`auth.json` is rewritten. The OIDC database is created/migrated automatically on first use.

## 1. Build

```bash
cd AppImage
npm install --legacy-peer-deps        # done by the build script as well
bash scripts/build_appimage.sh        # -> AppImage/dist/ProxMenux-<version>.AppImage (+ .sha256)
```

The build needs network access (pip wheels for `cp311` and `cp313` incl. `cryptography`, `appimagetool`).
The existing build host requirements still apply (the script also bundles host tools such as `upsc`/NUT libraries, so build on the
release/CI machine, not on a bare workstation). It now fails if `cryptography` or the three OIDC modules are missing from the image.

## 2. Upgrade an existing installation

Copy `ProxMenux-<version>.AppImage` (and its `.sha256`) plus `docs/authentik-oidc/oidc-deploy.sh` to the host:

```bash
chmod +x oidc-deploy.sh
./oidc-deploy.sh install ./ProxMenux-<version>.AppImage
```

What it does

1. verifies the SHA-256, refuses an AppImage that does not contain the OIDC modules;
2. backs up `~/.config/proxmenux-monitor` to `/root/proxmenux-oidc-backup/<timestamp>/config.tar.gz` (0600);
3. extracts the new build next to the old one, stops the service, keeps the old runtime as
   `/usr/local/share/proxmenux/monitor-app.pre-oidc`, switches, starts the service;
4. waits up to 30 s for `GET /api/auth/oidc/info`; **if the Monitor does not answer it rolls back automatically**.

Alternatively use the normal ProxMenux update path once the release is published; the config directory is
shared, so the same steps (configure in the UI) apply.

After the upgrade OIDC is **off** and behaviour is identical to the previous version. Configure it under
**Security → Identity Provider** ([AUTHENTIK-SETUP.md](AUTHENTIK-SETUP.md)).

Optional environment variables for the service (`systemctl edit proxmenux-monitor`):

| Variable | Meaning |
|---|---|
| `PROXMENUX_TRUST_PROXY=1` | trust `X-Forwarded-For` (rate limiting / Fail2Ban) when running behind your reverse proxy |
| `PROXMENUX_CORS_ORIGINS` | existing option; not needed for OIDC because the SPA and API share one origin |

## 3. Roll back

Back to the previous build (OIDC files are parked, the local account and all other settings are untouched):

```bash
./oidc-deploy.sh rollback
```

If you also want the configuration exactly as it was before the upgrade:

```bash
./oidc-deploy.sh rollback --restore-config
```

Manual equivalent:

```bash
systemctl stop proxmenux-monitor
mv /usr/local/share/proxmenux/monitor-app /usr/local/share/proxmenux/monitor-app.failed
mv /usr/local/share/proxmenux/monitor-app.pre-oidc /usr/local/share/proxmenux/monitor-app
systemctl start proxmenux-monitor
# optional: tar -C /root/.config -xzf /root/proxmenux-oidc-backup/<timestamp>/config.tar.gz
```

Database rollback: before each schema upgrade `oidc.db` is copied to `oidc.db.bak-v<N>`; restore it by
stopping the service and copying it back over `oidc.db`.

## 4. Remove the OIDC extension

* Keep the new build but delete every OIDC trace (config, encryption key, users, sessions):

  ```bash
  ./oidc-deploy.sh uninstall-oidc
  ```

  (files are moved to `/root/proxmenux-oidc-backup/parked/` first). Local login works again immediately.
* Remove the code: `./oidc-deploy.sh rollback`.

## 5. Locked out? (break-glass)

If OIDC is misconfigured and local login is disabled, run on the host:

```bash
cd /usr/local/share/proxmenux/monitor-app/usr/bin
python3 oidc_manager.py disable      # OIDC off + local login on (takes effect immediately)
python3 oidc_manager.py status       # inspect (the secret is never printed)
```

(The local login is also always re-enabled automatically whenever OIDC is switched off or its runtime
dependencies are unavailable.)

## 6. Verifying

```bash
curl -s http://127.0.0.1:8008/api/auth/oidc/info         # {"enabled":false,...} on a fresh upgrade
journalctl -u proxmenux-monitor -n 50
ls -l /root/.config/proxmenux-monitor/oidc.*              # after configuration: all -rw-------
```

Development / CI: `python3 -m pytest tests` (install `flask flask-cors PyJWT cryptography requests pyotp segno
flask-sock` first).
