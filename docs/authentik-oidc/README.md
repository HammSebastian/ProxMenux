# Native Authentik (OpenID Connect) login for ProxMenux Monitor

ProxMenux Monitor can use [Authentik](https://goauthentik.io) (or any standards-compliant OIDC provider)
as its identity provider. Users sign in with their Authentik account, are created on first login and
receive a ProxMenux role from their Authentik groups. The feature is **optional**: a default
installation without OIDC behaves exactly as before.

* Setup in Authentik: [AUTHENTIK-SETUP.md](AUTHENTIK-SETUP.md)
* Install / roll back / remove: [INSTALL.md](INSTALL.md)

---

## 1. Architecture found in the repository (analysis before the change)

| Topic | Finding (file) |
|---|---|
| Backend | Python 3 **Flask** app, one process, served by gevent (`AppImage/scripts/flask_server.py`, ~22k lines) plus blueprints `flask_*_routes.py`. |
| Frontend | **Next.js 15 / React 19** static export (`output: 'export'`), served by the same Flask process (`AppImage/app`, `AppImage/components`). i18n catalogs in `AppImage/messages/<lang>/common.json` (en is the fallback). |
| Authentication (before) | **Single local account** in `~/.config/proxmenux-monitor/auth.json` (`username`, PBKDF2 hash, optional TOTP). `auth_manager.py`. No user table. |
| Sessions | **Stateless HS256 JWT in the `Authorization: Bearer` header**, stored by the SPA in `localStorage`. Per-install secret in `auth.json`; claims `username, exp, iat, iss, aud[, scope]`; revocation list for API tokens. **No cookies.** |
| Roles (before) | Only the `scope` claim: `full_admin` (default, also legacy tokens) and `read_only` (API tokens). `@require_auth` blocks every non-GET for non-admin; `@require_admin_scope` demands `full_admin`. about 260 routes use `@require_auth`, about 56 `@require_admin_scope`. |
| Rate limiting / Fail2Ban | In-memory per-IP limiter on `/api/auth/login`; failures go to logger `proxmenux-auth` (Fail2Ban jail). |
| Configuration | JSON files in `~/.config/proxmenux-monitor/` (`/root/...` as the service runs as root); SQLite is used elsewhere (`health_persistence.py`, `audit_store.py`). |
| Packaging | `AppImage/scripts/build_appimage.sh` copies an **explicit list** of python files and pip-installs dependencies; per-ABI vendor trees (`cp311`, `cp313`) for compiled wheels. `install_proxmenux.sh` extracts the AppImage to `/usr/local/share/proxmenux/monitor-app` and runs it via `proxmenux-monitor.service`. |
| Tests | `tests/` (python `unittest`, node `.cjs`). |

Constraints that shaped the design

1. Auth is header-bearer, not cookie-session ➜ the OIDC callback cannot "log the browser in" by cookie.
   It ends with a **one-time code** that the SPA redeems for the same kind of JWT everything else already uses,
   so all existing routes keep working unchanged.
2. `cryptography` was deliberately *not* bundled (PyO3 ABI issues). PyJWT cannot verify RS256/ES256 without it.
   It is now added to the **per-ABI vendor trees**; if it is missing at runtime the OIDC feature reports itself as
   *unavailable* and everything else works.
3. The existing role model has no "user". The new scope `user` was added (see §4).

## 2. Authentication architecture

```
Browser                     ProxMenux Monitor (Flask)                      Authentik
  | GET /api/auth/oidc/login ------>|  begin_login(): discovery, state, nonce, PKCE verifier,
  |                                 |  browser-binding secret -> SQLite (hashed); cookie pmx_oidc
  |<-- 302 + Set-Cookie pmx_oidc ---|
  | ---------------------------- authorize?...&code_challenge=S256&state&nonce -------------->|
  |<----------------------------------------- 302 /api/auth/oidc/callback?code&state ---------|
  | GET callback (+cookie) -------->|  consume state (single use, 10 min), check binding cookie,
  |                                 |  POST token endpoint (code + code_verifier, client auth)  ---->|
  |                                 |<-------------------------------- id_token + access_token ----|
  |                                 |  PyJWT verifies signature (JWKS), iss, aud, exp, iat, nonce, azp
  |                                 |  groups -> role; upsert user by (issuer, sub); create session
  |<-- 302 /?oidc_code=<one-time> --|
  | POST /api/auth/oidc/exchange --->|  code single use, 60 s, bound to the same browser cookie
  |<-- { token } (fresh JWT) --------|  JWT: scope, src=oidc, sid (never reused from before login)
```

Every later request carries the JWT; `verify_token_full` sees `src=oidc` and **re-checks the server-side
session and user record** (revoked? disabled? expired? OIDC still on? same issuer?). The effective scope is
taken from the database, not from the token.

* Library use: **PyJWT** (`jwt.decode`, `PyJWKSet`) for all signature/claim validation; `requests` for HTTP;
  `cryptography.Fernet` for the stored secret. No hand-written crypto.
* Algorithms: asymmetric only (RS/PS/ES/EdDSA). `HS256` and `none` are rejected, so the client secret can never
  act as a signing key. The provider therefore needs a **signing key** (see Authentik guide).
* Refresh tokens: **not requested/stored.** Sessions live for the configured *Session timeout* (default 8 h,
  5 min – 30 days) and then require a new sign-in, which re-reads the groups. This keeps no long-lived upstream
  credential on the host. (If you want silent renewal later: request `offline_access`, store the refresh token
  encrypted in `sessions`.)
* Logout: `POST /api/auth/oidc/logout` revokes the server session and returns the provider's
  `end_session_endpoint` URL (with `id_token_hint`, `post_logout_redirect_uri`) which the SPA navigates to
  (central logout). Controlled by the *OIDC Logout* switch.

### Endpoints (`flask_oidc_routes.py`)

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /api/auth/oidc/info` | none | provider name + flags for the login page |
| `GET /api/auth/oidc/login` | none, rate-limited | start login (302 to IdP) |
| `GET /api/auth/oidc/callback` | none, rate-limited | **Redirect URI** – finish login |
| `POST /api/auth/oidc/exchange` | one-time code + cookie | code → session token |
| `POST /api/auth/oidc/logout` | session | revoke + central logout URL |
| `GET/PUT /api/auth/oidc/settings` | admin | configuration (secret write-only) |
| `POST /api/auth/oidc/test` | admin | discovery + JWKS test, returns discovery document |
| `GET/PATCH/DELETE /api/auth/oidc/users[/<id>]` | admin | list / disable / delete OIDC users |

`/api/auth/status` additionally returns `oidc` (public info), `local_login_allowed` and, for an authenticated
caller, `session` (`username`, `scope`, `source`).

## 3. Users, identity and storage

SQLite `~/.config/proxmenux-monitor/oidc.db` (0600, versioned migrations via `PRAGMA user_version`, a copy
`oidc.db.bak-v<N>` is taken before every upgrade):

* `users` – `issuer`, `subject` (**UNIQUE(issuer, subject)** = the identity), `username`, `email`,
  `display_name`, `groups` (JSON), `role`, `disabled`, `created_at`, `last_login`
* `sessions` – `sid`, user, encrypted `id_token` (for logout hint), expiry, `revoked`
* `transactions` / `exchange_codes` – short-lived login state (stored hashed)

**E-mail is never used to find or link an account**; a user with the same e-mail but a different `sub`
is a different account. OIDC identities are never merged with the local account: the JWT username is
`oidc:<preferred_username>` and OIDC sessions are refused on every endpoint that manages the local account
(password, 2FA, API-token creation, local profile/avatar, disabling authentication).

Configuration: `oidc.json` (0600). The client secret is stored **Fernet-encrypted**; the key is a separate
0600 file `oidc.key`. It is never returned by the API (`client_secret_set: true` only) and never logged.

## 4. Roles and group mapping

| Role | Token scope | May do |
|---|---|---|
| Administrator | `full_admin` | everything (same as the local admin) |
| Benutzer / User | `user` | all reads + the allow-list in `rbac.py`: guest start/stop/shutdown/reboot, LXC update *checks*, per-guest app checks, guest backup, custom links. **Everything else that changes state is denied (deny by default).** |
| Read Only | `read_only` | GET/HEAD/OPTIONS only |
| – | – | no mapped group and `default_role = none` ➜ sign-in refused, no session, no user row |

Mapping: *Admin group* / *User group* / *Read-only group* settings (comma-separated lists allowed), claim name
configurable (*Group claim*, dotted paths such as `realm.groups` work). If the claim is not in the ID token the
`userinfo` endpoint is queried (its `sub` must match). A user in several groups gets the **highest** role.
The role is recomputed at every login. Enforcement is in `jwt_middleware.require_auth` /
`require_admin_scope` / `require_local_session` on **every request**; the UI hides nothing that the server would
allow. Routes protected by `require_admin_scope` (power, updates, settings, secrets…) are admin-only by
construction.

## 5. Settings → Identity Provider

Card **Identity Provider (OpenID Connect)** on the *Security* page, directly under *Authentication*
(`components/identity-provider-settings.tsx`): Enable OIDC, Provider name, Issuer URL, Client ID, Client secret,
Public URL (shows the exact Redirect URI), Scopes, Group claim, Admin/User/Read-only group, Default role,
Automatic user provisioning, Allow local login, OIDC logout, Session timeout, **Test connection** (discovery +
JWKS, shows the discovery document), last connection status, and a user list (disable / delete).
Safeguards: OIDC can only be enabled while local authentication is set up (break-glass + API stays protected);
*Allow local login = off* is refused until a connection test has succeeded since the last connection change.

Login page: *Sign in with Authentik* button; the local form is shown below it, or hidden when local login is
disabled (the backend then also rejects `/api/auth/login` and password-based API-token creation with HTTP 403).

## 6. Security assessment

| Requirement | Implementation |
|---|---|
| Auth-code flow + PKCE S256 | yes; provider must advertise S256; verifier 86 chars random |
| State / nonce | 256-bit random, single-use, 10 min TTL, stored hashed; nonce compared in constant time |
| **Login CSRF** | state is bound to the initiating browser by an HttpOnly cookie `pmx_oidc` (hash in DB); callback without it ➜ rejected |
| CSRF on the API | API auth is a Bearer header (not a cookie), so cross-site requests carry no credentials; the only cookie is the Lax, path-scoped login-binding cookie |
| Session fixation | no pre-login session is ever promoted; a fresh JWT + `sid` is minted at exchange; one-time code is single-use, 60 s, bound to the browser cookie, removed from the URL by the SPA, `Referrer-Policy: no-referrer` on the redirect |
| Cookie flags | `HttpOnly`, `SameSite=Lax` (required for the cross-site redirect back), `Path=/api/auth/oidc`, `Secure` when the Public URL is https (or request is TLS), 10 min |
| Token validation | signature (JWKS, key rotation = one forced refetch), `iss` exact match, `aud`, `exp`, `iat`, required claims, `nonce`, `azp`; HS*/none rejected; discovery `issuer` must equal the configured issuer (mix-up) |
| Transport | issuer and all discovered endpoints must be https (http only for localhost); no redirects followed; 1 MB response cap; 5/10 s timeouts |
| Authorization | server-side per request; live DB scope; deny-by-default allow-list for `user` |
| Secrets | Fernet at rest, 0600 files, write-only API, not in logs/responses (covered by tests) |
| Logs | only reason codes; failures use the existing Fail2Ban format `authentication failure; rhost=…` |
| Rate limiting | 20 requests / 5 min / IP on login, callback and exchange; transaction table capped at 500 |
| Fail-safe | OIDC off/unavailable ➜ local login always allowed; CLI break-glass `oidc_manager.py disable` |

Known limitations / decisions to be aware of

* Read access is *all* `GET` routes for both `user` and `read_only` – the same exposure the existing
  read-only API tokens already had. Interactive terminal/script execution, power actions, updates and settings are
  `require_admin_scope` and therefore admin-only.
* The `user` allow-list is deliberately small; extend `rbac.py` if you want more for that role.
* Group changes in Authentik apply at next sign-in (or when the session timeout expires); disabling a user in
  ProxMenux or turning OIDC off takes effect immediately.
* Behind a reverse proxy the browser must reach ProxMenux under the **same host as the Public URL** (the binding
  cookie is host-scoped). Set `PROXMENUX_TRUST_PROXY=1` so rate limiting/Fail2Ban see the real client IP.
* Tokens live in `localStorage` (existing design of the Monitor); this is unchanged and XSS-exposed in the
  same way as before.
* Plain-http deployments work but produce a warning (cookie not `Secure`, secrets cross the LAN only between
  host and IdP over https).
* Single-process assumption for the in-memory rate limiter (same as the existing login limiter); all OIDC state
  itself is in SQLite.

## 7. Files

New
* `AppImage/scripts/oidc_manager.py` – config, secret encryption, discovery/JWKS, flow, users/sessions, migrations, CLI
* `AppImage/scripts/flask_oidc_routes.py` – HTTP endpoints
* `AppImage/scripts/rbac.py` – roles → scopes, allow-list
* `AppImage/components/identity-provider-settings.tsx` – settings card
* `tests/test_oidc_integration.py` – 68 tests
* `docs/authentik-oidc/*` – this documentation and `oidc-deploy.sh`

Changed
* `AppImage/scripts/auth_manager.py` – `generate_token(scope, expires_in, extra_claims)`, OIDC session enforcement in `verify_token(_full)`, `get_session_info`, local-login switch in `authenticate`
* `AppImage/scripts/jwt_middleware.py` – `user` scope allow-list, `require_local_session`
* `AppImage/scripts/flask_auth_routes.py` – status block, login gate, local-account-only guards, OIDC profile
* `AppImage/scripts/flask_server.py` – blueprint registration
* `AppImage/scripts/build_appimage.sh` – ships the 3 new modules; bundles `cryptography`+`cffi`+`pycparser` per ABI
* `AppImage/components/login.tsx`, `avatar-menu.tsx`, `security.tsx` – login button/exchange, central logout, settings card
* `AppImage/messages/{en,de}/common.json` – `idp.*` strings (other locales fall back to English)

## 8. Tests

`python3 -m pytest tests/test_oidc_integration.py` (needs `flask flask-cors PyJWT cryptography requests`).
A fake IdP signs real RS256 ID tokens; the real routes/middleware run on a Flask test client with HOME redirected
to a temp dir. Covered: successful login, failed login/IdP error, invalid state, replayed state, login-CSRF,
invalid/missing nonce, invalid signature, unknown kid, expired token, wrong issuer, wrong audience, HS256/none
confusion, discovery-issuer mismatch, PKCE parameters, code replay/expiry/binding, missing groups, group mapping
(each role, highest wins, multi-group, custom/nested claim, userinfo fallback, default role), auto-provisioning on/off,
identity by issuer+sub (never e-mail), role refresh, user disable, role permissions (admin/user/read-only, forged
claims), local-account protection, logout (central + local), session timeout/issuer change/OIDC off, rate limit,
local fallback and local-login switch, secret handling (encrypted, never in API/logs, 0600), settings validation and
lock-out guard, migrations (idempotent, backup, newer-DB refusal), CLI disable/purge.
