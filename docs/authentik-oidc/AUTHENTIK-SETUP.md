# Authentik setup

Example values used below

| | |
|---|---|
| Authentik | `https://auth.example.com` |
| ProxMenux | `https://proxmenux.example.com` |
| **Redirect URI** | `https://proxmenux.example.com/api/auth/oidc/callback` |
| Scopes | `openid profile email groups` |

(The callback path is fixed by the implementation: `/api/auth/oidc/callback`. If ProxMenux listens on a
non-standard port, include it: `https://pve.lan:8008/api/auth/oidc/callback`. The Redirect URI is also shown
live under the *Public URL* field in ProxMenux.)

## 1. Groups

*Directory → Groups* – create `proxmenux-admins`, `proxmenux-users`, `proxmenux-readonly` and add members.
Users in none of them are refused (unless you set a *Default role*).

## 2. Signing key (required)

*System → Certificates*: use an existing certificate-key pair (e.g. *authentik Self-signed Certificate*) or
generate one. ProxMenux only accepts **asymmetric** ID-token signatures (RS256/ES256…). A provider without a
signing key signs with HS256 and ProxMenux rejects it by design.

## 3. Groups in the token

Depending on the Authentik version, the built-in OpenID scope mappings may or may not already put a `groups`
claim into the token (verify this on your instance: provider page → *Preview* for a test user). If it is missing, create it:

*Customization → Property Mappings → Create → Scope Mapping*

* Name: `ProxMenux groups`
* Scope name: `groups`
* Expression: `return {"groups": [group.name for group in request.user.ak_groups.all()]}`

(If your instance already provides `groups` through a built-in mapping, just select that mapping in the provider.)
If the claim is missing from the ID token ProxMenux falls back to the `userinfo` endpoint.

## 4. Provider

*Applications → Providers → Create → OAuth2/OpenID Provider*

| Field | Value |
|---|---|
| Name | `ProxMenux` |
| Authorization flow | an explicit consent or implicit consent flow of your choice |
| Client type | **Confidential** |
| Client ID | copy it (or set your own, e.g. `proxmenux`) |
| Client Secret | copy it |
| Redirect URIs/Origins | **Strict** `https://proxmenux.example.com/api/auth/oidc/callback` |
| Signing Key | the key from step 2 |
| Scopes | `openid`, `email`, `profile`, `ProxMenux groups` (or your `groups` mapping) |
| Subject mode | **Based on the User's hashed ID** (default, stable `sub`; do not use e-mail-based subject modes – ProxMenux identifies users by `issuer + sub`) |
| Include claims in id_token | on (recommended) |
| Access/ID token validity | 5 minutes is enough; ProxMenux only uses the ID token once at login |

For central logout also register `https://proxmenux.example.com/` as an allowed *post-logout redirect URI*
(Authentik ≥ 2024.x: *Logout/redirect URIs*) – otherwise Authentik shows its own page after logout, which is harmless.

## 5. Application

*Applications → Applications → Create*: name `ProxMenux`, slug `proxmenux`, provider = the one above,
launch URL `https://proxmenux.example.com/`. Use *Policy / Group bindings* to limit who may use the app at all.

## 6. ProxMenux

Sign in locally → **Security → Identity Provider**

| Field | Value |
|---|---|
| Issuer URL | `https://auth.example.com/application/o/proxmenux/` – exactly the **OpenID Configuration Issuer** shown on the Authentik provider page (mind the trailing slash; it must match the `issuer` in the discovery document) |
| Client ID / Secret | from the provider |
| Public URL | `https://proxmenux.example.com` |
| Scopes | `openid profile email groups` |
| Group claim | `groups` |
| Admin / User / Read-only group | `proxmenux-admins` / `proxmenux-users` / `proxmenux-readonly` |

Press **Test connection** (checks discovery + JWKS), then **Save**, then turn on **Enable OIDC**. Open the login
page in a private window and use *Sign in with Authentik*. Only after you have verified an administrator login
should you consider switching **Allow local login** off (the UI requires a successful connection test first).
The local admin password remains your break-glass access; see INSTALL.md for the CLI recovery.

## Troubleshooting

| Symptom on the login page | Cause |
|---|---|
| "The identity provider's response was rejected" | wrong Client ID/secret path, no signing key (HS256), issuer with/without trailing slash, clock skew > 60 s |
| "The sign-in could not be verified" | expired/reused login (took > 10 min), or the browser reached ProxMenux under a different host than the *Public URL* (binding cookie not sent), or cookies blocked |
| "Your account is not a member of any ProxMenux group" | groups claim missing or group names differ; check the claim name and the mapping |
| "The identity provider is unreachable…" | host cannot reach `auth.example.com` over https (DNS, CA trust, proxy) |
| *Test connection* fails with `discovery issuer mismatch` | the Issuer URL differs from the `issuer` value Authentik publishes |

Server-side detail (no secrets) is in `journalctl -u proxmenux-monitor` and `/var/log/proxmenux-auth.log`.
