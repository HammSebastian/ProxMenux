"""
OIDC (Authentik) integration for ProxMenux Monitor.

Responsibilities
  * configuration storage (client secret encrypted at rest)
  * discovery + JWKS handling
  * Authorization Code flow with PKCE (S256), state and nonce
  * ID-token validation (signature/iss/aud/exp/nonce) - delegated to PyJWT,
    no home-grown cryptography
  * user + session persistence (SQLite, versioned migrations)
  * group -> role mapping

The Flask glue lives in ``flask_oidc_routes.py``; session enforcement for the
rest of the API is in ``auth_manager.verify_token_full`` / ``jwt_middleware``.

CLI (break-glass, run as root on the host):
    python3 oidc_manager.py status
    python3 oidc_manager.py disable     # turn OIDC off, re-enable local login
    python3 oidc_manager.py purge       # remove all OIDC data (uninstall)
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import sys
import threading
import time
from urllib.parse import urlencode, urlparse

import auth_manager
import rbac

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:  # pragma: no cover
    REQUESTS_AVAILABLE = False

try:
    import jwt
    from jwt import PyJWKSet
    JWT_AVAILABLE = True
except ImportError:  # pragma: no cover
    JWT_AVAILABLE = False

try:
    from cryptography.fernet import Fernet, InvalidToken
    CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover - ImportError or broken binary wheel
    CRYPTO_AVAILABLE = False

log = logging.getLogger("proxmenux-auth")

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

CALLBACK_PATH = "/api/auth/oidc/callback"
TX_TTL_SECONDS = 600          # login transaction (state/nonce/verifier)
CODE_TTL_SECONDS = 60         # one-time hand-over code
MAX_PENDING_TX = 500          # bound the transaction table (flood guard)
DISCOVERY_TTL = 600
JWKS_TTL = 3600
JWKS_MIN_REFETCH = 30
HTTP_TIMEOUT = (5, 10)
HTTP_MAX_BYTES = 1024 * 1024
CLOCK_LEEWAY = 60

# Asymmetric algorithms only.  HS* is rejected on purpose (algorithm
# confusion; the client secret must not double as a signing key) and "none"
# is never accepted.
ALLOWED_ALGS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
                "ES256", "ES384", "ES512", "EdDSA")

SESSION_MIN_MINUTES = 5
SESSION_MAX_MINUTES = 60 * 24 * 30

DEFAULT_CONFIG = {
    "enabled": False,
    "provider_name": "Authentik",
    "issuer": "",
    "client_id": "",
    "client_secret_enc": "",
    "scopes": "openid profile email groups",
    "group_claim": "groups",
    "username_claim": "preferred_username",
    "admin_group": "proxmenux-admins",
    "user_group": "proxmenux-users",
    "readonly_group": "proxmenux-readonly",
    "auto_provision": True,
    "default_role": "none",      # "none" == deny users without a mapped group
    "allow_local_login": True,
    "oidc_logout": True,
    "session_timeout_minutes": 480,
    "public_url": "",
    "last_status": None,
}

ERR_GENERIC = "internal"


class OidcError(Exception):
    """Raised for any flow failure. `code` is safe to show to the browser,
    `detail` is for the (secret-free) server log only."""

    def __init__(self, code, detail=""):
        super().__init__(code)
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# Paths (resolved lazily so tests / alternative HOME work)
# --------------------------------------------------------------------------

def _dir():
    return auth_manager.CONFIG_DIR


def config_path():
    return _dir() / "oidc.json"


def key_path():
    return _dir() / "oidc.key"


def db_path():
    return _dir() / "oidc.db"


def _write_private(path, data: bytes):
    """Atomic write with 0600 permissions from the first byte."""
    auth_manager.ensure_config_dir()
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except Exception:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise
    os.replace(str(tmp), str(path))
    try:
        os.chmod(str(path), 0o600)
    except OSError:
        pass


# --------------------------------------------------------------------------
# Availability
# --------------------------------------------------------------------------

def availability():
    """(ok, reason). OIDC is optional: when the runtime lacks a dependency
    the feature reports itself as unavailable instead of breaking the app."""
    if not REQUESTS_AVAILABLE:
        return False, "python 'requests' is not installed"
    if not JWT_AVAILABLE:
        return False, "python 'PyJWT' is not installed"
    if not CRYPTO_AVAILABLE:
        return False, ("python 'cryptography' is not installed "
                       "(needed for RS256/ES256 ID-token signatures and secret encryption)")
    return True, ""


# --------------------------------------------------------------------------
# Secret encryption
# --------------------------------------------------------------------------

_key_lock = threading.Lock()


def _fernet():
    if not CRYPTO_AVAILABLE:
        raise OidcError("unavailable", "cryptography missing")
    with _key_lock:
        kp = key_path()
        if kp.exists():
            key = kp.read_bytes().strip()
        else:
            key = Fernet.generate_key()
            _write_private(kp, key)
    return Fernet(key)


def encrypt_secret(plain: str) -> str:
    if not plain:
        return ""
    return _fernet().encrypt(plain.encode("utf-8")).decode("ascii")


def decrypt_secret(token: str) -> str:
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        raise OidcError("secret_unreadable", "stored client secret cannot be decrypted")


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

def load_config():
    cfg = dict(DEFAULT_CONFIG)
    try:
        if config_path().exists():
            with open(config_path(), "r") as fh:
                stored = json.load(fh)
            if isinstance(stored, dict):
                cfg.update({k: v for k, v in stored.items() if k in DEFAULT_CONFIG})
    except Exception as exc:
        log.warning("oidc: cannot read config (%s); using defaults", type(exc).__name__)
    return cfg


def save_config(cfg):
    clean = {k: cfg.get(k, DEFAULT_CONFIG[k]) for k in DEFAULT_CONFIG}
    _write_private(config_path(), json.dumps(clean, indent=2).encode("utf-8"))


def public_config(cfg=None):
    """Config as exposed over the API. NEVER contains the secret."""
    cfg = cfg or load_config()
    out = {k: v for k, v in cfg.items() if k != "client_secret_enc"}
    out["client_secret_set"] = bool(cfg.get("client_secret_enc"))
    out["redirect_uri"] = redirect_uri(cfg)
    return out


def split_groups(value):
    if isinstance(value, (list, tuple)):
        items = value
    else:
        items = re.split(r"[,\n]", value or "")
    return [str(i).strip() for i in items if str(i).strip()]


def _is_loopback_host(host):
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _url_ok(url, require_https=True):
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme not in ("http", "https") or not p.hostname:
        return False
    if p.username or p.password or p.fragment:
        return False
    if require_https and p.scheme != "https" and not _is_loopback_host(p.hostname):
        return False
    return True


def redirect_uri(cfg=None):
    cfg = cfg or load_config()
    base = (cfg.get("public_url") or "").rstrip("/")
    return f"{base}{CALLBACK_PATH}" if base else ""


def validate_config(cfg, for_enable=None):
    """Return {"errors": [...], "warnings": [...]}. `for_enable` defaults to
    cfg['enabled']; a disabled config is only checked for format problems."""
    errors, warnings = [], []
    enabled = cfg.get("enabled") if for_enable is None else for_enable

    issuer = (cfg.get("issuer") or "").strip()
    if issuer and not _url_ok(issuer):
        errors.append("Issuer URL must be a valid https:// URL (http only for localhost).")
    pub = (cfg.get("public_url") or "").strip()
    if pub:
        if not _url_ok(pub, require_https=False):
            errors.append("Public URL must be a valid http(s) URL.")
        elif urlparse(pub).scheme != "https":
            warnings.append("Public URL is not https: session cookies will not be marked Secure.")
    minutes = cfg.get("session_timeout_minutes")
    if not isinstance(minutes, int) or isinstance(minutes, bool) \
            or not (SESSION_MIN_MINUTES <= minutes <= SESSION_MAX_MINUTES):
        errors.append(f"Session timeout must be between {SESSION_MIN_MINUTES} and "
                      f"{SESSION_MAX_MINUTES} minutes.")
    if cfg.get("default_role") not in ("none",) + rbac.ROLES:
        errors.append("Default role must be one of: none, admin, user, readonly.")
    scopes = split_scopes(cfg.get("scopes"))
    if "openid" not in scopes:
        errors.append("Scopes must include 'openid'.")
    if not (cfg.get("group_claim") or "").strip():
        errors.append("Group claim must not be empty.")

    if enabled:
        for key, label in (("issuer", "Issuer URL"), ("client_id", "Client ID"),
                           ("public_url", "Public URL")):
            if not (cfg.get(key) or "").strip():
                errors.append(f"{label} is required.")
        if not cfg.get("client_secret_enc"):
            errors.append("Client secret is required.")
        if not (split_groups(cfg.get("admin_group"))
                or split_groups(cfg.get("user_group"))
                or split_groups(cfg.get("readonly_group"))
                or cfg.get("default_role") in rbac.ROLES):
            errors.append("Configure at least one group mapping or a default role, "
                          "otherwise nobody can sign in.")
        if not split_groups(cfg.get("admin_group")) and cfg.get("default_role") != rbac.ROLE_ADMIN:
            warnings.append("No admin group configured: administration remains possible "
                            "only through the local account.")
        lc = auth_manager.load_auth_config()
        if not lc.get("enabled") or lc.get("declined"):
            errors.append("Enable local authentication first (set up the local admin account). "
                          "It is required as break-glass access and keeps the API protected.")
    return {"errors": errors, "warnings": warnings}


def split_scopes(value):
    if isinstance(value, (list, tuple)):
        return [str(s) for s in value if str(s)]
    return [s for s in re.split(r"[\s,]+", value or "") if s]


def is_enabled():
    """True when OIDC is switched on AND the runtime can actually do it."""
    cfg = load_config()
    return bool(cfg.get("enabled")) and availability()[0]


def local_login_allowed():
    cfg = load_config()
    if not cfg.get("enabled") or not availability()[0]:
        return True  # OIDC off -> the local login is the only way in
    return bool(cfg.get("allow_local_login", True))


def public_info():
    """Unauthenticated info for the login page (no secrets, no endpoints)."""
    cfg = load_config()
    enabled = bool(cfg.get("enabled")) and availability()[0]
    return {
        "enabled": enabled,
        "provider_name": cfg.get("provider_name") or "Authentik",
        "local_login_allowed": local_login_allowed(),
    }


def _record_status(ok, message, kind):
    try:
        cfg = load_config()
        cfg["last_status"] = {"ok": bool(ok), "message": message[:200], "kind": kind,
                              "checked_at": int(time.time())}
        save_config(cfg)
    except Exception:
        pass


# --------------------------------------------------------------------------
# HTTP helpers (thin so tests can replace them)
# --------------------------------------------------------------------------

def _read_limited(resp):
    chunks, total = [], 0
    for chunk in resp.iter_content(chunk_size=16384):
        total += len(chunk)
        if total > HTTP_MAX_BYTES:
            raise OidcError("idp_error", "response too large")
        chunks.append(chunk)
    return b"".join(chunks)


def _http_request(method, url, **kwargs):
    if not _url_ok(url):
        raise OidcError("idp_error", "refusing non-https endpoint")
    try:
        resp = requests.request(method, url, timeout=HTTP_TIMEOUT, allow_redirects=False,
                                stream=True, **kwargs)
    except requests.RequestException as exc:
        raise OidcError("idp_error", f"request failed: {type(exc).__name__}")
    try:
        body = _read_limited(resp)
        status = resp.status_code
    finally:
        resp.close()
    try:
        data = json.loads(body.decode("utf-8")) if body else {}
    except ValueError:
        data = None
    return status, data


def http_get_json(url, headers=None):
    status, data = _http_request("GET", url, headers=headers or {"Accept": "application/json"})
    if status != 200 or not isinstance(data, dict):
        raise OidcError("idp_error", f"GET {urlparse(url).path} -> HTTP {status}")
    return data


def http_post_form(url, form, basic_auth=None):
    status, data = _http_request("POST", url, data=form, auth=basic_auth,
                                 headers={"Accept": "application/json"})
    if not isinstance(data, dict):
        raise OidcError("token", f"token endpoint -> HTTP {status}, non-JSON body")
    if status != 200:
        # Only the standard `error` code goes to the log - never the body.
        raise OidcError("token", f"token endpoint -> HTTP {status} error={str(data.get('error'))[:40]}")
    return data


# --------------------------------------------------------------------------
# Discovery / JWKS
# --------------------------------------------------------------------------

_cache_lock = threading.Lock()
_discovery_cache = {}   # issuer -> (ts, doc)
_jwks_cache = {}        # jwks_uri -> {"ts", "fetched", "set"}


def clear_caches():
    with _cache_lock:
        _discovery_cache.clear()
        _jwks_cache.clear()


def _validate_discovery(issuer, doc):
    if doc.get("issuer") != issuer:
        # RFC 8414 / OIDC Discovery 4.3: must match exactly (mix-up defence).
        raise OidcError("idp_error", "discovery issuer mismatch")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not _url_ok(doc.get(field) or ""):
            raise OidcError("idp_error", f"discovery: bad {field}")
    for field in ("userinfo_endpoint", "end_session_endpoint"):
        if doc.get(field) and not _url_ok(doc[field]):
            raise OidcError("idp_error", f"discovery: bad {field}")
    methods = doc.get("code_challenge_methods_supported")
    if methods is not None and "S256" not in methods:
        raise OidcError("idp_error", "provider does not support PKCE S256")
    return doc


def discover(issuer, force=False):
    now = time.time()
    with _cache_lock:
        hit = _discovery_cache.get(issuer)
        if hit and not force and now - hit[0] < DISCOVERY_TTL:
            return hit[1]
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    doc = _validate_discovery(issuer, http_get_json(url))
    with _cache_lock:
        _discovery_cache[issuer] = (now, doc)
    return doc


def _jwks(uri, force=False):
    now = time.time()
    with _cache_lock:
        entry = _jwks_cache.get(uri)
        if entry and not force and now - entry["ts"] < JWKS_TTL:
            return entry["set"]
        if entry and force and now - entry["fetched"] < JWKS_MIN_REFETCH:
            return entry["set"]
    data = http_get_json(uri)
    try:
        jwk_set = PyJWKSet.from_dict(data)
    except Exception:
        raise OidcError("idp_error", "invalid JWKS document")
    with _cache_lock:
        _jwks_cache[uri] = {"ts": now, "fetched": now, "set": jwk_set}
    return jwk_set


def _find_key(jwk_set, kid, alg):
    keys = list(jwk_set.keys)
    if kid:
        for k in keys:
            if k.key_id == kid:
                return k
        return None
    compatible = [k for k in keys if (k.public_key_use in (None, "sig"))]
    return compatible[0] if len(compatible) == 1 else None


# --------------------------------------------------------------------------
# ID token validation
# --------------------------------------------------------------------------

def verify_id_token(id_token, cfg, doc, expected_nonce):
    """Validate an ID token. Raises OidcError('token', ...) on any problem."""
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError:
        raise OidcError("token", "malformed id_token")
    alg = header.get("alg")
    allowed = [a for a in ALLOWED_ALGS
               if a in (doc.get("id_token_signing_alg_values_supported") or ALLOWED_ALGS)]
    if alg not in allowed:
        raise OidcError("token", f"unsupported id_token alg {str(alg)[:12]} "
                                 "(configure an asymmetric signing key in the provider)")
    jwk_set = _jwks(doc["jwks_uri"])
    key = _find_key(jwk_set, header.get("kid"), alg)
    if key is None:  # key rotation: refetch once
        key = _find_key(_jwks(doc["jwks_uri"], force=True), header.get("kid"), alg)
    if key is None:
        raise OidcError("token", "signing key not found in JWKS")
    try:
        claims = jwt.decode(
            id_token, key.key, algorithms=[alg],
            audience=cfg["client_id"], issuer=cfg["issuer"],
            leeway=CLOCK_LEEWAY,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        raise OidcError("token", "id_token expired")
    except jwt.InvalidAudienceError:
        raise OidcError("token", "audience mismatch")
    except jwt.InvalidIssuerError:
        raise OidcError("token", "issuer mismatch")
    except jwt.PyJWTError as exc:
        raise OidcError("token", f"id_token rejected: {type(exc).__name__}")

    nonce = claims.get("nonce")
    if not isinstance(nonce, str) or not hmac.compare_digest(nonce, expected_nonce):
        raise OidcError("token", "nonce mismatch")
    aud = claims.get("aud")
    if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != cfg["client_id"]:
        raise OidcError("token", "azp mismatch")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise OidcError("token", "missing sub")
    return claims


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------

_MIGRATIONS = [
    # v1
    """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        issuer TEXT NOT NULL,
        subject TEXT NOT NULL,
        username TEXT NOT NULL,
        email TEXT,
        display_name TEXT,
        groups TEXT NOT NULL DEFAULT '[]',
        role TEXT NOT NULL,
        disabled INTEGER NOT NULL DEFAULT 0,
        created_at REAL NOT NULL,
        last_login REAL,
        UNIQUE (issuer, subject)
    );
    CREATE TABLE sessions (
        sid TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        id_token_enc TEXT,
        created_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE transactions (
        state_hash TEXT PRIMARY KEY,
        nonce TEXT NOT NULL,
        verifier TEXT NOT NULL,
        binding_hash TEXT NOT NULL,
        created_at REAL NOT NULL
    );
    CREATE TABLE exchange_codes (
        code_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        sid TEXT NOT NULL,
        binding_hash TEXT NOT NULL,
        expires_at REAL NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
    );
    """,
]
SCHEMA_VERSION = len(_MIGRATIONS)


def _connect():
    auth_manager.ensure_config_dir()
    new = not db_path().exists()
    conn = sqlite3.connect(str(db_path()), timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    if new:
        try:
            os.chmod(str(db_path()), 0o600)
        except OSError:
            pass
    return conn


_migrated = {}


def migrate():
    """Bring the DB to SCHEMA_VERSION. Existing DBs are copied to
    `oidc.db.bak-v<old>` first so a failed/unwanted upgrade can be rolled
    back by restoring that file. Idempotent."""
    path = str(db_path())
    if _migrated.get(path):
        return
    conn = _connect()
    try:
        current = conn.execute("PRAGMA user_version").fetchone()[0]
        if current > SCHEMA_VERSION:
            raise OidcError("internal", f"database is newer (v{current}) than this build (v{SCHEMA_VERSION})")
        if current < SCHEMA_VERSION:
            if current > 0:
                shutil.copy2(path, f"{path}.bak-v{current}")
            conn.execute("BEGIN IMMEDIATE")
            try:
                for version in range(current, SCHEMA_VERSION):
                    for stmt in filter(None, (s.strip() for s in _MIGRATIONS[version].split(";"))):
                        conn.execute(stmt)
                conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        _migrated[path] = True
    finally:
        conn.close()


def _db():
    migrate()
    return _connect()


def _h(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _purge(conn, now):
    conn.execute("DELETE FROM transactions WHERE created_at < ?", (now - TX_TTL_SECONDS,))
    conn.execute("DELETE FROM exchange_codes WHERE expires_at < ? OR used = 1", (now,))
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now - 86400,))


# --------------------------------------------------------------------------
# Login flow
# --------------------------------------------------------------------------

def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def pkce_challenge(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def begin_login():
    """Create a login transaction.
    Returns (authorization_url, binding_cookie_value)."""
    ok, reason = availability()
    cfg = load_config()
    if not ok or not cfg.get("enabled"):
        raise OidcError("disabled_oidc", reason or "oidc disabled")
    if validate_config(cfg)["errors"]:
        raise OidcError("config", "invalid configuration")
    doc = discover(cfg["issuer"])

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)          # 86 chars, within 43..128
    binding = secrets.token_urlsafe(32)           # browser binding (cookie)
    now = time.time()
    conn = _db()
    try:
        _purge(conn, now)
        pending = conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
        if pending >= MAX_PENDING_TX:
            raise OidcError("busy", "too many pending logins")
        conn.execute("INSERT INTO transactions VALUES (?,?,?,?,?)",
                     (_h(state), nonce, verifier, _h(binding), now))
    finally:
        conn.close()

    params = {
        "response_type": "code",
        "client_id": cfg["client_id"],
        "redirect_uri": redirect_uri(cfg),
        "scope": " ".join(split_scopes(cfg["scopes"])),
        "state": state,
        "nonce": nonce,
        "code_challenge": pkce_challenge(verifier),
        "code_challenge_method": "S256",
    }
    return doc["authorization_endpoint"] + ("&" if "?" in doc["authorization_endpoint"] else "?") \
        + urlencode(params), binding


def _consume_tx(state, binding):
    now = time.time()
    conn = _db()
    try:
        row = conn.execute("SELECT * FROM transactions WHERE state_hash=?", (_h(state),)).fetchone()
        if row is None:
            raise OidcError("state", "unknown or reused state")
        # Single use, regardless of outcome.
        deleted = conn.execute("DELETE FROM transactions WHERE state_hash=?", (_h(state),)).rowcount
        if deleted != 1:
            raise OidcError("state", "state raced")
        if now - row["created_at"] > TX_TTL_SECONDS:
            raise OidcError("state", "transaction expired")
        if not binding or not hmac.compare_digest(row["binding_hash"], _h(binding)):
            # Login CSRF: the callback arrived in a browser that did not
            # start this login.
            raise OidcError("state", "browser binding mismatch")
        return row["nonce"], row["verifier"]
    finally:
        conn.close()


def _lookup_claim(claims, path):
    cur = claims
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def extract_groups(claims, group_claim):
    value = _lookup_claim(claims, group_claim)
    if value is None:
        value = claims.get(group_claim)
    if value is None:
        return []
    return split_groups(value)


def map_role(groups, cfg):
    """Highest-privilege role among the mapped groups; falls back to the
    default role; returns None when the user must be denied."""
    gset = set(groups)
    best = None
    for role, key in ((rbac.ROLE_ADMIN, "admin_group"),
                      (rbac.ROLE_USER, "user_group"),
                      (rbac.ROLE_READONLY, "readonly_group")):
        if gset & set(split_groups(cfg.get(key))):
            if best is None or rbac.ROLE_RANK[role] > rbac.ROLE_RANK[best]:
                best = role
    if best is None and cfg.get("default_role") in rbac.ROLES:
        best = cfg["default_role"]
    return best


def _clean_username(raw, fallback):
    name = re.sub(r"[^A-Za-z0-9._@+-]", "_", (raw or "").strip())[:64]
    return name or fallback[:64]


def _clean_text(value, limit):
    if not isinstance(value, str):
        return None
    value = "".join(ch for ch in value if ord(ch) >= 0x20 and ord(ch) != 0x7f).strip()
    return value[:limit] or None


def handle_callback(state, code, binding):
    """Process the IdP redirect. Returns an exchange code for the browser.
    Raises OidcError on every failure."""
    cfg = load_config()
    ok, reason = availability()
    if not ok or not cfg.get("enabled"):
        raise OidcError("disabled_oidc", reason or "oidc disabled")
    if not state or not code or not isinstance(state, str) or not isinstance(code, str):
        raise OidcError("state", "missing state/code")
    if len(state) > 200 or len(code) > 4096:
        raise OidcError("state", "oversized parameters")

    nonce, verifier = _consume_tx(state, binding)
    doc = discover(cfg["issuer"])
    secret = decrypt_secret(cfg.get("client_secret_enc", ""))

    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri(cfg),
        "code_verifier": verifier,
    }
    methods = doc.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
    basic = None
    if "client_secret_basic" in methods:
        from urllib.parse import quote
        basic = (quote(cfg["client_id"], safe=""), quote(secret, safe=""))
    else:
        form["client_id"] = cfg["client_id"]
        form["client_secret"] = secret
    tokens = http_post_form(doc["token_endpoint"], form, basic_auth=basic)

    id_token = tokens.get("id_token")
    access_token = tokens.get("access_token")
    if not isinstance(id_token, str) or not id_token:
        raise OidcError("token", "no id_token in response")
    if str(tokens.get("token_type", "")).lower() != "bearer":
        raise OidcError("token", "unexpected token_type")

    claims = verify_id_token(id_token, cfg, doc, nonce)

    group_claim = (cfg.get("group_claim") or "groups").strip()
    if _lookup_claim(claims, group_claim) is None and claims.get(group_claim) is None \
            and doc.get("userinfo_endpoint") and isinstance(access_token, str):
        info = http_get_json(doc["userinfo_endpoint"],
                             headers={"Accept": "application/json",
                                      "Authorization": f"Bearer {access_token}"})
        if info.get("sub") != claims["sub"]:
            raise OidcError("token", "userinfo sub mismatch")
        for k, v in info.items():
            claims.setdefault(k, v)   # id_token claims win over userinfo

    groups = extract_groups(claims, group_claim)
    role = map_role(groups, cfg)
    if role is None:
        raise OidcError("no_role", "user has no mapped group")

    user = _upsert_user(cfg, claims, groups, role)
    sid, exchange_code = _create_session(cfg, user, id_token, binding)
    _record_status(True, "Last login succeeded", "login")
    return exchange_code


def _upsert_user(cfg, claims, groups, role):
    issuer, sub = cfg["issuer"], claims["sub"]
    username = _clean_username(claims.get(cfg.get("username_claim") or "preferred_username")
                               or claims.get("preferred_username")
                               or (claims.get("email") or "").split("@")[0], f"user-{_h(sub)[:8]}")
    email = _clean_text(claims.get("email"), 254)
    display = _clean_text(claims.get("name"), 128)
    now = time.time()
    conn = _db()
    try:
        # Identity == (issuer, sub). E-mail / username are attributes only
        # and are never used to find or merge an account.
        row = conn.execute("SELECT * FROM users WHERE issuer=? AND subject=?", (issuer, sub)).fetchone()
        if row is None:
            if not cfg.get("auto_provision", True):
                raise OidcError("provisioning", "automatic provisioning disabled")
            cur = conn.execute(
                "INSERT INTO users (issuer,subject,username,email,display_name,groups,role,created_at,last_login)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (issuer, sub, username, email, display, json.dumps(groups), role, now, now))
            uid = cur.lastrowid
        else:
            if row["disabled"]:
                raise OidcError("disabled", "user disabled by administrator")
            uid = row["id"]
            conn.execute(
                "UPDATE users SET username=?, email=?, display_name=?, groups=?, role=?, last_login=? WHERE id=?",
                (username, email, display, json.dumps(groups), role, now, uid))
        return dict(conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone())
    finally:
        conn.close()


def session_lifetime_seconds(cfg):
    return int(cfg.get("session_timeout_minutes", 480)) * 60


def _create_session(cfg, user, id_token, binding):
    now = time.time()
    sid = secrets.token_urlsafe(24)
    code = secrets.token_urlsafe(32)
    conn = _db()
    try:
        _purge(conn, now)
        conn.execute("INSERT INTO sessions VALUES (?,?,?,?,?,0)",
                     (sid, user["id"], encrypt_secret(id_token), now, now + session_lifetime_seconds(cfg)))
        conn.execute("INSERT INTO exchange_codes VALUES (?,?,?,?,?,0)",
                     (_h(code), user["id"], sid, _h(binding), now + CODE_TTL_SECONDS))
    finally:
        conn.close()
    return sid, code


def exchange_code(code, binding):
    """Redeem the one-time code for a ProxMenux session token.
    Returns (token, user_dict). A fresh token is minted here - nothing from
    before the login is ever promoted to an authenticated session (no
    session fixation)."""
    if not code or not isinstance(code, str) or len(code) > 200:
        raise OidcError("state", "bad code")
    now = time.time()
    conn = _db()
    try:
        row = conn.execute("SELECT * FROM exchange_codes WHERE code_hash=?", (_h(code),)).fetchone()
        if row is None or row["used"] or row["expires_at"] < now:
            raise OidcError("state", "code invalid or expired")
        claimed = conn.execute("UPDATE exchange_codes SET used=1 WHERE code_hash=? AND used=0",
                               (_h(code),)).rowcount
        if claimed != 1:
            raise OidcError("state", "code already used")
        if not binding or not hmac.compare_digest(row["binding_hash"], _h(binding)):
            raise OidcError("state", "browser binding mismatch")
        user = conn.execute("SELECT * FROM users WHERE id=?", (row["user_id"],)).fetchone()
        sess = conn.execute("SELECT * FROM sessions WHERE sid=?", (row["sid"],)).fetchone()
        if user is None or sess is None or user["disabled"] or sess["revoked"]:
            raise OidcError("disabled", "session unavailable")
    finally:
        conn.close()

    scope = rbac.scope_for_role(user["role"])
    if scope is None:
        raise OidcError("no_role", "invalid stored role")
    token = auth_manager.generate_token(
        f"oidc:{user['username']}", scope=scope,
        expires_in=max(1, int(sess["expires_at"] - now)),
        extra_claims={"src": "oidc", "sid": sess["sid"], "role": user["role"]})
    if not token:
        raise OidcError("internal", "token generation failed")
    return token, dict(user)


# --------------------------------------------------------------------------
# Session enforcement (called by auth_manager.verify_token_full)
# --------------------------------------------------------------------------

def validate_session(sid):
    """Server-side check for a token with src=oidc. Returns the live scope
    (derived from the DB, not from the token) or None to reject."""
    if not sid or not is_enabled():
        return None
    cfg = load_config()
    conn = _db()
    try:
        row = conn.execute(
            "SELECT s.revoked, s.expires_at, u.disabled, u.role, u.issuer FROM sessions s "
            "JOIN users u ON u.id = s.user_id WHERE s.sid=?", (sid,)).fetchone()
    finally:
        conn.close()
    if row is None or row["revoked"] or row["disabled"] or row["expires_at"] < time.time():
        return None
    if row["issuer"] != cfg.get("issuer"):
        return None  # issuer changed: identities of the old IdP are not trusted
    return rbac.scope_for_role(row["role"])


def get_session_user(sid):
    conn = _db()
    try:
        row = conn.execute(
            "SELECT u.id, u.username, u.email, u.display_name, u.role, u.groups FROM sessions s "
            "JOIN users u ON u.id=s.user_id WHERE s.sid=?", (sid,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    d = dict(row)
    d["groups"] = json.loads(d["groups"] or "[]")
    return d


def logout(sid):
    """Revoke the server-side session. Returns the IdP end-session URL (for
    central logout) or None."""
    cfg = load_config()
    conn = _db()
    try:
        row = conn.execute("SELECT id_token_enc FROM sessions WHERE sid=?", (sid,)).fetchone()
        conn.execute("UPDATE sessions SET revoked=1 WHERE sid=?", (sid,))
    finally:
        conn.close()
    if not row or not cfg.get("enabled") or not cfg.get("oidc_logout", True):
        return None
    try:
        doc = discover(cfg["issuer"])
        endpoint = doc.get("end_session_endpoint")
        if not endpoint:
            return None
        params = {"client_id": cfg["client_id"]}
        if row["id_token_enc"]:
            params["id_token_hint"] = decrypt_secret(row["id_token_enc"])
        if cfg.get("public_url"):
            params["post_logout_redirect_uri"] = cfg["public_url"].rstrip("/") + "/"
        return endpoint + ("&" if "?" in endpoint else "?") + urlencode(params)
    except OidcError:
        return None


# --------------------------------------------------------------------------
# Admin operations
# --------------------------------------------------------------------------

def check_connection():
    """Run discovery + JWKS fetch against the saved config. Never raises."""
    ok, reason = availability()
    if not ok:
        return {"ok": False, "message": reason, "discovery": None}
    cfg = load_config()
    problems = validate_config(cfg, for_enable=True)
    problems["errors"] = [e for e in problems["errors"] if "local authentication" not in e]
    if problems["errors"]:
        msg = "; ".join(problems["errors"])
        _record_status(False, msg, "test")
        return {"ok": False, "message": msg, "discovery": None, "warnings": problems["warnings"]}
    try:
        doc = discover(cfg["issuer"], force=True)
        jwk_set = _jwks(doc["jwks_uri"], force=True)
        if not jwk_set.keys:
            raise OidcError("idp_error", "JWKS contains no keys")
        algs = doc.get("id_token_signing_alg_values_supported") or []
        warnings = list(problems["warnings"])
        if algs and not [a for a in algs if a in ALLOWED_ALGS]:
            raise OidcError("idp_error", "provider only offers symmetric/none signing; "
                                         "assign a signing key to the provider")
        if not doc.get("end_session_endpoint") and cfg.get("oidc_logout"):
            warnings.append("Provider advertises no end_session_endpoint; central logout is unavailable.")
        shown = {k: doc.get(k) for k in (
            "issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint",
            "end_session_endpoint", "jwks_uri", "scopes_supported", "claims_supported",
            "response_types_supported", "id_token_signing_alg_values_supported",
            "code_challenge_methods_supported", "token_endpoint_auth_methods_supported")
            if k in doc}
        _record_status(True, "Discovery and JWKS OK", "test")
        return {"ok": True, "message": "Discovery and JWKS OK", "discovery": shown,
                "jwks_keys": len(jwk_set.keys), "warnings": warnings}
    except OidcError as exc:
        log.warning("oidc test failed: %s", exc.detail)
        _record_status(False, exc.detail or exc.code, "test")
        return {"ok": False, "message": exc.detail or exc.code, "discovery": None}


def list_users():
    conn = _db()
    try:
        rows = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["groups"] = json.loads(d["groups"] or "[]")
        d["disabled"] = bool(d["disabled"])
        d.pop("subject", None)
        out.append(d)
    return out


def set_user_disabled(user_id, disabled):
    conn = _db()
    try:
        n = conn.execute("UPDATE users SET disabled=? WHERE id=?", (1 if disabled else 0, user_id)).rowcount
        if disabled:
            conn.execute("UPDATE sessions SET revoked=1 WHERE user_id=?", (user_id,))
    finally:
        conn.close()
    return n == 1


def delete_user(user_id):
    conn = _db()
    try:
        conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        n = conn.execute("DELETE FROM users WHERE id=?", (user_id,)).rowcount
    finally:
        conn.close()
    return n == 1


def revoke_all_sessions():
    conn = _db()
    try:
        conn.execute("UPDATE sessions SET revoked=1")
    finally:
        conn.close()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _cli(argv):
    cmd = argv[1] if len(argv) > 1 else "status"
    if cmd == "status":
        cfg = load_config()
        print(json.dumps(public_config(cfg), indent=2))
        print("available:", availability())
        return 0
    if cmd == "disable":
        cfg = load_config()
        cfg["enabled"] = False
        cfg["allow_local_login"] = True
        save_config(cfg)
        print("OIDC disabled; local login re-enabled.")
        return 0
    if cmd == "purge":
        for p in (config_path(), key_path(), db_path()):
            try:
                p.unlink()
            except FileNotFoundError:
                pass
        for p in _dir().glob("oidc.db.bak-v*"):
            p.unlink()
        print("All OIDC configuration, keys and users removed.")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv))
