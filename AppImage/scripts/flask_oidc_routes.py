"""
Flask routes for the OpenID Connect (Authentik) login.

Public (no session):
  GET  /api/auth/oidc/info        login-page info (provider name, flags)
  GET  /api/auth/oidc/login       start login   -> 302 to the IdP
  GET  /api/auth/oidc/callback    IdP redirect  -> 302 to the SPA with a one-time code
  POST /api/auth/oidc/exchange    one-time code -> ProxMenux session token
  POST /api/auth/oidc/logout      revoke session, return IdP logout URL

Administrator only:
  GET/PUT /api/auth/oidc/settings
  POST    /api/auth/oidc/test
  GET     /api/auth/oidc/users
  PATCH/DELETE /api/auth/oidc/users/<id>

Failures are logged with the same "authentication failure; rhost=..." format
the existing Fail2Ban filter understands; no tokens, codes or secrets are
ever logged or returned.
"""

import logging
import os
import threading
import time
from collections import defaultdict, deque
from urllib.parse import urlencode, urlparse

from flask import Blueprint, jsonify, request, redirect, make_response

import auth_manager
import oidc_manager
from jwt_middleware import require_admin_scope

oidc_bp = Blueprint("oidc", __name__)
auth_logger = logging.getLogger("proxmenux-auth")

COOKIE_NAME = "pmx_oidc"
COOKIE_PATH = "/api/auth/oidc"
COOKIE_MAX_AGE = oidc_manager.TX_TTL_SECONDS

_TRUST_PROXY = os.environ.get("PROXMENUX_TRUST_PROXY", "0") == "1"


class _RateLimiter:
    """Sliding-window limiter (same idea as the local-login limiter)."""

    def __init__(self, max_attempts, window_seconds):
        self._max, self._window = max_attempts, window_seconds
        self._buckets = defaultdict(deque)
        self._lock = threading.Lock()

    def check_and_record(self, key):
        now = time.time()
        cutoff = now - self._window
        with self._lock:
            bucket = self._buckets[key or "unknown"]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self._max:
                return False, max(1, int(self._window - (now - bucket[0])))
            bucket.append(now)
            if len(self._buckets) > 1024:
                for k in [k for k, q in self._buckets.items() if not q or q[-1] < cutoff]:
                    self._buckets.pop(k, None)
            return True, 0

    def reset(self):
        with self._lock:
            self._buckets.clear()


# Starting a login / hitting the callback / redeeming a code: 20 per IP per 5 min.
_flow_limiter = _RateLimiter(20, 300)


def _client_ip():
    if _TRUST_PROXY:
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
        real = request.headers.get("X-Real-IP", "")
        if real:
            return real.strip()
    return request.remote_addr or "unknown"


def _secure_cookie(cfg):
    if str(cfg.get("public_url", "")).startswith("https://"):
        return True
    return request.is_secure


def _spa_url(cfg, **params):
    base = (cfg.get("public_url") or "").rstrip("/") or ""
    return f"{base}/?{urlencode(params)}"


def _fail(cfg, code, detail):
    auth_logger.warning("authentication failure; rhost=%s user=oidc reason=%s; %s",
                        _client_ip(), code, detail[:120])
    oidc_manager._record_status(False, f"Login failed: {code}", "login")
    resp = redirect(_spa_url(cfg, oidc_error=code), code=302)
    resp.delete_cookie(COOKIE_NAME, path=COOKIE_PATH)
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _limited():
    allowed, retry = _flow_limiter.check_and_record(_client_ip())
    if allowed:
        return None
    resp = jsonify({"success": False, "message": "Too many attempts. Please wait.", "retry_after": retry})
    resp.status_code = 429
    resp.headers["Retry-After"] = str(retry)
    return resp


# ---------------------------------------------------------------- public ---

@oidc_bp.route("/api/auth/oidc/info", methods=["GET"])
def oidc_info():
    return jsonify({"success": True, **oidc_manager.public_info()})


@oidc_bp.route("/api/auth/oidc/login", methods=["GET"])
def oidc_login():
    cfg = oidc_manager.load_config()
    limited = _limited()
    if limited:
        return limited
    try:
        url, binding = oidc_manager.begin_login()
    except oidc_manager.OidcError as exc:
        return _fail(cfg, exc.code if exc.code in ("disabled_oidc", "busy") else "config", exc.detail)
    except Exception as exc:  # never leak internals
        return _fail(cfg, "internal", type(exc).__name__)
    resp = redirect(url, code=302)
    resp.set_cookie(COOKIE_NAME, binding, max_age=COOKIE_MAX_AGE, path=COOKIE_PATH,
                    httponly=True, secure=_secure_cookie(cfg), samesite="Lax")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@oidc_bp.route("/api/auth/oidc/callback", methods=["GET"])
def oidc_callback():
    cfg = oidc_manager.load_config()
    limited = _limited()
    if limited:
        return limited
    if request.args.get("error"):
        # IdP-reported error (e.g. access_denied). Do not echo its text.
        code = "denied" if request.args.get("error") == "access_denied" else "idp_error"
        return _fail(cfg, code, "idp returned error=" + request.args.get("error", "")[:40])
    try:
        exchange = oidc_manager.handle_callback(
            request.args.get("state"), request.args.get("code"), request.cookies.get(COOKIE_NAME))
    except oidc_manager.OidcError as exc:
        return _fail(cfg, exc.code, exc.detail)
    except Exception as exc:
        return _fail(cfg, "internal", type(exc).__name__)
    resp = redirect(_spa_url(cfg, oidc_code=exchange), code=302)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Referrer-Policy"] = "no-referrer"   # keep the code out of Referer
    return resp


@oidc_bp.route("/api/auth/oidc/exchange", methods=["POST"])
def oidc_exchange():
    limited = _limited()
    if limited:
        return limited
    data = request.get_json(silent=True) or {}
    try:
        token, user = oidc_manager.exchange_code(data.get("code"), request.cookies.get(COOKIE_NAME))
    except oidc_manager.OidcError as exc:
        auth_logger.warning("authentication failure; rhost=%s user=oidc reason=%s; %s",
                            _client_ip(), exc.code, exc.detail[:120])
        return jsonify({"success": False, "message": "Sign-in failed", "code": exc.code}), 401
    except Exception:
        return jsonify({"success": False, "message": "Sign-in failed", "code": "internal"}), 500
    resp = jsonify({"success": True, "token": token, "role": user["role"],
                    "username": user["username"], "display_name": user["display_name"]})
    resp.headers["Cache-Control"] = "no-store"
    resp.delete_cookie(COOKIE_NAME, path=COOKIE_PATH)
    return resp


@oidc_bp.route("/api/auth/oidc/logout", methods=["POST"])
def oidc_logout():
    """Works for every session type: local sessions just get no IdP URL."""
    parts = request.headers.get("Authorization", "").split()
    info = auth_manager.get_session_info(parts[1]) if len(parts) == 2 else None
    logout_url = None
    if info and info["src"] == "oidc" and info["sid"]:
        logout_url = oidc_manager.logout(info["sid"])
    return jsonify({"success": True, "logout_url": logout_url})


# ----------------------------------------------------------------- admin ---

_BOOL_KEYS = ("enabled", "auto_provision", "allow_local_login", "oidc_logout")
_STR_KEYS = ("provider_name", "issuer", "client_id", "scopes", "group_claim", "username_claim",
             "admin_group", "user_group", "readonly_group", "default_role", "public_url")
_CONNECTION_KEYS = ("issuer", "client_id", "public_url")


@oidc_bp.route("/api/auth/oidc/settings", methods=["GET"])
@require_admin_scope
def get_settings():
    ok, reason = oidc_manager.availability()
    cfg = oidc_manager.load_config()
    v = oidc_manager.validate_config(cfg)
    return jsonify({"success": True, "available": ok, "unavailable_reason": reason,
                    "settings": oidc_manager.public_config(cfg), "warnings": v["warnings"]})


@oidc_bp.route("/api/auth/oidc/settings", methods=["PUT"])
@require_admin_scope
def put_settings():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "message": "JSON object expected"}), 400
    ok, reason = oidc_manager.availability()
    if not ok:
        return jsonify({"success": False, "message": reason}), 400

    cfg = oidc_manager.load_config()
    before = dict(cfg)

    for key in _BOOL_KEYS:
        if key in data:
            if not isinstance(data[key], bool):
                return jsonify({"success": False, "message": f"'{key}' must be true or false"}), 400
            cfg[key] = data[key]
    for key in _STR_KEYS:
        if key in data:
            if not isinstance(data[key], str) or len(data[key]) > 2000:
                return jsonify({"success": False, "message": f"'{key}' must be a string"}), 400
            cfg[key] = data[key].strip()
    if "session_timeout_minutes" in data:
        cfg["session_timeout_minutes"] = data["session_timeout_minutes"]
    if "client_secret" in data:
        secret = data["client_secret"]
        if not isinstance(secret, str) or len(secret) > 1024:
            return jsonify({"success": False, "message": "'client_secret' must be a string"}), 400
        if secret:   # empty string == keep the stored secret
            cfg["client_secret_enc"] = oidc_manager.encrypt_secret(secret)

    # The issuer is kept byte-for-byte: Authentik publishes it WITH a trailing slash and
    # the discovery document / ID-token `iss` must match it exactly.
    secret_changed = cfg.get("client_secret_enc") != before.get("client_secret_enc")
    if secret_changed or any(cfg[k] != before[k] for k in _CONNECTION_KEYS):
        cfg["last_status"] = None   # a new target has not been verified yet

    result = oidc_manager.validate_config(cfg)
    if result["errors"]:
        return jsonify({"success": False, "message": "Invalid configuration",
                        "errors": result["errors"], "warnings": result["warnings"]}), 400

    # Lock-out guard: the local login may only be switched off while OIDC is
    # on AND a connection test has succeeded since the last connection change.
    if cfg["enabled"] and not cfg["allow_local_login"]:
        status = cfg.get("last_status") or {}
        if not status.get("ok"):
            return jsonify({"success": False,
                            "message": "Run a successful connection test before disabling local login.",
                            "errors": ["Run a successful connection test before disabling local login."]}), 400

    oidc_manager.save_config(cfg)
    oidc_manager.clear_caches()
    if before.get("enabled") and not cfg["enabled"]:
        oidc_manager.revoke_all_sessions()
    return jsonify({"success": True, "settings": oidc_manager.public_config(cfg),
                    "warnings": result["warnings"]})


@oidc_bp.route("/api/auth/oidc/test", methods=["POST"])
@require_admin_scope
def test_settings():
    result = oidc_manager.check_connection()
    result["success"] = result["ok"]
    result["settings"] = oidc_manager.public_config()
    return jsonify(result), 200


@oidc_bp.route("/api/auth/oidc/users", methods=["GET"])
@require_admin_scope
def users_list():
    return jsonify({"success": True, "users": oidc_manager.list_users()})


@oidc_bp.route("/api/auth/oidc/users/<int:user_id>", methods=["PATCH"])
@require_admin_scope
def users_patch(user_id):
    data = request.get_json(silent=True) or {}
    if not isinstance(data.get("disabled"), bool):
        return jsonify({"success": False, "message": "'disabled' (boolean) required"}), 400
    if not oidc_manager.set_user_disabled(user_id, data["disabled"]):
        return jsonify({"success": False, "message": "User not found"}), 404
    return jsonify({"success": True})


@oidc_bp.route("/api/auth/oidc/users/<int:user_id>", methods=["DELETE"])
@require_admin_scope
def users_delete(user_id):
    if not oidc_manager.delete_user(user_id):
        return jsonify({"success": False, "message": "User not found"}), 404
    return jsonify({"success": True})
