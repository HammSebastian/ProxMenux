"""
OIDC (Authentik) integration tests.

Runs the REAL oidc_manager / auth_manager / jwt_middleware / Flask routes
against a fake identity provider (RSA-signed ID tokens, JWKS, discovery) with
the HTTP layer replaced.  Nothing touches the network, the live auth config
or /var/log: HOME is redirected to a temporary directory.

    python3 -m unittest tests.test_oidc_integration -v
Requires: flask, PyJWT, cryptography, requests (the Monitor's own runtime deps).
"""
import base64
import hashlib
import json
import logging
import logging.handlers  # noqa: F401  (must load before FileHandler is patched)
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "AppImage" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import jwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from flask import Flask, jsonify  # noqa: E402

# flask_auth_routes opens /var/log/proxmenux-auth.log at import time.
with mock.patch.object(logging, "FileHandler", lambda *a, **k: logging.NullHandler()):
    import auth_manager  # noqa: E402
    import flask_auth_routes  # noqa: E402
import flask_oidc_routes  # noqa: E402
import oidc_manager  # noqa: E402
import rbac  # noqa: E402
from jwt_middleware import require_auth, require_admin_scope  # noqa: E402

ISSUER = "https://auth.example.com/application/o/proxmenux"
PUBLIC = "https://proxmenux.example.com"
CLIENT_ID = "proxmenux-client"
CLIENT_SECRET = "s3cr3t-client-secret-value"
LOCAL_PW = "Str0ng!LocalPassw0rd"

_RSA_A = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_RSA_B = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(private_key, kid):
    d = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    d.update(kid=kid, use="sig", alg="RS256")
    return d


class FakeIdP:
    """Stands in for Authentik: discovery, JWKS, token endpoint, userinfo."""

    def __init__(self):
        self.key, self.kid = _RSA_A, "key-a"
        self.claims = {}
        self.token_requests = []
        self.groups = ["proxmenux-admins"]
        self.sub = "sub-1"
        self.extra = {}
        self.userinfo_groups = None
        self.discovery_overrides = {}
        self.id_token_override = None

    def discovery(self):
        doc = {
            "issuer": ISSUER,
            "authorization_endpoint": "https://auth.example.com/application/o/authorize/",
            "token_endpoint": "https://auth.example.com/application/o/token/",
            "userinfo_endpoint": "https://auth.example.com/application/o/userinfo/",
            "end_session_endpoint": "https://auth.example.com/application/o/proxmenux/end-session/",
            "jwks_uri": "https://auth.example.com/application/o/proxmenux/jwks/",
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        }
        doc.update(self.discovery_overrides)
        return doc

    def get_json(self, url, headers=None):
        if url.endswith("/.well-known/openid-configuration"):
            return self.discovery()
        if url.endswith("/jwks/"):
            return {"keys": [_jwk(_RSA_A, "key-a"), _jwk(_RSA_B, "key-b")]}
        if url.endswith("/userinfo/"):
            return {"sub": self.sub, "groups": self.userinfo_groups or []}
        raise AssertionError(f"unexpected GET {url}")

    def make_id_token(self, _nonce, **over):
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT_ID, "sub": self.sub, "iat": now, "exp": now + 300,
                  "nonce": _nonce, "preferred_username": "alice", "email": "alice@example.com",
                  "name": "Alice Example"}
        if self.groups is not None:
            claims["groups"] = self.groups
        claims.update(self.extra)
        claims.update(over)
        for k in [k for k, v in claims.items() if v is None]:
            del claims[k]
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": self.kid})

    def post_form(self, url, form, basic_auth=None):
        self.token_requests.append((url, dict(form), basic_auth))
        if self.id_token_override:
            id_token = self.id_token_override
        else:
            id_token = self.make_id_token(self.current_nonce)
        return {"access_token": "at-123", "token_type": "Bearer", "id_token": id_token}


class OidcTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="pmx-oidc-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        cfgdir = self.tmp / "cfg"
        patches = [
            mock.patch.object(auth_manager, "CONFIG_DIR", cfgdir),
            mock.patch.object(auth_manager, "AUTH_CONFIG_FILE", cfgdir / "auth.json"),
            mock.patch.object(auth_manager, "AVATAR_FILE", cfgdir / "avatar.bin"),
            mock.patch.object(auth_manager, "AVATAR_CONTENT_TYPE_FILE", cfgdir / "avatar.type"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        auth_manager._REVOKED_CACHE.update(set=None)
        oidc_manager._migrated.clear()
        oidc_manager.clear_caches()
        flask_oidc_routes._flow_limiter.reset()

        self.idp = FakeIdP()
        for target, fn in (("http_get_json", self.idp.get_json), ("http_post_form", self.idp.post_form)):
            p = mock.patch.object(oidc_manager, target, fn)
            p.start()
            self.addCleanup(p.stop)

        ok, msg = auth_manager.setup_auth("localadmin", LOCAL_PW)
        self.assertTrue(ok, msg)
        self.configure()

        self.app = Flask(__name__)
        self.app.register_blueprint(flask_auth_routes.auth_bp)
        self.app.register_blueprint(flask_oidc_routes.oidc_bp)

        @self.app.route("/api/test/read")
        @require_auth
        def _read():
            return jsonify(ok=True)

        @self.app.route("/api/vms/100/control", methods=["POST"])
        @require_auth
        def _control():
            return jsonify(ok=True)

        @self.app.route("/api/scripts/execute", methods=["POST"])
        @require_auth
        def _execute():
            return jsonify(ok=True)

        @self.app.route("/api/test/admin", methods=["POST"])
        @require_admin_scope
        def _admin():
            return jsonify(ok=True)

        self.client = self.app.test_client()

    # ---- helpers -------------------------------------------------------
    def configure(self, **over):
        cfg = oidc_manager.load_config()
        cfg.update(enabled=True, issuer=ISSUER, client_id=CLIENT_ID, public_url=PUBLIC,
                   client_secret_enc=oidc_manager.encrypt_secret(CLIENT_SECRET))
        cfg.update(over)
        oidc_manager.save_config(cfg)

    def get(self, client, path, **kw):
        return client.get(path, base_url=PUBLIC, **kw)

    def begin(self, client=None):
        client = client or self.client
        r = self.get(client, "/api/auth/oidc/login")
        self.assertEqual(r.status_code, 302, r.data)
        q = parse_qs(urlparse(r.headers["Location"]).query)
        self.idp.current_nonce = q["nonce"][0]
        return r, q

    def callback(self, client, q, code="authcode", **over):
        params = {"state": q["state"][0], "code": code}
        params.update(over)
        return client.get("/api/auth/oidc/callback", query_string=params, base_url=PUBLIC)

    def full_login(self, client=None):
        """Complete the whole flow; return (token, exchange_response_json)."""
        client = client or self.client
        _, q = self.begin(client)
        r = self.callback(client, q)
        self.assertEqual(r.status_code, 302)
        loc = urlparse(r.headers["Location"])
        self.assertIn("oidc_code", parse_qs(loc.query), r.headers["Location"])
        code = parse_qs(loc.query)["oidc_code"][0]
        ex = client.post("/api/auth/oidc/exchange", json={"code": code}, base_url=PUBLIC)
        self.assertEqual(ex.status_code, 200, ex.data)
        return ex.get_json()["token"], ex.get_json()

    def login_as(self, groups, sub="sub-1"):
        self.idp.groups, self.idp.sub = groups, sub
        client = self.app.test_client()
        token, body = self.full_login(client)
        return token

    @staticmethod
    def auth(token):
        return {"Authorization": f"Bearer {token}"}

    def assert_denied_error(self, resp, code):
        self.assertEqual(resp.status_code, 302)
        q = parse_qs(urlparse(resp.headers["Location"]).query)
        self.assertEqual(q.get("oidc_error"), [code], resp.headers["Location"])
        self.assertNotIn("oidc_code", q)


# ===========================================================================

class LoginFlowTests(OidcTestBase):
    def test_successful_login_creates_user_and_session(self):
        token, body = self.full_login()
        self.assertEqual(body["role"], "admin")
        users = oidc_manager.list_users()
        self.assertEqual(len(users), 1)
        u = users[0]
        self.assertEqual((u["username"], u["email"], u["display_name"], u["role"]),
                         ("alice", "alice@example.com", "Alice Example", "admin"))
        self.assertEqual(u["groups"], ["proxmenux-admins"])
        self.assertIsNotNone(u["last_login"])
        self.assertEqual(u["issuer"], ISSUER)
        r = self.client.get("/api/test/read", headers=self.auth(token))
        self.assertEqual(r.status_code, 200)
        claims = jwt.decode(token, options={"verify_signature": False})
        self.assertEqual((claims["src"], claims["scope"]), ("oidc", "full_admin"))
        self.assertEqual(claims["username"], "oidc:alice")

    def test_authorization_request_uses_pkce_s256_state_nonce(self):
        r, q = self.begin()
        self.assertEqual(q["code_challenge_method"], ["S256"])
        self.assertEqual(q["response_type"], ["code"])
        self.assertEqual(q["redirect_uri"], [PUBLIC + "/api/auth/oidc/callback"])
        self.assertEqual(q["scope"], ["openid profile email groups"])
        self.assertGreaterEqual(len(q["state"][0]), 32)
        self.assertGreaterEqual(len(q["nonce"][0]), 32)
        self.callback(self.client, q)
        url, form, basic = self.idp.token_requests[0]
        verifier = form["code_verifier"]
        self.assertEqual(q["code_challenge"][0],
                         base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode())
        self.assertEqual(form["redirect_uri"], PUBLIC + "/api/auth/oidc/callback")
        self.assertEqual(basic, (CLIENT_ID, CLIENT_SECRET))
        self.assertNotIn("client_secret", form)

    def test_cookie_flags(self):
        r = self.get(self.client, "/api/auth/oidc/login")
        cookie = r.headers["Set-Cookie"]
        for flag in ("HttpOnly", "Secure", "SameSite=Lax", "Path=/api/auth/oidc"):
            self.assertIn(flag, cookie)

    def test_cookie_not_secure_on_http_public_url(self):
        self.configure(public_url="http://pve.lan:8008")
        r = self.client.get("/api/auth/oidc/login")
        self.assertNotIn("Secure", r.headers["Set-Cookie"])
        self.assertIn("HttpOnly", r.headers["Set-Cookie"])

    def test_idp_error_is_a_failed_login(self):
        r, q = self.begin()
        resp = self.client.get("/api/auth/oidc/callback",
                               query_string={"error": "access_denied", "state": q["state"][0]}, base_url=PUBLIC)
        self.assert_denied_error(resp, "denied")
        self.assertEqual(oidc_manager.list_users(), [])

    def test_invalid_state_rejected(self):
        _, q = self.begin()
        resp = self.callback(self.client, q, state="forged-state")
        self.assert_denied_error(resp, "state")
        self.assertEqual(self.idp.token_requests, [])

    def test_state_is_single_use(self):
        _, q = self.begin()
        self.assertEqual(self.callback(self.client, q).status_code, 302)
        self.assert_denied_error(self.callback(self.client, q), "state")

    def test_login_csrf_state_without_browser_binding_rejected(self):
        """Attacker starts a login, tricks the victim's browser into the callback."""
        _, q = self.begin(self.app.test_client())          # attacker's browser
        victim = self.app.test_client()                    # no binding cookie
        self.assert_denied_error(self.callback(victim, q), "state")
        self.assertEqual(oidc_manager.list_users(), [])

    def test_invalid_nonce_rejected(self):
        _, q = self.begin()
        self.idp.id_token_override = self.idp.make_id_token("not-the-nonce")
        self.assert_denied_error(self.callback(self.client, q), "token")

    def test_missing_nonce_rejected(self):
        _, q = self.begin()
        self.idp.id_token_override = self.idp.make_id_token("ignored", nonce=None)
        self.assert_denied_error(self.callback(self.client, q), "token")

    def test_invalid_signature_rejected(self):
        _, q = self.begin()
        self.idp.key = _RSA_B   # signed by a key that is NOT key-a in the JWKS
        self.assert_denied_error(self.callback(self.client, q), "token")
        self.assertEqual(oidc_manager.list_users(), [])

    def test_unknown_kid_rejected(self):
        _, q = self.begin()
        self.idp.kid = "key-unknown"
        self.assert_denied_error(self.callback(self.client, q), "token")

    def test_expired_token_rejected(self):
        _, q = self.begin()
        past = int(time.time()) - 3600
        self.idp.id_token_override = self.idp.make_id_token(self.idp.current_nonce, iat=past - 60, exp=past)
        self.assert_denied_error(self.callback(self.client, q), "token")

    def test_wrong_issuer_rejected(self):
        _, q = self.begin()
        self.idp.id_token_override = self.idp.make_id_token(self.idp.current_nonce, iss="https://evil.example.com")
        self.assert_denied_error(self.callback(self.client, q), "token")

    def test_wrong_audience_rejected(self):
        _, q = self.begin()
        self.idp.id_token_override = self.idp.make_id_token(self.idp.current_nonce, aud="another-client")
        self.assert_denied_error(self.callback(self.client, q), "token")

    def test_hs256_token_signed_with_client_secret_rejected(self):
        """Algorithm-confusion: HS256 / alg=none must never validate."""
        _, q = self.begin()
        now = int(time.time())
        claims = dict(iss=ISSUER, aud=CLIENT_ID, sub="x", iat=now, exp=now + 60,
                      nonce=self.idp.current_nonce, groups=["proxmenux-admins"])
        self.idp.id_token_override = jwt.encode(claims, CLIENT_SECRET * 2, algorithm="HS256")
        self.assert_denied_error(self.callback(self.client, q), "token")
        _, q = self.begin()
        self.idp.id_token_override = jwt.encode(claims, None, algorithm="none")
        self.assert_denied_error(self.callback(self.client, q), "token")

    def test_discovery_issuer_mismatch_rejected(self):
        self.idp.discovery_overrides["issuer"] = "https://evil.example.com"
        r = self.get(self.client, "/api/auth/oidc/login")
        self.assert_denied_error(r, "config")

    def test_provider_without_pkce_s256_rejected(self):
        self.idp.discovery_overrides["code_challenge_methods_supported"] = ["plain"]
        self.assert_denied_error(self.get(self.client, "/api/auth/oidc/login"), "config")

    def test_http_issuer_rejected_by_config_validation(self):
        cfg = oidc_manager.load_config()
        cfg["issuer"] = "http://auth.example.com"
        self.assertTrue(oidc_manager.validate_config(cfg)["errors"])

    def test_code_exchange_requires_browser_binding_and_is_single_use(self):
        _, q = self.begin()
        r = self.callback(self.client, q)
        code = parse_qs(urlparse(r.headers["Location"]).query)["oidc_code"][0]
        other = self.app.test_client()
        bad = other.post("/api/auth/oidc/exchange", json={"code": code}, base_url=PUBLIC)
        self.assertEqual(bad.status_code, 401)
        # a stolen code burns on first use, so the rightful browser cannot redeem it either
        again = self.client.post("/api/auth/oidc/exchange", json={"code": code}, base_url=PUBLIC)
        self.assertEqual(again.status_code, 401)

    def test_exchange_code_replay_rejected(self):
        _, q = self.begin()
        code = parse_qs(urlparse(self.callback(self.client, q).headers["Location"]).query)["oidc_code"][0]
        self.assertEqual(self.client.post("/api/auth/oidc/exchange", json={"code": code}, base_url=PUBLIC).status_code, 200)
        self.assertEqual(self.client.post("/api/auth/oidc/exchange", json={"code": code}, base_url=PUBLIC).status_code, 401)

    def test_exchange_code_expires(self):
        _, q = self.begin()
        code = parse_qs(urlparse(self.callback(self.client, q).headers["Location"]).query)["oidc_code"][0]
        with mock.patch.object(oidc_manager.time, "time", return_value=time.time() + 120):
            r = self.client.post("/api/auth/oidc/exchange", json={"code": code}, base_url=PUBLIC)
        self.assertEqual(r.status_code, 401)

    def test_transaction_expires(self):
        _, q = self.begin()
        with mock.patch.object(oidc_manager.time, "time", return_value=time.time() + 700):
            self.assert_denied_error(self.callback(self.client, q), "state")

    def test_jwks_key_rotation_refetches_once(self):
        """A token signed by a key that appears after the JWKS was cached must verify."""
        self.begin()
        self.full_login()          # primes the JWKS cache
        oidc_manager._jwks_cache[next(iter(oidc_manager._jwks_cache))]["fetched"] = 0  # allow refetch
        self.idp.kid = "key-a"
        self.assertTrue(self.login_as(["proxmenux-admins"], sub="sub-2"))


class UserAndRoleTests(OidcTestBase):
    def test_group_mapping_each_role(self):
        for groups, role in ((["proxmenux-admins"], "admin"), (["proxmenux-users"], "user"),
                             (["proxmenux-readonly"], "readonly")):
            self.idp.groups, self.idp.sub = groups, f"sub-{role}"
            _, body = self.full_login(self.app.test_client())
            self.assertEqual(body["role"], role)

    def test_highest_role_wins(self):
        self.idp.groups = ["proxmenux-readonly", "proxmenux-users", "other"]
        self.assertEqual(self.full_login(self.app.test_client())[1]["role"], "user")
        self.idp.groups, self.idp.sub = ["proxmenux-readonly", "proxmenux-admins"], "sub-9"
        self.assertEqual(self.full_login(self.app.test_client())[1]["role"], "admin")

    def test_multiple_groups_per_role_and_custom_claim(self):
        self.configure(admin_group="ops, sre", group_claim="roles")
        self.idp.groups = None
        self.idp.extra = {"roles": ["sre"]}
        self.assertEqual(self.full_login(self.app.test_client())[1]["role"], "admin")

    def test_nested_group_claim(self):
        self.configure(group_claim="realm.groups")
        self.idp.groups = None
        self.idp.extra = {"realm": {"groups": ["proxmenux-users"]}}
        self.assertEqual(self.full_login(self.app.test_client())[1]["role"], "user")

    def test_groups_fall_back_to_userinfo(self):
        self.idp.groups = None
        self.idp.userinfo_groups = ["proxmenux-readonly"]
        self.assertEqual(self.full_login(self.app.test_client())[1]["role"], "readonly")

    def test_user_without_mapped_group_denied(self):
        for groups in ([], ["some-other-group"], None):
            self.idp.groups = groups
            _, q = self.begin(self.app.test_client()) if False else (None, None)
            client = self.app.test_client()
            _, q = self.begin(client)
            self.assert_denied_error(self.callback(client, q), "no_role")
        self.assertEqual(oidc_manager.list_users(), [])

    def test_default_role_applies_when_configured(self):
        self.configure(default_role="readonly")
        self.idp.groups = ["unmapped"]
        self.assertEqual(self.full_login(self.app.test_client())[1]["role"], "readonly")

    def test_auto_provisioning_disabled_blocks_new_users_only(self):
        self.configure(auto_provision=False)
        client = self.app.test_client()
        _, q = self.begin(client)
        self.assert_denied_error(self.callback(client, q), "provisioning")
        self.configure(auto_provision=True)
        self.login_as(["proxmenux-users"])                      # provision once
        self.configure(auto_provision=False)
        self.assertTrue(self.login_as(["proxmenux-users"]))     # known identity may still log in

    def test_identity_is_issuer_plus_subject_never_email(self):
        self.login_as(["proxmenux-users"], sub="sub-A")
        # Different subject, SAME e-mail and username -> separate account, never merged
        self.login_as(["proxmenux-readonly"], sub="sub-B")
        users = oidc_manager.list_users()
        self.assertEqual(len(users), 2)
        self.assertEqual({u["role"] for u in users}, {"user", "readonly"})
        # same sub again -> same account
        self.login_as(["proxmenux-admins"], sub="sub-A")
        self.assertEqual(len(oidc_manager.list_users()), 2)

    def test_role_is_refreshed_on_every_login(self):
        self.login_as(["proxmenux-admins"], sub="s")
        self.login_as(["proxmenux-readonly"], sub="s")
        self.assertEqual(oidc_manager.list_users()[0]["role"], "readonly")

    def test_oidc_never_links_to_local_account(self):
        self.idp.extra = {"preferred_username": "localadmin"}
        token = self.login_as(["proxmenux-admins"])
        self.assertEqual(jwt.decode(token, options={"verify_signature": False})["username"], "oidc:localadmin")

    def test_user_disabled_loses_access_immediately(self):
        token = self.login_as(["proxmenux-admins"])
        self.assertEqual(self.client.get("/api/test/read", headers=self.auth(token)).status_code, 200)
        uid = oidc_manager.list_users()[0]["id"]
        oidc_manager.set_user_disabled(uid, True)
        self.assertEqual(self.client.get("/api/test/read", headers=self.auth(token)).status_code, 401)
        client = self.app.test_client()
        _, q = self.begin(client)
        self.assert_denied_error(self.callback(client, q), "disabled")


class PermissionTests(OidcTestBase):
    def _codes(self, token):
        h = self.auth(token)
        c = self.client
        return {
            "read": c.get("/api/test/read", headers=h).status_code,
            "control": c.post("/api/vms/100/control", headers=h).status_code,
            "execute": c.post("/api/scripts/execute", headers=h).status_code,
            "admin": c.post("/api/test/admin", headers=h).status_code,
        }

    def test_admin_may_do_everything(self):
        self.assertEqual(self._codes(self.login_as(["proxmenux-admins"])),
                         {"read": 200, "control": 200, "execute": 200, "admin": 200})

    def test_user_gets_allow_listed_actions_only(self):
        self.assertEqual(self._codes(self.login_as(["proxmenux-users"])),
                         {"read": 200, "control": 200, "execute": 403, "admin": 403})

    def test_readonly_may_only_read(self):
        self.assertEqual(self._codes(self.login_as(["proxmenux-readonly"])),
                         {"read": 200, "control": 403, "execute": 403, "admin": 403})

    def test_role_comes_from_server_not_from_token_claims(self):
        token = self.login_as(["proxmenux-readonly"])
        claims = jwt.decode(token, options={"verify_signature": False})
        claims.update(scope="full_admin", role="admin")
        forged_scope = jwt.encode(claims, auth_manager._get_jwt_secret(), algorithm="HS256")
        # Even a token re-signed with a valid secret cannot raise privileges: scope is read from the DB.
        self.assertEqual(self._codes(forged_scope)["execute"], 403)

    def test_rbac_matrix(self):
        self.assertTrue(rbac.is_allowed("full_admin", "DELETE", "/api/anything"))
        self.assertTrue(rbac.is_allowed("read_only", "GET", "/x"))
        self.assertFalse(rbac.is_allowed("read_only", "POST", "/api/vms/1/control"))
        self.assertTrue(rbac.is_allowed("user", "POST", "/api/vms/12/control"))
        self.assertFalse(rbac.is_allowed("user", "POST", "/api/vms/12/control/../x"))
        self.assertFalse(rbac.is_allowed("user", "POST", "/api/system/power/reboot"))
        self.assertFalse(rbac.is_allowed("user", "PUT", "/api/vms/12/control"))
        self.assertFalse(rbac.is_allowed("unknown", "GET", "/x"))
        self.assertIsNone(rbac.scope_for_role("nonsense"))

    def test_oidc_session_cannot_touch_local_account(self):
        token = self.login_as(["proxmenux-admins"])
        h = self.auth(token)
        for path, body in (("/api/auth/change-password", {"old_password": LOCAL_PW, "new_password": "An0ther!Passw0rd"}),
                           ("/api/auth/totp/setup", {}), ("/api/auth/disable", {}),
                           ("/api/auth/generate-api-token", {"password": LOCAL_PW})):
            r = self.client.post(path, json=body, headers=h)
            self.assertEqual(r.status_code, 403, path)
        self.assertEqual(self.client.put("/api/auth/profile", json={"display_name": "x"}, headers=h).status_code, 403)
        self.assertTrue(auth_manager.load_auth_config()["enabled"])
        self.assertTrue(auth_manager.verify_password(LOCAL_PW, auth_manager.load_auth_config()["password_hash"]))

    def test_non_admin_cannot_read_or_change_oidc_settings(self):
        for groups in (["proxmenux-users"], ["proxmenux-readonly"]):
            h = self.auth(self.login_as(groups))
            self.assertEqual(self.client.get("/api/auth/oidc/settings", headers=h).status_code, 403)
            self.assertEqual(self.client.put("/api/auth/oidc/settings", json={"enabled": False}, headers=h).status_code, 403)
            self.assertEqual(self.client.get("/api/auth/oidc/users", headers=h).status_code, 403)
        self.assertEqual(self.client.get("/api/auth/oidc/settings").status_code, 401)


class LogoutAndSessionTests(OidcTestBase):
    def test_logout_revokes_session_and_returns_idp_url(self):
        token = self.login_as(["proxmenux-admins"])
        r = self.client.post("/api/auth/oidc/logout", headers=self.auth(token))
        url = r.get_json()["logout_url"]
        self.assertTrue(url.startswith("https://auth.example.com/application/o/proxmenux/end-session/?"))
        q = parse_qs(urlparse(url).query)
        self.assertIn("id_token_hint", q)
        self.assertEqual(q["post_logout_redirect_uri"], [PUBLIC + "/"])
        self.assertEqual(self.client.get("/api/test/read", headers=self.auth(token)).status_code, 401)

    def test_logout_without_central_logout(self):
        self.configure(oidc_logout=False)
        token = self.login_as(["proxmenux-admins"])
        self.assertIsNone(self.client.post("/api/auth/oidc/logout", headers=self.auth(token)).get_json()["logout_url"])
        self.assertEqual(self.client.get("/api/test/read", headers=self.auth(token)).status_code, 401)

    def test_logout_of_local_session_has_no_idp_url(self):
        ok, token, _, _ = auth_manager.authenticate("localadmin", LOCAL_PW)
        self.assertTrue(ok)
        self.assertIsNone(self.client.post("/api/auth/oidc/logout", headers=self.auth(token)).get_json()["logout_url"])

    def test_session_timeout_is_honoured(self):
        self.configure(session_timeout_minutes=5)
        token = self.login_as(["proxmenux-admins"])
        claims = jwt.decode(token, options={"verify_signature": False})
        self.assertAlmostEqual(claims["exp"] - claims["iat"], 300, delta=2)
        with mock.patch.object(oidc_manager.time, "time", return_value=time.time() + 400):
            self.assertIsNone(oidc_manager.validate_session(claims["sid"]))

    def test_session_dies_when_oidc_disabled_or_issuer_changes(self):
        token = self.login_as(["proxmenux-admins"])
        self.configure(issuer="https://other-idp.example.com/o/x")
        self.assertEqual(self.client.get("/api/test/read", headers=self.auth(token)).status_code, 401)
        self.configure(issuer=ISSUER, enabled=False)
        self.assertEqual(self.client.get("/api/test/read", headers=self.auth(token)).status_code, 401)

    def test_every_login_mints_a_fresh_token(self):
        a = self.login_as(["proxmenux-admins"])
        b = self.login_as(["proxmenux-admins"])
        self.assertNotEqual(a, b)
        self.assertNotEqual(jwt.decode(a, options={"verify_signature": False})["sid"],
                            jwt.decode(b, options={"verify_signature": False})["sid"])

    def test_login_endpoints_are_rate_limited(self):
        codes = [self.get(self.client, "/api/auth/oidc/login").status_code for _ in range(25)]
        self.assertEqual(codes.count(429), 5)


class LocalLoginTests(OidcTestBase):
    def test_local_login_still_works_with_oidc_enabled(self):
        r = self.client.post("/api/auth/login", json={"username": "localadmin", "password": LOCAL_PW})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["token"])
        token = r.get_json()["token"]
        self.assertEqual(self.client.post("/api/scripts/execute", headers=self.auth(token)).status_code, 200)

    def test_local_login_rejects_bad_password(self):
        r = self.client.post("/api/auth/login", json={"username": "localadmin", "password": "wrong-password-1A!"})
        self.assertEqual(r.status_code, 401)

    def test_local_login_can_be_disabled(self):
        oidc_manager._record_status(True, "ok", "test")
        self.configure(allow_local_login=False, last_status={"ok": True, "message": "", "kind": "test", "checked_at": 1})
        r = self.client.post("/api/auth/login", json={"username": "localadmin", "password": LOCAL_PW})
        self.assertEqual(r.status_code, 403)
        self.assertTrue(r.get_json()["local_login_disabled"])
        ok, token, _, _ = auth_manager.authenticate("localadmin", LOCAL_PW)
        self.assertFalse(ok)     # API-token generation (authenticate()) is gated as well
        st = self.client.get("/api/auth/status").get_json()
        self.assertFalse(st["local_login_allowed"])
        self.assertTrue(st["oidc"]["enabled"])
        # OIDC login remains possible
        self.assertTrue(self.login_as(["proxmenux-admins"]))

    def test_local_login_open_again_when_oidc_disabled(self):
        self.configure(allow_local_login=False, enabled=False)
        r = self.client.post("/api/auth/login", json={"username": "localadmin", "password": LOCAL_PW})
        self.assertEqual(r.status_code, 200)

    def test_standard_install_without_oidc_unchanged(self):
        oidc_manager.config_path().unlink()
        st = self.client.get("/api/auth/status").get_json()
        self.assertFalse(st["oidc"]["enabled"])
        self.assertTrue(st["local_login_allowed"])
        self.assertEqual(self.client.post("/api/auth/login",
                                          json={"username": "localadmin", "password": LOCAL_PW}).status_code, 200)
        self.assertEqual(self.get(self.client, "/api/auth/oidc/login").status_code, 302)  # -> error redirect
        self.assertIn("oidc_error", self.get(self.client, "/api/auth/oidc/login").headers["Location"])

    def test_legacy_local_token_without_scope_is_still_admin(self):
        token = auth_manager.generate_token("localadmin")
        self.assertEqual(auth_manager.verify_token_full(token), ("localadmin", "full_admin"))


class SettingsAndSecretTests(OidcTestBase):
    def admin_headers(self):
        ok, token, _, _ = auth_manager.authenticate("localadmin", LOCAL_PW)
        return self.auth(token)

    def test_secret_is_encrypted_on_disk_and_never_returned_or_logged(self):
        h = self.admin_headers()
        with self.assertLogs("proxmenux-auth", level="WARNING") as logs:
            logging.getLogger("proxmenux-auth").warning("sentinel")
            r = self.client.put("/api/auth/oidc/settings", headers=h, json={"client_secret": "brand-new-secret-123"})
            self.assertEqual(r.status_code, 200, r.data)
            _, q = self.begin(self.client)
            self.idp.groups = None
            self.callback(self.client, q)
        for blob in (r.get_data(as_text=True), self.client.get("/api/auth/oidc/settings", headers=h).get_data(as_text=True),
                     oidc_manager.config_path().read_text(), "\n".join(logs.output)):
            self.assertNotIn("brand-new-secret-123", blob)
            self.assertNotIn(CLIENT_SECRET, blob)
        settings = self.client.get("/api/auth/oidc/settings", headers=h).get_json()["settings"]
        self.assertTrue(settings["client_secret_set"])
        self.assertNotIn("client_secret_enc", settings)
        self.assertNotIn("client_secret", settings)
        self.assertEqual(oidc_manager.decrypt_secret(oidc_manager.load_config()["client_secret_enc"]),
                         "brand-new-secret-123")
        for p in (oidc_manager.config_path(), oidc_manager.key_path(), oidc_manager.db_path()):
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600, p)

    def test_empty_secret_keeps_stored_secret(self):
        h = self.admin_headers()
        self.client.put("/api/auth/oidc/settings", headers=h, json={"client_secret": "", "provider_name": "Corp SSO"})
        cfg = oidc_manager.load_config()
        self.assertEqual(cfg["provider_name"], "Corp SSO")
        self.assertEqual(oidc_manager.decrypt_secret(cfg["client_secret_enc"]), CLIENT_SECRET)

    def test_settings_validation(self):
        h = self.admin_headers()
        for bad in ({"issuer": "http://auth.example.com"}, {"session_timeout_minutes": 1},
                    {"session_timeout_minutes": "x"}, {"default_role": "root"}, {"scopes": "profile"},
                    {"enabled": "yes"}, {"public_url": ""}):
            r = self.client.put("/api/auth/oidc/settings", headers=h, json=bad)
            self.assertEqual(r.status_code, 400, bad)

    def test_cannot_enable_without_local_auth(self):
        auth_manager.disable_auth()
        cfg = oidc_manager.load_config()
        self.assertTrue(any("local authentication" in e for e in oidc_manager.validate_config(cfg)["errors"]))

    def test_cannot_disable_local_login_without_successful_test(self):
        h = self.admin_headers()
        r = self.client.put("/api/auth/oidc/settings", headers=h, json={"allow_local_login": False})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.client.post("/api/auth/oidc/test", headers=h).get_json()["ok"], True)
        r = self.client.put("/api/auth/oidc/settings", headers=h, json={"allow_local_login": False})
        self.assertEqual(r.status_code, 200, r.data)

    def test_connection_test_reports_discovery_and_status(self):
        h = self.admin_headers()
        res = self.client.post("/api/auth/oidc/test", headers=h).get_json()
        self.assertTrue(res["ok"])
        self.assertEqual(res["discovery"]["issuer"], ISSUER)
        self.assertEqual(res["jwks_keys"], 2)
        self.assertTrue(oidc_manager.load_config()["last_status"]["ok"])
        self.idp.discovery_overrides["id_token_signing_alg_values_supported"] = ["HS256"]
        oidc_manager.clear_caches()
        res = self.client.post("/api/auth/oidc/test", headers=h).get_json()
        self.assertFalse(res["ok"])
        self.assertFalse(oidc_manager.load_config()["last_status"]["ok"])

    def test_connection_change_resets_last_status(self):
        h = self.admin_headers()
        self.client.post("/api/auth/oidc/test", headers=h)
        self.client.put("/api/auth/oidc/settings", headers=h, json={"client_id": "other"})
        self.assertIsNone(oidc_manager.load_config()["last_status"])

    def test_user_management_endpoints(self):
        self.login_as(["proxmenux-users"])
        h = self.admin_headers()
        users = self.client.get("/api/auth/oidc/users", headers=h).get_json()["users"]
        self.assertEqual(len(users), 1)
        self.assertNotIn("subject", users[0])
        uid = users[0]["id"]
        self.assertEqual(self.client.patch(f"/api/auth/oidc/users/{uid}", headers=h, json={"disabled": True}).status_code, 200)
        self.assertEqual(self.client.delete(f"/api/auth/oidc/users/{uid}", headers=h).status_code, 200)
        self.assertEqual(self.client.delete(f"/api/auth/oidc/users/{uid}", headers=h).status_code, 404)


class MigrationTests(OidcTestBase):
    def test_migration_is_idempotent_and_versioned(self):
        oidc_manager.migrate()
        oidc_manager._migrated.clear()
        oidc_manager.migrate()
        conn = oidc_manager._connect()
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], oidc_manager.SCHEMA_VERSION)
        conn.close()

    def test_upgrade_backs_up_existing_db(self):
        oidc_manager.migrate()
        self.login_as(["proxmenux-users"])
        with mock.patch.object(oidc_manager, "_MIGRATIONS", oidc_manager._MIGRATIONS + ["ALTER TABLE users ADD COLUMN note TEXT"]), \
                mock.patch.object(oidc_manager, "SCHEMA_VERSION", 2):
            oidc_manager._migrated.clear()
            oidc_manager.migrate()
        backup = Path(str(oidc_manager.db_path()) + ".bak-v1")
        self.assertTrue(backup.exists())
        self.assertEqual(len(oidc_manager.list_users()), 1)

    def test_newer_database_is_refused(self):
        oidc_manager.migrate()
        conn = oidc_manager._connect()
        conn.execute("PRAGMA user_version=99")
        conn.close()
        oidc_manager._migrated.clear()
        with self.assertRaises(oidc_manager.OidcError):
            oidc_manager.migrate()

    def test_cli_disable_and_purge(self):
        self.configure(allow_local_login=False)
        self.assertEqual(oidc_manager._cli(["x", "disable"]), 0)
        cfg = oidc_manager.load_config()
        self.assertFalse(cfg["enabled"])
        self.assertTrue(cfg["allow_local_login"])
        oidc_manager.migrate()
        self.assertEqual(oidc_manager._cli(["x", "purge"]), 0)
        self.assertFalse(oidc_manager.db_path().exists())
        self.assertFalse(oidc_manager.config_path().exists())
        self.assertFalse(oidc_manager.key_path().exists())
        self.assertTrue(auth_manager.AUTH_CONFIG_FILE.exists())   # local account untouched


if __name__ == "__main__":
    unittest.main(verbosity=2)
