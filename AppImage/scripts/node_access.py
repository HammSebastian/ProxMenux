"""
Per-node access control (server side, evaluated on every request).

Extends rbac.py (which answers "may this role do <method> <path>?") with
"may this identity touch THIS node at all?".

Rules, in order:
  1. no authentication configured / local ProxMenux account / local API token
     -> every node (these identities already are administrator-issued)
  2. OIDC user with an explicit per-user DENY for the node (or ``*``)  -> no
     (deny always wins, also for administrators)
  3. OIDC administrator (group ``proxmenux-admins``)                    -> yes
  4. per-user ALLOW for the node (or ``*``)                             -> yes
  5. role allow-list (``user`` = proxmenux-users, ``readonly`` =
     proxmenux-readonly) containing the node, ``*`` or ``@local``       -> yes
  6. otherwise                                                          -> no
"""

import re

from flask import request

import auth_manager
import cluster_manager
import rbac

_GUEST_PATH = re.compile(r"^/api/(?:vms|lxc)/(\d+)(?:/|$)")


class Identity:
    __slots__ = ("username", "scope", "src", "user_id", "role", "anonymous")

    def __init__(self, username=None, scope=rbac.SCOPE_ADMIN, src="local",
                 user_id=None, role=None, anonymous=False):
        self.username, self.scope, self.src = username, scope, src
        self.user_id, self.role, self.anonymous = user_id, role, anonymous

    @property
    def label(self):
        return self.username or "anonymous"


class AuthRequired(Exception):
    pass


def identity_from_request():
    """Resolve the caller. Raises AuthRequired for missing/invalid sessions.
    Mirrors jwt_middleware.require_auth: with auth disabled everything is open."""
    cfg = auth_manager.load_auth_config()
    if not cfg.get("enabled", False) or cfg.get("declined", False):
        return Identity(anonymous=True)
    parts = (request.headers.get("Authorization") or "").split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise AuthRequired()
    info = auth_manager.get_session_info(parts[1])
    if not info:
        raise AuthRequired()
    ident = Identity(info["username"], info["scope"], info["src"])
    if info["src"] == "oidc":
        import oidc_manager
        user = oidc_manager.get_session_user(info["sid"]) if info["sid"] else None
        if not user:
            raise AuthRequired()
        ident.user_id, ident.role = user["id"], user["role"]
    return ident


def _matches(entries, node, local):
    for e in entries or ():
        if e == "*" or e == node or (e == "@local" and node == local):
            return True
    return False


def can_access(identity, node, cfg=None, local=None):
    """Decision for one (identity, node)."""
    if identity.src != "oidc":
        return True
    cfg = cfg or cluster_manager.load_config()
    local = local or cluster_manager.local_node_name()
    perms = cfg.get("permissions") or {}
    rule = (perms.get("user_rules") or {}).get(str(identity.user_id), {})
    if _matches(rule.get("deny"), node, local):
        return False
    if identity.role == rbac.ROLE_ADMIN:
        return True
    if _matches(rule.get("allow"), node, local):
        return True
    if identity.role in (rbac.ROLE_USER, rbac.ROLE_READONLY):
        return _matches((perms.get("role_nodes") or {}).get(identity.role), node, local)
    return False


def allowed_node_names(identity, names, cfg=None):
    cfg = cfg or cluster_manager.load_config()
    local = cluster_manager.local_node_name()
    return [n for n in names if can_access(identity, n, cfg, local)]


def restricts_local(cfg):
    """True when some OIDC identity could be denied the LOCAL node, which makes
    the check necessary even for requests without a node selector."""
    local = cluster_manager.local_node_name()
    perms = cfg.get("permissions") or {}
    for role in ("user", "readonly"):
        if not _matches((perms.get("role_nodes") or {}).get(role), local, local):
            return True
    for rule in (perms.get("user_rules") or {}).values():
        if _matches(rule.get("deny"), local, local):
            return True
    return False


def guest_vmid(path):
    m = _GUEST_PATH.match(path or "")
    return int(m.group(1)) if m else None
