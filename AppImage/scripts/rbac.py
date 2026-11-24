"""
Role-based access control for ProxMenux Monitor sessions.

Existing model (unchanged): a session/API token carries a `scope` claim.
  * ``full_admin`` - everything (local login, legacy tokens, OIDC admins)
  * ``read_only``  - GET/HEAD/OPTIONS only

OIDC integration adds one intermediate scope:
  * ``user``       - read access plus an explicit allow-list of mutating
                     operations (guest power control, update checks, guest
                     backups, custom links).  Everything NOT on the
                     allow-list is denied (deny by default).

Routes decorated with ``require_admin_scope`` already demand ``full_admin``,
so ``user`` and ``read_only`` can never reach them.

The decision is made on the server for every request; the UI merely mirrors
it for convenience.
"""

import re

ROLE_ADMIN = "admin"
ROLE_USER = "user"
ROLE_READONLY = "readonly"
ROLES = (ROLE_ADMIN, ROLE_USER, ROLE_READONLY)

SCOPE_ADMIN = "full_admin"
SCOPE_USER = "user"
SCOPE_READONLY = "read_only"

ROLE_TO_SCOPE = {
    ROLE_ADMIN: SCOPE_ADMIN,
    ROLE_USER: SCOPE_USER,
    ROLE_READONLY: SCOPE_READONLY,
}

# Higher number == more privileged. Used to pick the highest matching role
# when a user belongs to several mapped groups.
ROLE_RANK = {ROLE_READONLY: 1, ROLE_USER: 2, ROLE_ADMIN: 3}

READ_METHODS = ("GET", "HEAD", "OPTIONS")

# (method, compiled-path) pairs a `user` session may call.  Keep this list
# short and review every addition: it is the whole definition of what the
# "Benutzer" role may change.
_USER_WRITE_ALLOWLIST = [
    ("POST", r"^/api/vms/\d+/control$"),
    ("POST", r"^/api/vms/\d+/updates/check$"),
    ("POST", r"^/api/vms/\d+/updates/refresh-check$"),
    ("POST", r"^/api/vms/\d+/apps/check$"),
    ("POST", r"^/api/vms/\d+/apps/[^/]+/check$"),
    ("POST", r"^/api/vms/\d+/backup$"),
    ("POST", r"^/api/apps/custom-links$"),
    ("PUT", r"^/api/apps/custom-links/[^/]+$"),
    ("DELETE", r"^/api/apps/custom-links/[^/]+$"),
]
_USER_WRITE_ALLOWLIST = [(m, re.compile(p)) for m, p in _USER_WRITE_ALLOWLIST]


def scope_for_role(role):
    """Map a ProxMenux role to a token scope. Unknown role -> no access."""
    return ROLE_TO_SCOPE.get(role)


def is_allowed(scope, method, path):
    """Return True when a session with `scope` may issue `method` on `path`."""
    method = (method or "").upper()
    if scope == SCOPE_ADMIN:
        return True
    if method in READ_METHODS:
        return scope in (SCOPE_USER, SCOPE_READONLY)
    if scope == SCOPE_USER:
        return any(m == method and rx.match(path or "") for m, rx in _USER_WRITE_ALLOWLIST)
    return False
