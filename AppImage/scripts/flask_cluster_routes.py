"""
Flask routes for multi-node (cluster) management.

  GET  /api/cluster/nodes       nodes the caller may see + cluster/discovery state
  GET  /api/cluster/guests      VMs/containers of all visible nodes (column "Node")

Administrator only (full_admin scope, rate limited, audited):
  GET/PUT /api/cluster/settings
  POST    /api/cluster/discover   manual discovery
  POST    /api/cluster/test       connection / TLS / token / privilege test
  GET     /api/cluster/audit      recent audit events

The API token secret is write-only: it is stored encrypted and never returned.
"""

from flask import Blueprint, jsonify, request

import cluster_gateway as gw
import cluster_manager as cm
import node_access
from jwt_middleware import require_auth, require_admin_scope

cluster_bp = Blueprint("cluster", __name__)

PUBLIC_NODE_FIELDS = ("name", "node_id", "local", "online", "status", "cluster", "pve_version",
                      "api_status", "api_error", "cpu", "maxcpu", "mem", "maxmem", "disk",
                      "maxdisk", "uptime", "last_seen", "last_checked")
ADMIN_NODE_FIELDS = ("ip", "ssl_fingerprint")


def _identity():
    try:
        return node_access.identity_from_request()
    except node_access.AuthRequired:
        return None


def _admin_limited(ident):
    ok, retry = gw.admin_limiter.hit(ident.label if ident else "anon")
    if ok:
        return None
    r = jsonify({"success": False, "message": "Too many requests", "retry_after": retry})
    r.status_code = 429
    r.headers["Retry-After"] = str(retry)
    return r


def _visible(ident, cfg):
    nodes = cm.list_nodes()
    allowed = set(node_access.allowed_node_names(ident, [n["name"] for n in nodes], cfg))
    admin = ident.src != "oidc" or ident.role == "admin"
    out = []
    for n in nodes:
        if n["name"] not in allowed:
            continue
        keys = PUBLIC_NODE_FIELDS + (ADMIN_NODE_FIELDS if admin else ())
        out.append({k: n.get(k) for k in keys})
    return out


@cluster_bp.route("/api/cluster/nodes", methods=["GET"])
@require_auth
def nodes():
    ident = _identity()
    if ident is None:
        return jsonify({"error": "Authentication required"}), 401
    cfg = cm.load_config()
    visible = _visible(ident, cfg)
    info, disc = cm.cluster_info()
    local = cm.local_node_name()
    names = [n["name"] for n in visible]
    default = local if local in names else (names[0] if names else None)
    # Non-admins only learn aggregate numbers about nodes they may see.
    info = dict(info)
    info.update(node_count=len(visible), online=sum(1 for n in visible if n["status"] == "online"))
    info["offline"] = info["node_count"] - info["online"]
    return jsonify({"success": True, "enabled": cfg["enabled"], "cluster": info,
                    "discovery": {"enabled": disc["enabled"], "last_sync": disc["last_sync"],
                                  "interval": disc["interval"], "running": disc["running"]},
                    "local_node": local, "default_node": default, "nodes": visible})


@cluster_bp.route("/api/cluster/guests", methods=["GET"])
@require_auth
def guests():
    ident = _identity()
    if ident is None:
        return jsonify({"error": "Authentication required"}), 401
    cfg = cm.load_config()
    names = [n["name"] for n in _visible(ident, cfg)]
    online = [n for n in names if (cm.get_node(n) or {}).get("online")]
    rows, errors, stale = cm.list_guests(online)
    offline = [n for n in names if n not in online]
    for n in offline:
        errors[n] = {"code": "offline", "message": gw.OFFLINE_TEXT}
    return jsonify({"success": True, "guests": [gw._guest_row(g) for g in rows],
                    "errors": errors, "stale": stale})


@cluster_bp.route("/api/cluster/settings", methods=["GET"])
@require_admin_scope
def get_settings():
    info, disc = cm.cluster_info()
    return jsonify({"success": True, "settings": cm.public_config(), "cluster": info,
                    "discovery": disc, "local_node": cm.local_node_name(),
                    "nodes": cm.list_nodes()})


@cluster_bp.route("/api/cluster/settings", methods=["PUT"])
@require_admin_scope
def put_settings():
    ident = _identity()
    limited = _admin_limited(ident)
    if limited:
        return limited
    data = request.get_json(silent=True)
    before = cm.load_config()
    cfg, err = cm.validate_settings_update(data, cm.load_config())
    if err:
        return jsonify({"success": False, "message": err}), 400
    cm.save_config(cfg)
    cm._cache.clear()
    changed = sorted(k for k in (data or {}) if k != "token_secret" and before.get(k) != cfg.get(k))
    if "token_secret" in (data or {}) and data["token_secret"]:
        changed.append("token_secret")
    gw.audit("settings_changed", ident, changed=changed)
    return jsonify({"success": True, "settings": cm.public_config(cfg)})


@cluster_bp.route("/api/cluster/discover", methods=["POST"])
@require_admin_scope
def discover():
    ident = _identity()
    limited = _admin_limited(ident)
    if limited:
        return limited
    result = cm.discover(force=True)
    gw.audit("manual_discovery", ident, ok=result.get("ok"))
    info, disc = cm.cluster_info()
    return jsonify({"success": bool(result.get("ok")), "result": result, "cluster": info,
                    "discovery": disc, "nodes": cm.list_nodes()}), 200


@cluster_bp.route("/api/cluster/test", methods=["POST"])
@require_admin_scope
def test():
    ident = _identity()
    limited = _admin_limited(ident)
    if limited:
        return limited
    data = request.get_json(silent=True) or {}
    node = data.get("node")
    if node is not None and not cm.valid_node_name(node):
        return jsonify({"success": False, "message": "Invalid node name"}), 400
    results = [cm.test_node(node)] if node else cm.test_all()
    gw.audit("connection_test", ident, node=node or "*", ok=all(r.get("ok") for r in results))
    return jsonify({"success": True, "results": results})


@cluster_bp.route("/api/cluster/audit", methods=["GET"])
@require_admin_scope
def audit_events():
    try:
        limit = int(request.args.get("limit", 100))
    except ValueError:
        limit = 100
    return jsonify({"success": True, "events": gw.read_audit(limit)})
