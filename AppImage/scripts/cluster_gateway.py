"""
Request gateway for multi-node operation.

A single ``before_request`` hook decides, for every ``/api/`` request, which
node it addresses (``X-ProxMenux-Node`` header or ``?pmx_node=``; none means
the local node) and enforces - on the server, on every request:

  * authentication + rbac scope (same rules as the route decorators)
  * per-node authorisation (node_access.can_access: groups + per-user allow/deny)
  * a per-user rate limit for requests that leave the local node
  * for guest routes (``/api/vms/<vmid>`` ...): the access right to the node
    that really hosts the guest, so a manipulated vmid/node pair can never
    reach a node the caller is not allowed to see

Requests for the local node continue to the existing Flask handlers
unchanged.  Requests for another node are answered here by
``REMOTE_ROUTES`` which read the node through the Proxmox API
(cluster_manager.node_call) and return the SAME JSON shapes as the local
handlers.  A node-scoped route without a remote implementation answers
``501 node_unsupported`` - it never silently returns the local node's data.

The central API token is only a transport: it is used strictly after the
caller passed the checks above and only for allow-listed operations.
"""

import json
import logging
import logging.handlers
import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from flask import Response, g, jsonify, request

import cluster_manager as cm
import node_access
import rbac

NODE_HEADER = "X-ProxMenux-Node"
NODE_QUERY = "pmx_node"
OFFLINE_TEXT = "Node offline – Daten derzeit nicht verfügbar"

# Instance-level routes: they configure ProxMenux itself (or authenticate) and
# never address a node, so the node selector is ignored for them.
GLOBAL_PREFIXES = (
    "/api/auth/", "/api/cluster/", "/api/notifications/", "/api/proxmenux/", "/api/platform",
    "/api/monitor-links", "/api/apps/", "/api/updates/", "/api/lxc-updates/",
    # ProxMenux health configuration (not the health STATUS of a node, which is
    # node-scoped): thresholds, exclusions, acknowledgements.
    "/api/health/settings", "/api/health/thresholds", "/api/health/disk-exclusions",
    "/api/health/storage-exclusions", "/api/health/interface-exclusions", "/api/health/dismissed",
    "/api/health/acknowledge", "/api/health/un-acknowledge", "/api/health/disks",
    "/api/health/interfaces", "/api/health/remote-storages",
)

audit_log = logging.getLogger("proxmenux.cluster.audit")
audit_log.setLevel(logging.INFO)
audit_log.propagate = False
_audit_state = {"path": None}


def _ensure_audit_handler():
    """(Re)attach the rotating JSON-lines file in the config dir."""
    path = str(cm._dir() / "cluster-audit.log")
    if _audit_state["path"] == path:
        return
    for h in list(audit_log.handlers):
        audit_log.removeHandler(h)
        try:
            h.close()
        except Exception:
            pass
    try:
        cm.auth_manager.ensure_config_dir()
        h = logging.handlers.RotatingFileHandler(path, maxBytes=1_000_000, backupCount=3)
    except Exception:
        h = logging.NullHandler()
    h.setFormatter(logging.Formatter("%(message)s"))
    audit_log.addHandler(h)
    _audit_state["path"] = path


def audit(event, identity=None, **fields):
    """One JSON line per security-relevant event. Never contains secrets."""
    try:
        _ensure_audit_handler()
        rec = {"ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "event": event,
               "user": getattr(identity, "label", None),
               "src": getattr(identity, "src", None), "ip": _client_ip()}
        rec.update({k: v for k, v in fields.items() if v is not None})
        audit_log.info(json.dumps(rec, separators=(",", ":")))
    except Exception:
        pass


def read_audit(limit=200):
    try:
        with open(cm._dir() / "cluster-audit.log", "r") as fh:
            lines = fh.readlines()[-max(1, min(int(limit), 1000)):]
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue
    return list(reversed(out))


def _client_ip():
    try:
        return request.remote_addr or "unknown"
    except RuntimeError:
        return "unknown"


class RateLimiter:
    """Sliding window per key."""

    def __init__(self, maximum, window):
        self.max, self.window = maximum, window
        self._b = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key):
        now = time.time()
        with self._lock:
            q = self._b[key]
            while q and q[0] < now - self.window:
                q.popleft()
            if len(q) >= self.max:
                return False, max(1, int(self.window - (now - q[0])))
            q.append(now)
            if len(self._b) > 2048:
                for k in [k for k, v in self._b.items() if not v or v[-1] < now - self.window]:
                    self._b.pop(k, None)
            return True, 0

    def reset(self):
        with self._lock:
            self._b.clear()


remote_read_limiter = RateLimiter(600, 60)     # proxied reads per user / minute
remote_write_limiter = RateLimiter(30, 60)     # proxied mutations per user / minute
admin_limiter = RateLimiter(20, 60)            # discovery/test/settings per user / minute


def _err(status, code, message, **extra):
    body = {"error": code, "message": message}
    body.update(extra)
    resp = jsonify(body)
    resp.status_code = status
    return resp


def node_error_response(node, exc):
    """Map a NodeApiError to an HTTP answer. Token/TLS problems are 502, never
    401/403, so the SPA does not mistake them for an expired user session."""
    if exc.code == "offline":
        return _err(503, "node_offline", OFFLINE_TEXT, node=node)
    if exc.code == "timeout":
        return _err(504, "node_timeout", exc.message, node=node)
    if exc.code in ("tls", "auth", "forbidden", "not_configured", "rejected_address"):
        return _err(502, f"node_{exc.code}", exc.message, node=node)
    if exc.code == "not_found":
        return _err(404, "not_found", exc.message, node=node)
    return _err(502, "node_error", exc.message, node=node)


def _attach(resp, node, *results):
    resp.headers[NODE_HEADER] = node
    stale = [r for r in results if r is not None and r.stale]
    if stale:
        resp.headers["X-ProxMenux-Stale"] = "1"
        resp.headers["X-ProxMenux-Cached-At"] = str(int(min(r.cached_at or 0 for r in stale)))
    return resp


# --------------------------------------------------------------------------
# Remote handlers: PVE API -> the shapes the local handlers return
# --------------------------------------------------------------------------

GB = 1024 ** 3


def _num(v, default=0):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else default


def _pve_version(s):
    m = re.search(r"pve-manager/([^/\s]+)", s or "")
    return m.group(1) if m else (s or None)


def _h_system(node, rec):
    res = cm.node_call(node, "GET", f"/nodes/{node}/status", ttl=4)
    d = res.data if isinstance(res.data, dict) else {}
    mem = d.get("memory") or {}
    total, used = _num(mem.get("total")), _num(mem.get("used"))
    cpuinfo = d.get("cpuinfo") or {}
    load = []
    for v in d.get("loadavg") or []:
        try:
            load.append(float(v))
        except (TypeError, ValueError):
            load.append(0.0)
    kver = (d.get("current-kernel") or {}).get("release") or (d.get("kversion") or "").split(" ")[1:2] or None
    if isinstance(kver, list):
        kver = kver[0] if kver else None
    cached = (_num(mem.get("cached")) + _num(mem.get("buffers"))) / GB
    payload = {
        "cpu_usage": round(_num(d.get("cpu")) * 100, 1), "cpu_user": 0, "cpu_system": 0,
        "memory_usage": round(used / total * 100, 1) if total else 0,
        "memory_total": round(total / GB, 1), "memory_used": round(used / GB, 1),
        "memory_cached": round(cached, 1),
        "zram": {"available": False, "devices": []},
        "temperature": 0, "temperature_sparkline": [],
        "uptime": str(timedelta(seconds=int(_num(d.get("uptime"))))),
        "load_average": load, "hostname": node, "proxmox_node": node, "node_id": node,
        "timestamp": datetime.now().isoformat(),
        "cpu_cores": _num(cpuinfo.get("cores"), 0) * max(1, _num(cpuinfo.get("sockets"), 1)) or None,
        "cpu_threads": cpuinfo.get("cpus"),
        "proxmox_version": _pve_version(d.get("pveversion")) or rec.get("pve_version"),
        "kernel_version": kver, "platform": {"type": "pve", "remote": True},
        "remote": True, "node": node,
    }
    return payload, [res]


def _h_system_info(node, rec):
    res = cm.node_call(node, "GET", f"/nodes/{node}/status", ttl=4)
    d = res.data if isinstance(res.data, dict) else {}
    return {"hostname": node, "node_id": node, "remote": True,
            "uptime": str(timedelta(seconds=int(_num(d.get("uptime"))))),
            "health": {"status": "OK"}}, [res]


def _guest_row(g_):
    return {
        "vmid": g_.get("vmid"), "name": g_.get("name"), "status": g_.get("status", "unknown"),
        "type": g_.get("type"), "cpu": g_.get("cpu", 0), "mem": g_.get("mem", 0),
        "maxmem": g_.get("maxmem", 0), "disk": g_.get("disk", 0), "maxdisk": g_.get("maxdisk", 0),
        "uptime": g_.get("uptime", 0), "netin": g_.get("netin", 0), "netout": g_.get("netout", 0),
        "diskread": g_.get("diskread", 0), "diskwrite": g_.get("diskwrite", 0),
        "maxcpu": g_.get("cpus", g_.get("maxcpu", 0)), "tags": g_.get("tags", ""),
        "template": bool(g_.get("template")), "node": g_.get("node"), "stale": bool(g_.get("stale")),
        "description": "", "modal_cache_revision": 0,
    }


def _h_vms(node, rec):
    info = cm._guests_of(node)
    rows = [_guest_row(x) for x in info["guests"]]
    r = cm.NodeResult(None, info["stale"], info["cached_at"])
    return rows, [r]


def _guest_on_node(node, vmid):
    info = cm._guests_of(node)
    for x in info["guests"]:
        if int(x["vmid"]) == int(vmid):
            return x["type"]
    return None


def _h_vm_detail(node, rec, vmid):
    kind = _guest_on_node(node, vmid)
    if not kind:
        return _err(404, "not_found", "VM/LXC not found on this node", node=node), []
    cfg_res = cm.node_call(node, "GET", f"/nodes/{node}/{kind}/{vmid}/config", ttl=10)
    st_res = cm.node_call(node, "GET", f"/nodes/{node}/{kind}/{vmid}/status/current", ttl=4)
    config = {k: v for k, v in (cfg_res.data or {}).items() if k != "digest"}
    return {"vmid": vmid, "config": config, "node": node, "vm_type": kind,
            "status": st_res.data if isinstance(st_res.data, dict) else {}, "remote": True}, [cfg_res, st_res]


def _h_storage_summary(node, rec):
    st = cm.node_call(node, "GET", f"/nodes/{node}/status", ttl=10)
    root = (st.data or {}).get("rootfs") or {}
    disks, results = [], [st]
    try:
        dl = cm.node_call(node, "GET", f"/nodes/{node}/disks/list", ttl=60)
        results.append(dl)
        disks = [d for d in (dl.data or []) if isinstance(d, dict)]
    except cm.NodeApiError:
        pass     # Sys.Audit on /nodes/<n>/disks missing: still show rootfs below
    total = sum(_num(d.get("size")) for d in disks) or _num(root.get("total"))
    return {"total": round(total / 1024 ** 4, 1), "used": round(_num(root.get("used")) / GB, 1),
            "available": round(_num(root.get("avail")) / GB, 1), "disk_count": len(disks),
            "disks": [{"name": (d.get("devpath") or "").rsplit("/", 1)[-1], "mountpoint": "",
                       "total": round(_num(d.get("size")) / GB, 1), "used": 0, "available": 0,
                       "usage_percent": 0} for d in disks],
            "remote": True, "node": node}, results


def _h_proxmox_storage(node, rec):
    res = cm.node_call(node, "GET", f"/nodes/{node}/storage", ttl=10)
    out = []
    for s in res.data or []:
        if not isinstance(s, dict):
            continue
        total, used = _num(s.get("total")), _num(s.get("used"))
        active = bool(s.get("active")) and s.get("enabled", 1) != 0
        out.append({"name": s.get("storage"), "type": s.get("type"),
                    "status": "active" if active else "inactive",
                    "total": round(total / GB, 2), "used": round(used / GB, 2),
                    "available": round(_num(s.get("avail")) / GB, 2),
                    "percent": round(used / total * 100, 2) if total else 0.0,
                    "shared": bool(s.get("shared")), "content": s.get("content")})
    return {"storage": out}, [res]


def _h_network_summary(node, rec):
    res = cm.node_call(node, "GET", f"/nodes/{node}/network", ttl=15)
    ifaces, phys, bridges = [], [], []
    for n in res.data or []:
        if not isinstance(n, dict):
            continue
        item = {"name": n.get("iface"), "status": "up" if n.get("active") else "down",
                "addresses": ([{"ip": n.get("address") or n.get("cidr", "").split("/")[0],
                                "netmask": n.get("netmask") or ""}] if (n.get("address") or n.get("cidr")) else [])}
        ifaces.append(item)
        if n.get("type") == "bridge":
            bridges.append(item)
        elif n.get("type") in ("eth", "bond"):
            phys.append(item)
    up = lambda xs: sum(1 for x in xs if x["status"] == "up")
    return {"interfaces": ifaces, "traffic": {"bytes_sent": 0, "bytes_recv": 0,
            "packets_sent": 0, "packets_recv": 0},
            "physical_active_count": up(phys), "physical_total_count": len(phys),
            "bridge_active_count": up(bridges), "bridge_total_count": len(bridges),
            "physical_interfaces": phys, "bridge_interfaces": bridges,
            "remote": True, "node": node}, [res]


def _h_node_metrics(node, rec):
    tf = request.args.get("timeframe", "week")
    if tf not in ("hour", "day", "week", "month", "year"):
        return _err(400, "bad_request", "Invalid timeframe. Must be one of: hour, day, week, month, year"), []
    res = cm.node_call(node, "GET", f"/nodes/{node}/rrddata", {"timeframe": tf, "cf": "AVERAGE"}, ttl=30)
    data = [p for p in (res.data or []) if isinstance(p, dict)]
    for p in data:
        if "arcsize" in p:
            p["zfsarc"] = p["arcsize"]

    def stats(key, scale):
        vals = [p[key] * scale for p in data if isinstance(p.get(key), (int, float)) and not isinstance(p.get(key), bool)]
        return {"avg": sum(vals) / len(vals), "max": max(vals), "min": min(vals)} if vals else None
    return {"node": node, "timeframe": tf, "data": data,
            "period_stats": {"cpu": stats("cpu", 100.0), "memory_used": stats("memused", 1 / GB)},
            "last_checked": int(time.time()), "cache_status": "stale" if res.stale else "fresh"}, [res]


CONTROL_ACTIONS = ("start", "stop", "shutdown", "reboot")


def _h_vm_control(node, rec, vmid):
    cfg = cm.load_config()
    if not cfg.get("allow_remote_control"):
        return _err(403, "remote_control_disabled",
                    "Power control of guests on other nodes is disabled in Cluster Management.", node=node), []
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    if action not in CONTROL_ACTIONS:
        return _err(400, "bad_request", "Invalid action"), []
    kind = _guest_on_node(node, vmid)
    if not kind:
        return _err(404, "not_found", f"VM/LXC {vmid} not found on node {node}", node=node), []
    res = cm.node_call(node, "POST", f"/nodes/{node}/{kind}/{vmid}/status/{action}")
    task = res.data if isinstance(res.data, str) else ""
    if not re.fullmatch(r"UPID:[\w.-]+:[0-9A-Fa-f]+:[0-9A-Fa-f]+:[0-9A-Fa-f]+:[\w]+:[\w]*:[\w.@!-]+:", task or ""):
        return _err(502, "node_error", "Control task was not confirmed by Proxmox", node=node), []
    cm._cache.pop((node, f"GET /nodes/{node}/{'qemu' if kind == 'qemu' else 'lxc'} []"), None)
    return {"success": True, "vmid": vmid, "action": action, "task": task, "node": node}, []


# (method, compiled path, handler, takes vmid)
REMOTE_ROUTES = [
    ("GET", re.compile(r"^/api/system$"), _h_system, False),
    ("GET", re.compile(r"^/api/system-info$"), _h_system_info, False),
    ("GET", re.compile(r"^/api/vms$"), _h_vms, False),
    ("GET", re.compile(r"^/api/vms/(\d+)$"), _h_vm_detail, True),
    ("POST", re.compile(r"^/api/vms/(\d+)/control$"), _h_vm_control, True),
    ("GET", re.compile(r"^/api/storage/summary$"), _h_storage_summary, False),
    ("GET", re.compile(r"^/api/proxmox-storage$"), _h_proxmox_storage, False),
    ("GET", re.compile(r"^/api/network/summary$"), _h_network_summary, False),
    ("GET", re.compile(r"^/api/node/metrics$"), _h_node_metrics, False),
]


# --------------------------------------------------------------------------
# before_request
# --------------------------------------------------------------------------

def requested_node():
    """(name or None, error response or None). Header and query must agree."""
    h = request.headers.get(NODE_HEADER)
    q = request.args.get(NODE_QUERY)
    for v in (h, q):
        if v is not None and not cm.valid_node_name(v):
            return None, _err(400, "bad_node", "Invalid node name")
    if h and q and h != q:
        return None, _err(400, "bad_node", "Conflicting node selectors")
    return (h or q or None), None


def _cached_guest_node(vmid):
    """Host node of a guest from cache only (no network on the local path)."""
    best = None
    for (node, key), (ts, data) in list(cm._cache.items()):
        if not (key.startswith(f"GET /nodes/{node}/qemu") or key.startswith(f"GET /nodes/{node}/lxc")):
            continue
        if isinstance(data, list) and any(isinstance(x, dict) and str(x.get("vmid")) == str(vmid) for x in data):
            if best is None or ts > best[0]:
                best = (ts, node)
    return best[1] if best else None


def _lookup_guest_node(vmid):
    """Cache miss for a restricted caller: ask the online nodes once (this also
    warms the cache). Fails closed to None only when the guest does not exist."""
    online = [n["name"] for n in cm.list_nodes() if n["online"]]
    return cm.find_guest_node(vmid, online)[0]


def enforce():
    path = request.path
    if request.method == "OPTIONS" or not path.startswith("/api/") or path.startswith(GLOBAL_PREFIXES):
        return None
    cfg = cm.load_config()
    node, bad = requested_node()
    if bad is not None:
        return bad
    local = cm.local_node_name()
    target = node or local
    is_remote = target != local
    # Fast path: untouched single-node behaviour.
    if not is_remote and not node_access.restricts_local(cfg) and not (
            node_access.guest_vmid(path) and _needs_guest_check(cfg)):
        g.pmx_node = local
        return None

    try:
        ident = node_access.identity_from_request()
    except node_access.AuthRequired:
        return _err(401, "Authentication required", "Please log in again")
    g.pmx_identity = ident

    if not cfg.get("enabled") and is_remote:
        return _err(404, "cluster_disabled", "Multi-node management is disabled")

    if is_remote:
        if not rbac.is_allowed(ident.scope, request.method, path):
            audit("deny_scope", ident, node=target, method=request.method, path=path)
            return _err(403, "Insufficient scope", f"This action requires a full_admin token (your token: {ident.scope})")
        rec = cm.get_node(target)
        if rec is None or not node_access.can_access(ident, target, cfg, local):
            # identical answer for "unknown" and "not allowed": no node enumeration
            audit("deny_node", ident, node=target, method=request.method, path=path,
                  known=rec is not None)
            return _err(403, "node_forbidden", "You do not have access to this node")
    elif not node_access.can_access(ident, local, cfg, local):
        audit("deny_node", ident, node=local, method=request.method, path=path)
        return _err(403, "node_forbidden", "You do not have access to this node")

    # Guest routes: the node that really hosts the guest must be allowed too.
    vmid = node_access.guest_vmid(path)
    if vmid is not None and not is_remote:
        host = _cached_guest_node(vmid) or _lookup_guest_node(vmid)
        if host and host != local and not node_access.can_access(ident, host, cfg, local):
            audit("deny_guest_node", ident, node=host, vmid=vmid, method=request.method, path=path)
            return _err(403, "node_forbidden", "You do not have access to the node hosting this guest")

    if not is_remote:
        g.pmx_node = local
        return None

    g.pmx_node = target
    mutating = request.method not in ("GET", "HEAD")
    ok, retry = (remote_write_limiter if mutating else remote_read_limiter).hit(ident.label)
    if not ok:
        r = _err(429, "rate_limited", "Too many requests", retry_after=retry)
        r.headers["Retry-After"] = str(retry)
        return r

    for method, rx, fn, with_vmid in REMOTE_ROUTES:
        m = rx.match(path)
        if method == request.method and m:
            return _run_remote(fn, target, ident, int(m.group(1)) if with_vmid else None, mutating)
    audit("unsupported", ident, node=target, method=request.method, path=path) if mutating else None
    return _err(501, "node_unsupported",
                "This function is not available for other nodes yet. Switch to the local node.", node=target)


def _needs_guest_check(cfg):
    """Guest routes need the host-node check whenever the cluster has more than
    one node: the local handlers act on ANY guest of the cluster through pvesh,
    so a user limited to the local node must not reach another node's guest by
    simply omitting the node selector."""
    return cm.node_count() > 1


def _run_remote(fn, node, ident, vmid, mutating):
    rec = cm.get_node(node)
    try:
        out = fn(node, rec) if vmid is None else fn(node, rec, vmid)
        if isinstance(out, Response):
            return out
        payload, results = out
        if isinstance(payload, Response):
            return payload
        resp = _attach(jsonify(payload), node, *results)
        if mutating:
            audit("remote_action", ident, node=node, method=request.method, path=request.path,
                  result="ok")
        return resp
    except cm.NodeApiError as exc:
        if mutating:
            audit("remote_action", ident, node=node, method=request.method, path=request.path,
                  result=exc.code)
        return node_error_response(node, exc)
    except Exception:
        return _err(502, "node_error", "Unexpected error while querying the node", node=node)


def init_app(app, local_node_name_fn=None, start_discovery=True):
    """Wire the gateway into the Flask app (called once by flask_server)."""
    from flask_cluster_routes import cluster_bp
    if local_node_name_fn:
        cm.set_local_node_name_provider(local_node_name_fn)
    app.register_blueprint(cluster_bp)
    app.before_request(enforce)
    if start_discovery:
        cm.start_discovery_loop()
