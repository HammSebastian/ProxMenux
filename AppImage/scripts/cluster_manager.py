"""
Central multi-node management for ProxMenux Monitor (Proxmox VE clusters).

One public ProxMenux instance manages every node of its cluster over the
internal network.  Nothing is installed on the other nodes: they are reached
through the official Proxmox VE REST API (``https://<node-ip>:8006/api2/json``)
with ONE least-privilege API token.  The node that runs ProxMenux talks to its
own API through ``pvesh`` (no token, no network hop) - exactly what the rest of
the Monitor already does.

Responsibilities of this module (no Flask code in here):

  * configuration (``cluster.json``) + Fernet-encrypted token secret
    (``cluster.key``, same scheme as ``oidc.key``), never returned to callers
  * strict TLS: verification against the cluster CA (default), a pinned SHA-256
    certificate fingerprint, or the system trust store.  There is deliberately
    NO "insecure" mode and no silent fallback.
  * only internal addresses (RFC1918 / ULA / loopback / CGNAT) are ever dialled
  * node registry fed by automatic discovery (``/cluster/status`` + ``/nodes``)
  * per-node calls with timeouts, GET retries, a failure circuit-breaker, a
    TTL cache and stale-on-error answers, plus parallel fan-out
  * error classification (offline / timeout / tls / auth / forbidden / ...) so
    one failing node never breaks another one
"""

import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import threading
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

try:
    import requests
    from requests.adapters import HTTPAdapter
    REQUESTS_AVAILABLE = True
except ImportError:  # pragma: no cover - runtime dependency
    requests = None
    HTTPAdapter = object
    REQUESTS_AVAILABLE = False

try:
    from cryptography.fernet import Fernet, InvalidToken
    CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    Fernet = InvalidToken = None
    CRYPTO_AVAILABLE = False

import auth_manager

log = logging.getLogger("proxmenux.cluster")

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

DEFAULT_CA_FILE = "/etc/pve/pve-root-ca.pem"
API_PORT = 8006
CONNECT_TIMEOUT = 3.05
READ_TIMEOUT = 8
GET_ATTEMPTS = 2                 # one retry for idempotent reads
BREAKER_THRESHOLD = 3            # consecutive failures before skipping a node
BREAKER_BASE_DELAY = 5           # seconds, doubles up to BREAKER_MAX_DELAY
BREAKER_MAX_DELAY = 60
STALE_MAX_AGE = 900              # serve cached data up to 15 min when a node fails
FANOUT_WORKERS = 8
MIN_INTERVAL, MAX_INTERVAL = 15, 3600

NODE_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
TOKEN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}@[A-Za-z0-9._-]{1,64}![A-Za-z0-9._-]{1,64}$")
FINGERPRINT_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:?){31}[0-9A-Fa-f]{2}$")
TLS_MODES = ("ca", "fingerprint", "system")

# Human readable text per error code (shown in the UI; never contains secrets).
ERROR_TEXT = {
    "offline": "Node offline",
    "timeout": "Node did not answer in time",
    "tls": "TLS certificate could not be verified",
    "auth": "API token rejected (invalid, expired or revoked)",
    "forbidden": "API token lacks the required permissions",
    "not_found": "Resource not found on the node",
    "not_configured": "No API token configured",
    "rejected_address": "Node address is not an internal address",
    "bad_response": "Unexpected answer from the node",
    "unknown_node": "Unknown node",
    "error": "Node API error",
}

DEFAULT_CONFIG = {
    "enabled": True,
    "discovery_enabled": True,
    "discovery_interval": 60,
    "tls_mode": "ca",
    "ca_file": DEFAULT_CA_FILE,
    "api_port": API_PORT,
    "token_id": "",
    "token_secret_enc": "",
    "fingerprints": {},          # node -> sha256 (tls_mode == "fingerprint")
    "node_addresses": {},        # node -> manual internal address override
    "allow_remote_control": False,
    "permissions": {
        "role_nodes": {"user": ["@local"], "readonly": ["@local"]},
        "user_rules": {},        # "<oidc user id>": {"allow": [...], "deny": [...]}
    },
}


class NodeApiError(Exception):
    """A node could not be queried. ``code`` is one of ERROR_TEXT's keys."""

    def __init__(self, code, detail="", status=None):
        super().__init__(code)
        self.code = code if code in ERROR_TEXT else "error"
        self.detail = (detail or "")[:200]
        self.status = status

    @property
    def message(self):
        return ERROR_TEXT.get(self.code, ERROR_TEXT["error"])


# --------------------------------------------------------------------------
# Paths, secrets, configuration
# --------------------------------------------------------------------------

def _dir():
    return auth_manager.CONFIG_DIR


def config_path():
    return _dir() / "cluster.json"


def key_path():
    return _dir() / "cluster.key"


def state_path():
    return _dir() / "cluster-state.json"


def _write_private(path, data: bytes):
    """Atomic write, 0600 from the first byte."""
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


_key_lock = threading.Lock()


def _fernet():
    if not CRYPTO_AVAILABLE:
        raise NodeApiError("error", "cryptography missing")
    with _key_lock:
        kp = key_path()
        if kp.exists():
            key = kp.read_bytes().strip()
        else:
            key = Fernet.generate_key()
            _write_private(kp, key)
    return Fernet(key)


def encrypt_secret(plain):
    return _fernet().encrypt(plain.encode("utf-8")).decode("ascii") if plain else ""


def decrypt_secret(token):
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        raise NodeApiError("auth", "stored token secret cannot be decrypted")


_cfg_cache = {"path": None, "mtime": None, "cfg": None}
_cfg_lock = threading.Lock()


def _merge_defaults(stored):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if isinstance(stored, dict):
        for k in DEFAULT_CONFIG:
            if k in stored:
                cfg[k] = stored[k]
    return cfg


def load_config():
    """Config with defaults applied. Cached by file mtime (read on every request)."""
    path = config_path()
    try:
        mtime = path.stat().st_mtime_ns
    except OSError:
        mtime = None
    with _cfg_lock:
        if _cfg_cache["path"] == str(path) and _cfg_cache["mtime"] == mtime and _cfg_cache["cfg"] is not None:
            return json.loads(json.dumps(_cfg_cache["cfg"]))
        stored = None
        if mtime is not None:
            try:
                with open(path, "r") as fh:
                    stored = json.load(fh)
            except Exception as exc:
                log.warning("cluster: cannot read config (%s); using defaults", type(exc).__name__)
        cfg = _merge_defaults(stored)
        _cfg_cache.update(path=str(path), mtime=mtime, cfg=cfg)
        return json.loads(json.dumps(cfg))


def save_config(cfg):
    clean = _merge_defaults(cfg)
    _write_private(config_path(), json.dumps(clean, indent=2).encode("utf-8"))
    with _cfg_lock:
        _cfg_cache["cfg"] = None
    _breakers.clear()


def public_config(cfg=None):
    """Config safe for the browser: the token secret is replaced by a flag."""
    cfg = cfg or load_config()
    out = {k: v for k, v in cfg.items() if k != "token_secret_enc"}
    out["token_secret_set"] = bool(cfg.get("token_secret_enc"))
    return out


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------

def valid_node_name(name):
    return isinstance(name, str) and bool(NODE_RE.match(name))


def is_internal_ip(ip):
    """True for private / loopback / CGNAT / ULA addresses, never for public,
    link-local (cloud metadata), multicast or unspecified ones."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return False
    if addr.is_loopback or (addr.is_private and not addr.is_reserved) or \
            (addr.version == 6 and addr in ipaddress.ip_network("fc00::/7")):
        return True
    if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
        return True
    return False


def resolve_internal(host):
    """Resolve `host` and require EVERY address to be internal. Returns the
    first address. Raises NodeApiError('rejected_address') otherwise."""
    if not host or not isinstance(host, str) or len(host) > 253:
        raise NodeApiError("rejected_address", "empty address")
    try:
        ipaddress.ip_address(host)
        ips = [host]
    except ValueError:
        try:
            ips = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
        except OSError:
            raise NodeApiError("offline", "address does not resolve")
    if not ips or not all(is_internal_ip(ip) for ip in ips):
        raise NodeApiError("rejected_address", "not an internal address")
    return ips[0]


def validate_acl_entries(entries):
    """Normalise a list of node names / '*' / '@local'. Returns (list, error)."""
    if not isinstance(entries, list) or len(entries) > 256:
        return None, "must be a list"
    out = []
    for e in entries:
        if not isinstance(e, str) or not (e in ("*", "@local") or valid_node_name(e)):
            return None, "invalid node entry"
        if e not in out:
            out.append(e)
    return out, None


def validate_permissions(perms):
    if not isinstance(perms, dict):
        return None, "permissions must be an object"
    clean = {"role_nodes": {}, "user_rules": {}}
    rn = perms.get("role_nodes", {})
    if not isinstance(rn, dict):
        return None, "role_nodes must be an object"
    for role in ("user", "readonly"):
        lst, err = validate_acl_entries(rn.get(role, []))
        if err:
            return None, f"role_nodes.{role}: {err}"
        clean["role_nodes"][role] = lst
    ur = perms.get("user_rules", {})
    if not isinstance(ur, dict) or len(ur) > 1000:
        return None, "user_rules must be an object"
    for uid, rule in ur.items():
        if not (isinstance(uid, str) and uid.isdigit() and isinstance(rule, dict)):
            return None, "invalid user rule"
        allow, e1 = validate_acl_entries(rule.get("allow", []))
        deny, e2 = validate_acl_entries(rule.get("deny", []))
        if e1 or e2:
            return None, f"user_rules.{uid}: {e1 or e2}"
        if allow or deny:
            clean["user_rules"][uid] = {"allow": allow, "deny": deny}
    return clean, None


def validate_settings_update(data, cfg):
    """Apply a partial settings update onto `cfg`. Returns (cfg, error)."""
    if not isinstance(data, dict):
        return None, "JSON object expected"
    for key in ("enabled", "discovery_enabled", "allow_remote_control"):
        if key in data:
            if not isinstance(data[key], bool):
                return None, f"'{key}' must be true or false"
            cfg[key] = data[key]
    if "discovery_interval" in data:
        v = data["discovery_interval"]
        if isinstance(v, bool) or not isinstance(v, int) or not MIN_INTERVAL <= v <= MAX_INTERVAL:
            return None, f"'discovery_interval' must be {MIN_INTERVAL}-{MAX_INTERVAL} seconds"
        cfg["discovery_interval"] = v
    if "tls_mode" in data:
        if data["tls_mode"] not in TLS_MODES:
            return None, "'tls_mode' must be one of: " + ", ".join(TLS_MODES)
        cfg["tls_mode"] = data["tls_mode"]
    if "ca_file" in data:
        v = data["ca_file"]
        if not isinstance(v, str) or not v.startswith("/") or len(v) > 512 or ".." in v.split("/"):
            return None, "'ca_file' must be an absolute path"
        cfg["ca_file"] = v
    if "api_port" in data:
        v = data["api_port"]
        if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= 65535:
            return None, "'api_port' must be a TCP port"
        cfg["api_port"] = v
    if "token_id" in data:
        v = data["token_id"]
        if not isinstance(v, str) or (v and not TOKEN_ID_RE.match(v)):
            return None, "'token_id' must look like user@realm!tokenname"
        cfg["token_id"] = v
        if not v:
            cfg["token_secret_enc"] = ""
    if "token_secret" in data:
        v = data["token_secret"]
        if not isinstance(v, str) or len(v) > 256:
            return None, "'token_secret' must be a string"
        if v:   # empty == keep the stored secret
            cfg["token_secret_enc"] = encrypt_secret(v.strip())
    if "fingerprints" in data:
        fp = data["fingerprints"]
        if not isinstance(fp, dict) or len(fp) > 256:
            return None, "'fingerprints' must be an object"
        clean = {}
        for n, v in fp.items():
            if not valid_node_name(n) or not isinstance(v, str) or not FINGERPRINT_RE.match(v):
                return None, "invalid fingerprint entry"
            clean[n] = v.replace(":", "").lower()
        cfg["fingerprints"] = clean
    if "node_addresses" in data:
        na = data["node_addresses"]
        if not isinstance(na, dict) or len(na) > 256:
            return None, "'node_addresses' must be an object"
        clean = {}
        for n, v in na.items():
            if not valid_node_name(n) or not isinstance(v, str):
                return None, "invalid node address entry"
            try:
                resolve_internal(v.strip())
            except NodeApiError as exc:
                return None, f"address of {n}: {exc.message}"
            clean[n] = v.strip()
        cfg["node_addresses"] = clean
    if "permissions" in data:
        perms, err = validate_permissions(data["permissions"])
        if err:
            return None, err
        cfg["permissions"] = perms
    if cfg["tls_mode"] == "ca" and not cfg["ca_file"]:
        return None, "'ca_file' is required for tls_mode 'ca'"
    return cfg, None


# --------------------------------------------------------------------------
# Transports
# --------------------------------------------------------------------------

def _default_local_runner(method, path, params=None):
    """Run `pvesh` on THIS node (it talks to the local pveproxy/pmxcfs)."""
    verb = {"GET": "get", "POST": "create", "PUT": "set", "DELETE": "delete"}[method]
    cmd = ["pvesh", verb, path, "--output-format", "json"]
    for k, v in (params or {}).items():
        cmd += [f"--{k}", str(v)]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
    except subprocess.TimeoutExpired:
        raise NodeApiError("timeout", "pvesh timed out")
    except (OSError, subprocess.SubprocessError) as exc:
        raise NodeApiError("error", f"pvesh unavailable: {type(exc).__name__}")
    if res.returncode != 0:
        err = (res.stderr or res.stdout or "").lower()
        if "permission denied" in err or "401" in err:
            raise NodeApiError("forbidden", "pvesh permission denied")
        if "no such" in err or "does not exist" in err or "not found" in err:
            raise NodeApiError("not_found", "pvesh: not found")
        raise NodeApiError("error", "pvesh failed")
    out = (res.stdout or "").strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except ValueError:
        # task creation returns the bare UPID string
        return out.strip('"')


_local_runner = _default_local_runner


def set_local_runner(fn):
    """Test hook / alternative local transport."""
    global _local_runner
    _local_runner = fn or _default_local_runner


class _PinnedAdapter(HTTPAdapter):
    """Accept exactly one certificate (SHA-256 fingerprint); hostname is not
    checked because the pin itself identifies the peer."""

    def __init__(self, fingerprint, **kw):
        self._fp = fingerprint
        super().__init__(**kw)

    def init_poolmanager(self, *a, **kw):
        kw["assert_fingerprint"] = self._fp
        kw["assert_hostname"] = False
        super().init_poolmanager(*a, **kw)


def _verify_settings(cfg, node_name):
    """-> (verify_arg, pin_fingerprint or None). Raises tls NodeApiError when the
    selected mode lacks its material - never degrades to an unverified call."""
    mode = cfg.get("tls_mode", "ca")
    if mode == "fingerprint":
        fp = (cfg.get("fingerprints") or {}).get(node_name)
        if not fp:
            raise NodeApiError("tls", "no pinned fingerprint for this node")
        return False, fp.replace(":", "").lower()
    if mode == "system":
        return True, None
    ca = cfg.get("ca_file") or ""
    if not os.path.isfile(ca):
        raise NodeApiError("tls", "CA file not found")
    return ca, None


def _classify_request_error(exc):
    if isinstance(exc, requests.exceptions.SSLError):
        return NodeApiError("tls", type(exc).__name__)
    if isinstance(exc, (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout)):
        return NodeApiError("timeout", type(exc).__name__)
    # urllib3 raises MaxRetryError(SSLError) wrapped in ConnectionError for pinned mismatch
    text = str(exc).lower()
    if "certificate" in text or "fingerprint" in text or "ssl" in text:
        return NodeApiError("tls", type(exc).__name__)
    if isinstance(exc, requests.exceptions.ConnectionError):
        return NodeApiError("offline", type(exc).__name__)
    return NodeApiError("error", type(exc).__name__)


def http_request(address, method, path, params=None, cfg=None, node_name=None):
    """One call against the PVE API of a remote node with a verified TLS channel."""
    if not REQUESTS_AVAILABLE:
        raise NodeApiError("error", "python 'requests' missing")
    cfg = cfg or load_config()
    if not cfg.get("token_id") or not cfg.get("token_secret_enc"):
        raise NodeApiError("not_configured")
    ip = resolve_internal(address)
    verify, pin = _verify_settings(cfg, node_name)
    secret = decrypt_secret(cfg["token_secret_enc"])
    host = f"[{ip}]" if ":" in ip else ip
    url = f"https://{host}:{int(cfg.get('api_port') or API_PORT)}/api2/json{path}"
    headers = {"Authorization": f"PVEAPIToken={cfg['token_id']}={secret}",
               "Accept": "application/json"}
    session = requests.Session()
    session.trust_env = False        # never route node traffic through env proxies
    if pin:
        session.mount("https://", _PinnedAdapter(pin))
    kwargs = dict(headers=headers, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                  verify=verify, allow_redirects=False)
    if method == "GET":
        kwargs["params"] = params
    else:
        kwargs["data"] = params
    try:
        with warnings.catch_warnings():
            if pin:   # the pin replaces CA validation; urllib3 warns about verify=False
                warnings.simplefilter("ignore")
            resp = session.request(method, url, **kwargs)
    except requests.exceptions.RequestException as exc:
        raise _classify_request_error(exc)
    finally:
        session.close()
    if resp.status_code == 401:
        raise NodeApiError("auth", "HTTP 401", 401)
    if resp.status_code == 403:
        raise NodeApiError("forbidden", "HTTP 403", 403)
    if resp.status_code == 404:
        raise NodeApiError("not_found", "HTTP 404", 404)
    if resp.status_code == 595:      # PVE proxy: target node unreachable
        raise NodeApiError("offline", "HTTP 595", 595)
    if resp.status_code >= 500 or resp.status_code in (301, 302, 307, 308):
        raise NodeApiError("error", f"HTTP {resp.status_code}", resp.status_code)
    if resp.status_code >= 400:
        raise NodeApiError("error", f"HTTP {resp.status_code}", resp.status_code)
    try:
        body = resp.json()
        return body.get("data") if isinstance(body, dict) else None
    except ValueError:
        raise NodeApiError("bad_response", "not JSON")


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

_lock = threading.RLock()
_nodes = {}                       # name -> record
_cluster = {"name": None, "quorate": None, "version": None, "standalone": True}
_discovery = {"running": False, "last_sync": None, "last_attempt": None,
              "last_error": None, "last_duration_ms": None, "count": 0}
_local_name_fn = lambda: socket.gethostname().split(".", 1)[0].lower()
_cache = {}                       # (node, key) -> (ts, data)
_breakers = {}                    # node -> {"fails": n, "retry_at": ts}
_discovery_lock = threading.Lock()
_loaded_state = {"done": False}


def set_local_node_name_provider(fn):
    global _local_name_fn
    _local_name_fn = fn


def local_node_name():
    return _local_name_fn()


def _now():
    return time.time()


def _iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None


def _new_record(name):
    return {"name": name, "node_id": None, "ip": None, "local": False, "online": False,
            "cluster": None, "pve_version": None, "api_status": "unknown", "api_error": None,
            "cpu": None, "maxcpu": None, "mem": None, "maxmem": None, "disk": None,
            "maxdisk": None, "uptime": None, "ssl_fingerprint": None,
            "last_seen": None, "last_checked": None}


def _load_state_once():
    if _loaded_state["done"]:
        return
    _loaded_state["done"] = True
    try:
        with open(state_path(), "r") as fh:
            st = json.load(fh)
        with _lock:
            if not _nodes:
                for rec in st.get("nodes", []):
                    if valid_node_name(rec.get("name")):
                        r = _new_record(rec["name"])
                        r.update({k: rec.get(k) for k in r if k in rec})
                        r["online"] = False          # unverified after a restart
                        r["api_status"] = "unknown"
                        _nodes[r["name"]] = r
                _cluster.update(st.get("cluster") or {})
                _discovery["last_sync"] = st.get("last_sync")
    except Exception:
        pass


def _save_state():
    try:
        with _lock:
            data = {"nodes": list(_nodes.values()), "cluster": dict(_cluster),
                    "last_sync": _discovery["last_sync"]}
        _write_private(state_path(), json.dumps(data).encode("utf-8"))
    except Exception as exc:
        log.warning("cluster: cannot persist state (%s)", type(exc).__name__)


def reset_runtime():
    """Forget registry, caches and breakers (tests / config reset)."""
    with _lock:
        _nodes.clear()
        _cache.clear()
        _breakers.clear()
        _cluster.update({"name": None, "quorate": None, "version": None, "standalone": True})
        _discovery.update({"running": False, "last_sync": None, "last_attempt": None,
                           "last_error": None, "last_duration_ms": None, "count": 0})
        _loaded_state["done"] = True


def get_node(name):
    _load_state_once()
    with _lock:
        rec = _nodes.get(name) if isinstance(name, str) else None
        return dict(rec) if rec else None


def node_count():
    _load_state_once()
    with _lock:
        return len(_nodes)


def list_nodes():
    _load_state_once()
    with _lock:
        recs = [dict(r) for r in _nodes.values()]
    recs.sort(key=lambda r: (not r["local"], r["name"]))
    for r in recs:
        r["status"] = node_status(r)
    return recs


def node_status(rec):
    """online | offline | degraded (reachable cluster member whose API fails)."""
    if not rec.get("online"):
        return "offline"
    if rec.get("local") or rec.get("api_status") in ("ok", "unknown"):
        return "online"
    if rec.get("api_status") in ("offline", "timeout"):
        return "offline"
    return "degraded"


def cluster_info():
    with _lock:
        nodes = list(_nodes.values())
        info = dict(_cluster)
        disc = dict(_discovery)
    online = sum(1 for n in nodes if node_status(n) == "online")
    info.update(node_count=len(nodes), online=online, offline=len(nodes) - online)
    cfg = load_config()
    disc.update(enabled=bool(cfg["discovery_enabled"]), interval=cfg["discovery_interval"],
                last_sync_iso=_iso(disc.get("last_sync")),
                last_attempt_iso=_iso(disc.get("last_attempt")))
    return info, disc


def _set_api_state(name, code):
    with _lock:
        rec = _nodes.get(name)
        if rec is not None and not rec["local"]:
            rec["api_status"] = code
            rec["api_error"] = None if code == "ok" else ERROR_TEXT.get(code, code)
            rec["last_checked"] = _now()


# --------------------------------------------------------------------------
# Node calls: timeouts, retries, breaker, cache, stale-on-error
# --------------------------------------------------------------------------

def _node_address(cfg, rec):
    return (cfg.get("node_addresses") or {}).get(rec["name"]) or rec.get("ip")


def _raw_call(rec, method, path, params, cfg):
    if rec["local"]:
        return _local_runner(method, path, params)
    addr = _node_address(cfg, rec)
    if not addr:
        raise NodeApiError("offline", "no address known")
    last = None
    attempts = GET_ATTEMPTS if method == "GET" else 1
    for i in range(attempts):
        try:
            return http_request(addr, method, path, params, cfg, rec["name"])
        except NodeApiError as exc:
            last = exc
            # only transient problems are worth a retry
            if exc.code not in ("timeout", "offline", "error") or i + 1 >= attempts:
                break
            time.sleep(0.15 * (i + 1))
    raise last


class NodeResult:
    __slots__ = ("data", "stale", "cached_at")

    def __init__(self, data, stale=False, cached_at=None):
        self.data, self.stale, self.cached_at = data, stale, cached_at


def _breaker_open(name):
    b = _breakers.get(name)
    return bool(b and b["fails"] >= BREAKER_THRESHOLD and _now() < b["retry_at"])


def _breaker_record(name, ok):
    if ok:
        _breakers.pop(name, None)
        return
    b = _breakers.setdefault(name, {"fails": 0, "retry_at": 0})
    b["fails"] += 1
    if b["fails"] >= BREAKER_THRESHOLD:
        delay = min(BREAKER_MAX_DELAY, BREAKER_BASE_DELAY * 2 ** (b["fails"] - BREAKER_THRESHOLD))
        b["retry_at"] = _now() + delay


def node_call(name, method, path, params=None, ttl=0, cache_key=None, allow_stale=True):
    """Query one node. Returns NodeResult; raises NodeApiError.

    * the node must be in the registry (names from clients are never used to
      build URLs; the address always comes from the registry/config)
    * `ttl` > 0 enables the cache for GETs; on failure a cached answer younger
      than STALE_MAX_AGE is returned with stale=True instead of the error
    """
    method = method.upper()
    rec = get_node(name)
    if rec is None:
        raise NodeApiError("unknown_node")
    cfg = load_config()
    key = (name, cache_key or f"{method} {path} {sorted((params or {}).items())}")
    cacheable = method == "GET"
    now = _now()
    if cacheable and ttl > 0:
        hit = _cache.get(key)
        if hit and now - hit[0] < ttl:
            return NodeResult(hit[1], False, hit[0])
    try:
        if not rec["local"] and _breaker_open(name):
            raise NodeApiError("offline", "circuit open")
        if not rec["online"] and not rec["local"]:
            raise NodeApiError("offline", "node is not a quorum member")
        data = _raw_call(rec, method, path, params, cfg)
    except NodeApiError as exc:
        # Only connectivity failures trip the breaker: a missing/rejected token
        # or certificate must keep its own error instead of becoming "offline".
        if (not rec["local"] and exc.detail != "circuit open"
                and exc.code in ("offline", "timeout", "error")):
            _breaker_record(name, False)
        _set_api_state(name, exc.code)
        hit = _cache.get(key) if cacheable else None
        if allow_stale and hit and now - hit[0] < STALE_MAX_AGE:
            return NodeResult(hit[1], True, hit[0])
        raise
    _breaker_record(name, True)
    _set_api_state(name, "ok")
    if cacheable:
        _cache[key] = (now, data)
        if len(_cache) > 2000:
            for k in sorted(_cache, key=lambda k: _cache[k][0])[:500]:
                _cache.pop(k, None)
    return NodeResult(data, False, now)


def fan_out(names, fn, timeout=20):
    """Run fn(name) for every node in parallel. Returns {name: (ok, value_or_NodeApiError)}.
    One node's failure/timeout never affects another."""
    results = {}
    names = list(names)
    if not names:
        return results
    pool = ThreadPoolExecutor(max_workers=min(FANOUT_WORKERS, len(names)))
    try:
        futures = {pool.submit(fn, n): n for n in names}
        try:
            for fut in as_completed(futures, timeout=timeout):
                n = futures[fut]
                try:
                    results[n] = (True, fut.result())
                except NodeApiError as exc:
                    results[n] = (False, exc)
                except Exception as exc:
                    results[n] = (False, NodeApiError("error", type(exc).__name__))
        except Exception:      # as_completed timeout
            pass
        for fut, n in futures.items():
            if n not in results:
                results[n] = (False, NodeApiError("timeout", "fan-out deadline"))
    finally:
        pool.shutdown(wait=False)
    return results


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

def _probe_node(rec, cfg):
    """API reachability + version of one remote node (isolated, never raises
    anything but NodeApiError)."""
    data = _raw_call(rec, "GET", "/version", None, cfg)
    return (data or {}).get("version") if isinstance(data, dict) else None


def discover(force=False):
    """Refresh the node registry from the cluster API. Safe to call from any
    thread; concurrent calls collapse into one. Returns the discovery state."""
    _load_state_once()
    if not _discovery_lock.acquire(blocking=False):
        return {"ok": True, "skipped": "already running"}
    started = _now()
    try:
        with _lock:
            _discovery.update(running=True, last_attempt=started)
        cfg = load_config()
        if not cfg["enabled"] and not force:
            return {"ok": False, "skipped": "disabled"}
        try:
            status = _local_runner("GET", "/cluster/status", None)
            try:
                resources = _local_runner("GET", "/nodes", None)
            except NodeApiError:
                resources = []
        except NodeApiError as exc:
            with _lock:
                _discovery["last_error"] = exc.message + (f" ({exc.detail})" if exc.detail else "")
            return {"ok": False, "error": exc.message}
        if not isinstance(status, list):
            with _lock:
                _discovery["last_error"] = ERROR_TEXT["bad_response"]
            return {"ok": False, "error": ERROR_TEXT["bad_response"]}

        cluster_entry = next((e for e in status if isinstance(e, dict) and e.get("type") == "cluster"), None)
        node_entries = [e for e in status if isinstance(e, dict) and e.get("type") == "node"
                        and valid_node_name(e.get("name"))]
        res_by_name = {r.get("node"): r for r in (resources or []) if isinstance(r, dict)}
        local = local_node_name()
        now = _now()
        fresh = {}
        with _lock:
            previous = {k: dict(v) for k, v in _nodes.items()}
        for e in node_entries:
            name = e["name"]
            rec = _new_record(name)
            old = previous.get(name)
            if old:
                rec.update({k: old[k] for k in ("pve_version", "api_status", "api_error",
                                                "last_seen", "last_checked")})
            r = res_by_name.get(name, {})
            rec.update(
                node_id=e.get("nodeid"), ip=e.get("ip") or (old or {}).get("ip"),
                local=bool(e.get("local")) or name == local,
                online=bool(e.get("online", 1)), cluster=(cluster_entry or {}).get("name"),
                cpu=r.get("cpu"), maxcpu=r.get("maxcpu"), mem=r.get("mem"), maxmem=r.get("maxmem"),
                disk=r.get("disk"), maxdisk=r.get("maxdisk"), uptime=r.get("uptime"),
                ssl_fingerprint=r.get("ssl_fingerprint"))
            if rec["online"]:
                rec["last_seen"] = now
            fresh[name] = rec

        # Probe every online node's API in parallel (local = pvesh /version).
        def probe(name):
            rec = fresh[name]
            return _probe_node(rec, cfg)

        to_probe = [n for n, r in fresh.items() if r["online"]]
        probed = fan_out(to_probe, probe, timeout=CONNECT_TIMEOUT + READ_TIMEOUT * GET_ATTEMPTS + 5)
        for name, (ok, val) in probed.items():
            rec = fresh[name]
            rec["last_checked"] = now
            if ok:
                rec["api_status"], rec["api_error"] = "ok", None
                rec["pve_version"] = val or rec["pve_version"]
            else:
                rec["api_status"], rec["api_error"] = val.code, val.message
        for name, rec in fresh.items():
            if not rec["online"]:
                rec["api_status"], rec["api_error"] = "offline", ERROR_TEXT["offline"]

        with _lock:
            gone = set(_nodes) - set(fresh)
            _nodes.clear()
            _nodes.update(fresh)
            for g in gone:
                _breakers.pop(g, None)
            for k in [k for k in _cache if k[0] in gone]:
                _cache.pop(k, None)
            _cluster.update(name=(cluster_entry or {}).get("name"),
                            quorate=bool(cluster_entry.get("quorate")) if cluster_entry else True,
                            version=(cluster_entry or {}).get("version"),
                            standalone=cluster_entry is None)
            _discovery.update(last_sync=now, last_error=None, count=len(fresh),
                              last_duration_ms=int((_now() - started) * 1000))
        _save_state()
        return {"ok": True, "nodes": len(fresh), "removed": sorted(gone)}
    finally:
        with _lock:
            _discovery["running"] = False
        _discovery_lock.release()


_thread = {"t": None, "stop": threading.Event()}


def start_discovery_loop():
    """Background refresh. Interval/enable flag are re-read every cycle."""
    if _thread["t"] and _thread["t"].is_alive():
        return

    def loop():
        _thread["stop"].wait(2)
        while not _thread["stop"].is_set():
            try:
                cfg = load_config()
                if cfg["enabled"] and cfg["discovery_enabled"]:
                    discover()
                    # keep the guest->node map warm: the gateway uses it to
                    # authorise guest routes without any network round trip
                    list_guests([n["name"] for n in list_nodes() if n["online"]])
                wait = cfg["discovery_interval"]
            except Exception as exc:       # the loop must never die
                log.warning("cluster discovery loop error: %s", type(exc).__name__)
                wait = 60
            _thread["stop"].wait(wait)

    _thread["stop"].clear()
    t = threading.Thread(target=loop, name="cluster-discovery", daemon=True)
    _thread["t"] = t
    t.start()


def stop_discovery_loop():
    _thread["stop"].set()


# --------------------------------------------------------------------------
# Connection test
# --------------------------------------------------------------------------

def test_node(name):
    """Step-by-step check of one node: address, TLS+token (version), privileges."""
    rec = get_node(name)
    if rec is None:
        return {"node": name, "ok": False, "steps": [], "error": ERROR_TEXT["unknown_node"]}
    cfg = load_config()
    steps = []

    def step(label, fn):
        t0 = _now()
        try:
            val = fn()
            steps.append({"step": label, "ok": True, "ms": int((_now() - t0) * 1000)})
            return val
        except NodeApiError as exc:
            steps.append({"step": label, "ok": False, "code": exc.code, "message": exc.message,
                          "ms": int((_now() - t0) * 1000)})
            return None

    if rec["local"]:
        ver = step("local_api", lambda: _local_runner("GET", "/version", None))
        return {"node": name, "ok": bool(ver), "local": True, "steps": steps,
                "version": (ver or {}).get("version") if isinstance(ver, dict) else None}
    if not rec["online"]:
        steps.append({"step": "membership", "ok": False, "code": "offline", "message": ERROR_TEXT["offline"]})
        return {"node": name, "ok": False, "steps": steps}
    addr = _node_address(cfg, rec)
    if step("address", lambda: resolve_internal(addr)) is None:
        return {"node": name, "ok": False, "steps": steps}
    ver = step("tls_and_token", lambda: _raw_call(rec, "GET", "/version", None, cfg))
    if ver is None:
        return {"node": name, "ok": False, "steps": steps}
    perms = step("privileges", lambda: _raw_call(rec, "GET", "/access/permissions", None, cfg))
    privs = set()
    if isinstance(perms, dict):
        for path_perms in perms.values():
            if isinstance(path_perms, dict):
                privs.update(path_perms)
    missing = [p for p in ("Sys.Audit", "VM.Audit") if privs and p not in privs]
    if perms is not None and missing:
        steps.append({"step": "required_privileges", "ok": False, "code": "forbidden",
                      "message": "Missing: " + ", ".join(missing)})
    elif perms is not None:
        steps.append({"step": "required_privileges", "ok": True})
    ok = all(s["ok"] for s in steps)
    _set_api_state(name, "ok" if ok else next((s["code"] for s in steps if not s["ok"]), "error"))
    return {"node": name, "ok": ok, "steps": steps,
            "version": (ver or {}).get("version") if isinstance(ver, dict) else None,
            "can_control": "VM.PowerMgmt" in privs}


def test_all():
    names = [n["name"] for n in list_nodes()]
    out = fan_out(names, test_node, timeout=40)
    return [v if ok else {"node": n, "ok": False, "steps": [], "error": v.message}
            for n, (ok, v) in sorted(out.items())]


# --------------------------------------------------------------------------
# Guests across the cluster
# --------------------------------------------------------------------------

GUEST_TTL = 8


def _guests_of(name):
    out = []
    stale = False
    cached_at = None
    for kind in ("qemu", "lxc"):
        res = node_call(name, "GET", f"/nodes/{name}/{'qemu' if kind == 'qemu' else 'lxc'}", ttl=GUEST_TTL)
        stale = stale or res.stale
        cached_at = min(cached_at, res.cached_at) if cached_at and res.cached_at else (res.cached_at or cached_at)
        for g in res.data or []:
            if not isinstance(g, dict) or g.get("vmid") is None:
                continue
            item = dict(g)
            item.update(type=kind, node=name)
            item.setdefault("name", f"VM-{g.get('vmid')}")
            item["stale"] = res.stale
            out.append(item)
    return {"guests": out, "stale": stale, "cached_at": cached_at}


def list_guests(node_names):
    """Guests of the given nodes. -> (guests, node_errors, stale_nodes).
    Nodes are queried in parallel and fail independently."""
    res = fan_out(node_names, _guests_of)
    guests, errors, stale = [], {}, {}
    for name, (ok, val) in res.items():
        if ok:
            guests.extend(val["guests"])
            if val["stale"]:
                stale[name] = val["cached_at"]
        else:
            errors[name] = {"code": val.code, "message": val.message}
    guests.sort(key=lambda g: (g["node"], int(g["vmid"])))
    return guests, errors, stale


def find_guest_node(vmid, node_names=None):
    """Which node hosts `vmid`? Looks at the cache first, then asks the nodes.
    Returns (node, type) or (None, None)."""
    names = node_names or [n["name"] for n in list_nodes()]
    guests, _, _ = list_guests(names)
    for g in guests:
        if int(g["vmid"]) == int(vmid):
            return g["node"], g["type"]
    return None, None
