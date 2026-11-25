"""
Multi-node management tests.

Runs the REAL cluster_manager / node_access / cluster_gateway / Flask routes.
The PVE API of the "other nodes" is played by real local HTTPS servers
(127.0.0.2-4, certificates generated on the fly) so TLS verification, token
handling, timeouts and offline behaviour are exercised for real; the local
``pvesh`` is replaced by a fake runner.  HOME/config dir is a temp directory.

    python3 -m unittest tests.test_cluster_management -v
Requires: flask, PyJWT, cryptography, requests.
"""
import datetime
import hashlib
import http.server
import json
import logging
import logging.handlers  # noqa: F401
import os
import shutil
import ssl
import stat
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "AppImage" / "scripts"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from flask import Flask, jsonify  # noqa: E402

with mock.patch.object(logging, "FileHandler", lambda *a, **k: logging.NullHandler()):
    import auth_manager  # noqa: E402
import cluster_gateway as gw  # noqa: E402
import cluster_manager as cm  # noqa: E402
import jwt_middleware  # noqa: E402
import node_access  # noqa: E402
import rbac  # noqa: E402
from flask_cluster_routes import cluster_bp  # noqa: E402

TOKEN_ID = "proxmenux@pve!monitor"
SECRET = "11111111-2222-3333-4444-555555555555"
NODE_IPS = {"pve": "127.0.0.1", "pve-1": "127.0.0.2", "pve-2": "127.0.0.3", "pve-3": "127.0.0.4"}


# ------------------------------------------------------------------ PKI ---

def _make_ca(cn="Test PVE CA"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False),
                           critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def _make_leaf(ca_key, ca_cert):
    import ipaddress
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pve-node")]))
            .issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(f"127.0.0.{i}")) for i in range(1, 6)]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


def _pem_cert(c):
    return c.public_bytes(serialization.Encoding.PEM)


def _pem_key(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                           serialization.NoEncryption())


class Pki:
    """One CA + one leaf shared by the whole module (RSA keygen is slow)."""
    ca_key, ca_cert = _make_ca()
    other_key, other_cert = _make_ca("Unrelated CA")
    leaf_key, leaf_cert = _make_leaf(ca_key, ca_cert)
    fingerprint = hashlib.sha256(leaf_cert.public_bytes(serialization.Encoding.DER)).hexdigest()


# ------------------------------------------------------- fake PVE nodes ---

class FakeNode:
    """A PVE API endpoint over real TLS."""

    def __init__(self, name, ip, port, workdir):
        self.name, self.ip, self.port = name, ip, port
        self.data = {}
        self.delay = 0.0
        self.token = (TOKEN_ID, SECRET)
        self.deny_prefixes = ()
        self.hits = 0
        self.posts = []
        self._lock = threading.Lock()
        cert, key = Path(workdir) / f"{name}.crt", Path(workdir) / f"{name}.key"
        cert.write_bytes(_pem_cert(Pki.leaf_cert))
        key.write_bytes(_pem_key(Pki.leaf_key))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert), str(key))
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _serve(self, method):
                with outer._lock:
                    outer.hits += 1
                if outer.delay:
                    time.sleep(outer.delay)
                want = f"PVEAPIToken={outer.token[0]}={outer.token[1]}"
                if self.headers.get("Authorization") != want:
                    return self._send(401, {"data": None})
                path = self.path.split("?", 1)[0]
                if path.startswith("/api2/json"):
                    path = path[len("/api2/json"):]
                if any(path.startswith(p) for p in outer.deny_prefixes):
                    return self._send(403, {"data": None})
                if method == "POST":
                    n = int(self.headers.get("Content-Length") or 0)
                    outer.posts.append((path, self.rfile.read(n).decode()))
                if (method, path) in outer.data:
                    return self._send(200, {"data": outer.data[(method, path)]})
                if method == "GET" and ("GET", path) in outer.data:
                    return self._send(200, {"data": outer.data[("GET", path)]})
                return self._send(404, {"data": None})

            def _send(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self._serve("GET")

            def do_POST(self):
                self._serve("POST")

        class Srv(http.server.ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = True

            def handle_error(self, *a):
                pass

        self.httpd = Srv((ip, port), H)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True,
                                            do_handshake_on_connect=False)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def node_data(name, cpu=0.25, vms=(), lxcs=(), pveversion="pve-manager/8.2.4/abc"):
    return {
        ("GET", "/version"): {"version": pveversion.split("/")[1], "release": "8.2"},
        ("GET", f"/nodes/{name}/status"): {
            "cpu": cpu, "uptime": 3700, "loadavg": ["0.10", "0.20", "0.30"],
            "memory": {"total": 8 * 1024 ** 3, "used": 2 * 1024 ** 3, "free": 6 * 1024 ** 3},
            "cpuinfo": {"cpus": 8, "cores": 4, "sockets": 1}, "pveversion": pveversion,
            "kversion": "Linux 6.8.4-2-pve #1 SMP", "rootfs": {"total": 100 * 1024 ** 3,
                                                               "used": 40 * 1024 ** 3, "avail": 60 * 1024 ** 3}},
        ("GET", f"/nodes/{name}/qemu"): list(vms),
        ("GET", f"/nodes/{name}/lxc"): list(lxcs),
        ("GET", f"/nodes/{name}/storage"): [
            {"storage": "local", "type": "dir", "active": 1, "enabled": 1, "total": 100 * 1024 ** 3,
             "used": 10 * 1024 ** 3, "avail": 90 * 1024 ** 3, "content": "iso,backup"}],
        ("GET", f"/nodes/{name}/network"): [
            {"iface": "vmbr0", "type": "bridge", "active": 1, "address": "10.0.0.5", "netmask": "255.255.255.0"},
            {"iface": "eno1", "type": "eth", "active": 1}],
        ("GET", f"/nodes/{name}/rrddata"): [{"time": 1, "cpu": 0.1, "memused": 1024 ** 3},
                                            {"time": 2, "cpu": 0.3, "memused": 2 * 1024 ** 3}],
        ("GET", f"/nodes/{name}/disks/list"): [{"devpath": "/dev/sda", "size": 500 * 1024 ** 3}],
        ("GET", "/access/permissions"): {"/": {"Sys.Audit": 1, "VM.Audit": 1, "VM.PowerMgmt": 1}},
    }


UPID = "UPID:{n}:000A1B2C:00123456:65F00000:{t}:{v}:proxmenux@pve!monitor:"


class FakePvesh:
    """Stand-in for the local `pvesh` (the node running ProxMenux)."""

    def __init__(self):
        self.fail = None
        self.nodes = [("pve", 1, "127.0.0.1", 1, 1), ("pve-1", 2, "127.0.0.2", 0, 1),
                      ("pve-2", 3, "127.0.0.3", 0, 1), ("pve-3", 4, "127.0.0.4", 0, 1)]
        self.quorate = 1
        self.cluster_name = "s6"
        self.calls = []
        self.local_vms = [{"vmid": 100, "name": "web", "status": "running", "mem": 1, "maxmem": 2,
                           "cpu": 0.1, "disk": 0, "maxdisk": 10, "uptime": 5}]

    def __call__(self, method, path, params=None):
        self.calls.append((method, path))
        if self.fail:
            raise cm.NodeApiError(self.fail)
        if path == "/cluster/status":
            out = [{"type": "cluster", "name": self.cluster_name, "nodes": len(self.nodes),
                    "quorate": self.quorate, "version": 3, "id": "cluster"}] if self.cluster_name else []
            for name, nid, ip, local, online in self.nodes:
                out.append({"type": "node", "name": name, "nodeid": nid, "ip": ip, "local": local,
                            "online": online, "id": f"node/{name}"})
            return out
        if path == "/nodes":
            return [{"node": n, "status": "online" if on else "offline", "cpu": 0.1 * i, "maxcpu": 8,
                     "mem": 1024 ** 3, "maxmem": 8 * 1024 ** 3, "uptime": 1000 * i}
                    for i, (n, _, _, _, on) in enumerate(self.nodes, 1)]
        if path == "/version":
            return {"version": "8.2.4", "release": "8.2"}
        if path == "/nodes/pve/status":
            return node_data("pve", cpu=0.5)[("GET", "/nodes/pve/status")]
        if path == "/nodes/pve/qemu":
            return self.local_vms
        if path == "/nodes/pve/lxc":
            return []
        raise cm.NodeApiError("not_found")


# ----------------------------------------------------------------- base ---

class ClusterBase(unittest.TestCase):
    PORT = None

    @classmethod
    def setUpClass(cls):
        cls._workdir = tempfile.mkdtemp(prefix="pmx-cluster-")
        # one port shared by all fake nodes (the config has a single api_port)
        import socket
        s = socket.socket()
        s.bind(("127.0.0.2", 0))
        cls.PORT = s.getsockname()[1]
        s.close()
        cls.ca_file = Path(cls._workdir) / "ca.pem"
        cls.ca_file.write_bytes(_pem_cert(Pki.ca_cert))
        cls.other_ca_file = Path(cls._workdir) / "other-ca.pem"
        cls.other_ca_file.write_bytes(_pem_cert(Pki.other_cert))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._workdir, ignore_errors=True)

    def setUp(self):
        self.cfgdir = Path(tempfile.mkdtemp(prefix="pmx-cfg-"))
        self.patches = [
            mock.patch.object(auth_manager, "CONFIG_DIR", self.cfgdir),
            mock.patch.object(auth_manager, "ensure_config_dir", lambda: self.cfgdir.mkdir(parents=True, exist_ok=True)),
        ]
        for p in self.patches:
            p.start()
        cm.reset_runtime()
        cm._cfg_cache.update(path=None, mtime=None, cfg=None)
        cm.set_local_node_name_provider(lambda: "pve")
        self.pvesh = FakePvesh()
        cm.set_local_runner(self.pvesh)
        gw.remote_read_limiter.reset()
        gw.remote_write_limiter.reset()
        gw.admin_limiter.reset()
        gw._audit_state["path"] = None
        self.servers = {}
        self.configure(token=True)

    def tearDown(self):
        for s in self.servers.values():
            try:
                s.stop()
            except Exception:
                pass
        cm.set_local_runner(None)
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.cfgdir, ignore_errors=True)

    # helpers
    def configure(self, token=True, **extra):
        cfg = cm.load_config()
        cfg.update(dict(tls_mode="ca", ca_file=str(self.ca_file), api_port=self.PORT), **extra)
        if token:
            cfg["token_id"] = TOKEN_ID
            cfg["token_secret_enc"] = cm.encrypt_secret(SECRET)
        cm.save_config(cfg)

    def start_node(self, name, **kw):
        node = FakeNode(name, NODE_IPS[name], self.PORT, self._workdir)
        node.data = node_data(name, **kw)
        self.servers[name] = node
        return node

    def start_all(self):
        vm = lambda vmid, n: {"vmid": vmid, "name": f"vm{vmid}", "status": "running", "cpu": 0.1,
                              "mem": 1, "maxmem": 2, "disk": 0, "maxdisk": 1, "uptime": 9}
        self.start_node("pve-1", cpu=0.11, vms=[vm(201, "pve-1")], lxcs=[{"vmid": 301, "name": "ct301", "status": "stopped"}])
        self.start_node("pve-2", cpu=0.22, vms=[vm(202, "pve-2")])
        self.start_node("pve-3", cpu=0.33)
        for n in ("pve-1", "pve-2", "pve-3"):
            self.servers[n].data[("POST", f"/nodes/{n}/qemu/20{n[-1]}/status/start")] = UPID.format(n=n, t="qmstart", v="20" + n[-1])


# ------------------------------------------------------------ discovery ---

class DiscoveryTests(ClusterBase):
    def test_discovers_cluster_nodes_versions_and_flags(self):
        self.start_all()
        res = cm.discover(force=True)
        self.assertTrue(res["ok"])
        nodes = {n["name"]: n for n in cm.list_nodes()}
        self.assertEqual(set(nodes), {"pve", "pve-1", "pve-2", "pve-3"})
        self.assertTrue(nodes["pve"]["local"])
        self.assertEqual(nodes["pve-1"]["ip"], "127.0.0.2")
        self.assertEqual(nodes["pve-2"]["node_id"], 3)
        self.assertEqual(nodes["pve-3"]["pve_version"], "8.2.4")
        self.assertTrue(all(n["api_status"] == "ok" for n in nodes.values()))
        info, disc = cm.cluster_info()
        self.assertEqual((info["name"], info["node_count"], info["online"], info["offline"]), ("s6", 4, 4, 0))
        self.assertTrue(info["quorate"])
        self.assertIsNotNone(disc["last_sync"])

    def test_new_node_appears_removed_node_disappears(self):
        self.start_all()
        cm.discover(force=True)
        self.pvesh.nodes = [n for n in self.pvesh.nodes if n[0] != "pve-3"]
        cm.discover(force=True)
        self.assertNotIn("pve-3", {n["name"] for n in cm.list_nodes()})
        self.pvesh.nodes.append(("pve-3", 4, "127.0.0.4", 0, 1))
        cm.discover(force=True)
        self.assertIn("pve-3", {n["name"] for n in cm.list_nodes()})

    def test_offline_node_is_marked_and_not_probed(self):
        self.start_all()
        self.pvesh.nodes[2] = ("pve-2", 3, "127.0.0.3", 0, 0)
        hits_before = self.servers["pve-2"].hits
        cm.discover(force=True)
        n = cm.get_node("pve-2")
        self.assertFalse(n["online"])
        self.assertEqual(cm.node_status(n), "offline")
        self.assertEqual(self.servers["pve-2"].hits, hits_before)
        info, _ = cm.cluster_info()
        self.assertEqual((info["online"], info["offline"]), (3, 1))

    def test_standalone_host_without_cluster(self):
        self.pvesh.cluster_name = None
        self.pvesh.nodes = [("pve", 0, "127.0.0.1", 1, 1)]
        cm.discover(force=True)
        info, _ = cm.cluster_info()
        self.assertTrue(info["standalone"])
        self.assertEqual(info["node_count"], 1)

    def test_no_quorum_is_reported(self):
        self.start_all()
        self.pvesh.quorate = 0
        cm.discover(force=True)
        info, _ = cm.cluster_info()
        self.assertFalse(info["quorate"])

    def test_central_connection_loss_keeps_last_registry(self):
        self.start_all()
        cm.discover(force=True)
        self.pvesh.fail = "error"
        res = cm.discover(force=True)
        self.assertFalse(res["ok"])
        self.assertEqual(len(cm.list_nodes()), 4)
        _, disc = cm.cluster_info()
        self.assertIsNotNone(disc["last_error"])

    def test_discovery_disabled_skips_unless_forced(self):
        cfg = cm.load_config()
        cfg["enabled"] = False
        cm.save_config(cfg)
        self.assertEqual(cm.discover().get("skipped"), "disabled")
        self.assertEqual(self.pvesh.calls, [])

    def test_state_survives_restart_but_unverified(self):
        self.start_all()
        cm.discover(force=True)
        cm._nodes.clear()
        cm._loaded_state["done"] = False
        names = {n["name"] for n in cm.list_nodes()}
        self.assertEqual(names, {"pve", "pve-1", "pve-2", "pve-3"})
        self.assertTrue(all(not n["online"] for n in cm.list_nodes()))

    def test_parallel_probe_is_not_sequential(self):
        self.start_all()
        for n in ("pve-1", "pve-2", "pve-3"):
            self.servers[n].delay = 0.4
        t0 = time.time()
        cm.discover(force=True)
        self.assertLess(time.time() - t0, 1.0)     # 3 x 0.4s would be >= 1.2s sequentially


# -------------------------------------------------------- address / TLS ---

class AddressTests(unittest.TestCase):
    def test_internal_ranges(self):
        for ip in ("10.1.2.3", "192.168.0.9", "172.16.5.5", "127.0.0.1", "fd00::5", "::1", "100.64.1.1"):
            self.assertTrue(cm.is_internal_ip(ip), ip)
        for ip in ("8.8.8.8", "1.1.1.1", "169.254.169.254", "0.0.0.0", "224.0.0.1", "2001:db8::1" if False else "2606:4700::1", "bad"):
            self.assertFalse(cm.is_internal_ip(ip), ip)

    def test_resolve_rejects_mixed_results(self):
        with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.1", 0)), (2, 1, 6, "", ("8.8.8.8", 0))]):
            with self.assertRaises(cm.NodeApiError) as ctx:
                cm.resolve_internal("evil.example.com")
        self.assertEqual(ctx.exception.code, "rejected_address")

    def test_node_names_validated(self):
        for bad in ("../etc", "a b", "a/b", "", "x" * 70, "pve;rm", None, 5):
            self.assertFalse(cm.valid_node_name(bad), bad)
        for ok in ("pve", "pve-1", "N1"):
            self.assertTrue(cm.valid_node_name(ok))


class TlsAndTokenTests(ClusterBase):
    def _probe(self, name="pve-1"):
        self.pvesh.nodes = [("pve", 1, "127.0.0.1", 1, 1), (name, 2, NODE_IPS[name], 0, 1)]
        cm.discover(force=True)
        return cm.get_node(name)

    def test_valid_ca_works(self):
        self.start_node("pve-1")
        self.assertEqual(self._probe()["api_status"], "ok")

    def test_wrong_ca_is_a_tls_error_never_ignored(self):
        self.start_node("pve-1")
        self.configure(ca_file=str(self.other_ca_file))
        rec = self._probe()
        self.assertEqual(rec["api_status"], "tls")
        with self.assertRaises(cm.NodeApiError) as ctx:
            cm.node_call("pve-1", "GET", "/nodes/pve-1/status")
        self.assertEqual(ctx.exception.code, "tls")

    def test_missing_ca_file_fails_closed(self):
        self.start_node("pve-1")
        self.configure(ca_file="/nonexistent/ca.pem")
        self.assertEqual(self._probe()["api_status"], "tls")

    def test_fingerprint_pin_accepts_exact_certificate(self):
        self.start_node("pve-1")
        self.configure(tls_mode="fingerprint", fingerprints={"pve-1": Pki.fingerprint})
        self.assertEqual(self._probe()["api_status"], "ok")

    def test_fingerprint_pin_rejects_other_certificate(self):
        self.start_node("pve-1")
        self.configure(tls_mode="fingerprint", fingerprints={"pve-1": "ab" * 32})
        self.assertEqual(self._probe()["api_status"], "tls")

    def test_fingerprint_mode_without_pin_fails_closed(self):
        self.start_node("pve-1")
        self.configure(tls_mode="fingerprint", fingerprints={})
        self.assertEqual(self._probe()["api_status"], "tls")

    def test_system_trust_store_rejects_private_ca(self):
        self.start_node("pve-1")
        self.configure(tls_mode="system")
        self.assertEqual(self._probe()["api_status"], "tls")

    def test_no_insecure_mode_exists(self):
        for mode in ("insecure", "none", "off", "false", ""):
            cfg, err = cm.validate_settings_update({"tls_mode": mode}, cm.load_config())
            self.assertIsNotNone(err, mode)

    def test_wrong_token_secret_is_auth_error(self):
        node = self.start_node("pve-1")
        node.token = (TOKEN_ID, "other-secret")
        self.assertEqual(self._probe()["api_status"], "auth")

    def test_token_without_privileges_is_forbidden(self):
        node = self.start_node("pve-1")
        node.deny_prefixes = ("/nodes/",)
        cm.discover(force=True)
        self._probe()
        with self.assertRaises(cm.NodeApiError) as ctx:
            cm.node_call("pve-1", "GET", "/nodes/pve-1/status")
        self.assertEqual(ctx.exception.code, "forbidden")

    def test_missing_token_is_not_configured(self):
        self.start_node("pve-1")
        cfg = cm.load_config()
        cfg.update(token_id="", token_secret_enc="")
        cm.save_config(cfg)
        self.assertEqual(self._probe()["api_status"], "not_configured")

    def test_public_node_address_is_never_contacted(self):
        self.pvesh.nodes = [("pve", 1, "127.0.0.1", 1, 1), ("pve-1", 2, "8.8.8.8", 0, 1)]
        with mock.patch.object(cm.requests.Session, "request") as req:
            cm.discover(force=True)
        req.assert_not_called()
        self.assertEqual(cm.get_node("pve-1")["api_status"], "rejected_address")

    def test_manual_address_override_must_be_internal(self):
        cfg, err = cm.validate_settings_update({"node_addresses": {"pve-1": "8.8.8.8"}}, cm.load_config())
        self.assertIsNotNone(err)
        cfg, err = cm.validate_settings_update({"node_addresses": {"pve-1": "10.0.0.7"}}, cm.load_config())
        self.assertIsNone(err)

    def test_secret_is_encrypted_at_rest_and_private(self):
        raw = (self.cfgdir / "cluster.json").read_text()
        self.assertNotIn(SECRET, raw)
        self.assertIn("token_secret_enc", raw)
        for f in ("cluster.json", "cluster.key"):
            mode = stat.S_IMODE(os.stat(self.cfgdir / f).st_mode)
            self.assertEqual(mode & 0o077, 0, f)
        pub = cm.public_config()
        self.assertNotIn("token_secret_enc", pub)
        self.assertTrue(pub["token_secret_set"])
        self.assertNotIn(SECRET, json.dumps(pub))

    def test_secret_roundtrip_and_undecryptable(self):
        self.assertEqual(cm.decrypt_secret(cm.encrypt_secret("abc")), "abc")
        with self.assertRaises(cm.NodeApiError):
            cm.decrypt_secret("not-a-fernet-token")

    def test_timeout_is_classified(self):
        node = self.start_node("pve-1")
        node.delay = 1.2
        with mock.patch.object(cm, "READ_TIMEOUT", 0.3), mock.patch.object(cm, "GET_ATTEMPTS", 1):
            self.assertEqual(self._probe()["api_status"], "timeout")

    def test_settings_validation(self):
        base = cm.load_config()
        bad = [{"discovery_interval": 5}, {"discovery_interval": "60"}, {"api_port": 0}, {"ca_file": "relative.pem"},
               {"ca_file": "/etc/../x"}, {"token_id": "not a token"}, {"enabled": "yes"},
               {"fingerprints": {"pve": "zz"}}, {"permissions": {"role_nodes": {"user": ["a b"]}}},
               {"permissions": {"user_rules": {"x": {}}}}]
        for b in bad:
            self.assertIsNotNone(cm.validate_settings_update(dict(b), json.loads(json.dumps(base)))[1], b)


# ------------------------------------------- node calls / cache / fan-out ---

class NodeCallTests(ClusterBase):
    def setUp(self):
        super().setUp()
        self.start_all()
        cm.discover(force=True)

    def test_cache_avoids_second_request(self):
        n = self.servers["pve-1"]
        cm.node_call("pve-1", "GET", "/nodes/pve-1/status", ttl=30)
        hits = n.hits
        cm.node_call("pve-1", "GET", "/nodes/pve-1/status", ttl=30)
        self.assertEqual(n.hits, hits)

    def test_stale_data_when_node_goes_away(self):
        cm.node_call("pve-1", "GET", "/nodes/pve-1/status", ttl=0.01)
        time.sleep(0.05)
        self.servers["pve-1"].stop()
        res = cm.node_call("pve-1", "GET", "/nodes/pve-1/status", ttl=0.01)
        self.assertTrue(res.stale)
        self.assertIsNotNone(res.cached_at)

    def test_offline_without_cache_raises(self):
        self.servers["pve-3"].stop()
        with self.assertRaises(cm.NodeApiError) as ctx:
            cm.node_call("pve-3", "GET", "/nodes/pve-3/status", ttl=5)
        self.assertEqual(ctx.exception.code, "offline")

    def test_circuit_breaker_stops_hammering_dead_node(self):
        self.servers["pve-3"].stop()
        for _ in range(cm.BREAKER_THRESHOLD + 4):
            try:
                cm.node_call("pve-3", "GET", "/nodes/pve-3/status")
            except cm.NodeApiError as exc:
                self.assertEqual(exc.code, "offline")
        self.assertTrue(cm._breaker_open("pve-3"))
        with mock.patch.object(cm, "_raw_call") as raw:
            with self.assertRaises(cm.NodeApiError):
                cm.node_call("pve-3", "GET", "/nodes/pve-3/status")
        raw.assert_not_called()

    def test_unknown_node_name_is_rejected_before_any_io(self):
        with mock.patch.object(cm, "http_request") as req:
            with self.assertRaises(cm.NodeApiError) as ctx:
                cm.node_call("evil", "GET", "/version")
        self.assertEqual(ctx.exception.code, "unknown_node")
        req.assert_not_called()

    def test_get_is_retried_once_post_is_not(self):
        calls = []

        def flaky(*a, **k):
            calls.append(a[1])
            raise cm.NodeApiError("offline")
        with mock.patch.object(cm, "http_request", flaky):
            with self.assertRaises(cm.NodeApiError):
                cm.node_call("pve-1", "GET", "/x")
            n_get = len(calls)
            calls.clear()
            with self.assertRaises(cm.NodeApiError):
                cm.node_call("pve-2", "POST", "/x")
        self.assertEqual(n_get, cm.GET_ATTEMPTS)
        self.assertEqual(len(calls), 1)

    def test_fan_out_isolates_failures_and_runs_in_parallel(self):
        def work(name):
            time.sleep(0.3)
            if name == "pve-2":
                raise cm.NodeApiError("tls")
            if name == "pve-3":
                raise RuntimeError("boom")
            return name
        t0 = time.time()
        res = cm.fan_out(["pve", "pve-1", "pve-2", "pve-3"], work)
        self.assertLess(time.time() - t0, 0.9)
        self.assertEqual(res["pve"], (True, "pve"))
        self.assertEqual(res["pve-2"][1].code, "tls")
        self.assertFalse(res["pve-3"][0])

    def test_fan_out_deadline_marks_slow_node_timeout(self):
        res = cm.fan_out(["a", "b"], lambda n: time.sleep(2) if n == "b" else n, timeout=0.4)
        self.assertEqual(res["a"], (True, "a"))
        self.assertEqual(res["b"][1].code, "timeout")

    def test_guests_across_nodes_with_node_column(self):
        guests, errors, stale = cm.list_guests(["pve", "pve-1", "pve-2", "pve-3"])
        by_vmid = {g["vmid"]: g for g in guests}
        self.assertEqual({100, 201, 202, 301}, set(by_vmid))
        self.assertEqual(by_vmid[201]["node"], "pve-1")
        self.assertEqual(by_vmid[301]["type"], "lxc")
        self.assertEqual(by_vmid[100]["node"], "pve")
        self.assertEqual(errors, {})

    def test_guest_listing_survives_one_node_failing(self):
        self.servers["pve-2"].stop()
        guests, errors, _ = cm.list_guests(["pve", "pve-1", "pve-2", "pve-3"])
        self.assertIn(201, {g["vmid"] for g in guests})
        self.assertNotIn(202, {g["vmid"] for g in guests})
        self.assertEqual(errors["pve-2"]["code"], "offline")

    def test_find_guest_node(self):
        self.assertEqual(cm.find_guest_node(202), ("pve-2", "qemu"))
        self.assertEqual(cm.find_guest_node(9999), (None, None))

    def test_connection_test_steps_and_privileges(self):
        res = cm.test_node("pve-1")
        self.assertTrue(res["ok"], res)
        self.assertEqual([s["step"] for s in res["steps"]][:3], ["address", "tls_and_token", "privileges"])
        self.assertTrue(res["can_control"])
        self.servers["pve-2"].token = (TOKEN_ID, "bad")
        bad = cm.test_node("pve-2")
        self.assertFalse(bad["ok"])
        self.assertEqual([s for s in bad["steps"] if not s["ok"]][0]["code"], "auth")
        self.assertTrue(cm.test_node("pve")["ok"])
        self.assertFalse(cm.test_node("nope")["ok"])

    def test_connection_test_flags_missing_privileges(self):
        self.servers["pve-1"].data[("GET", "/access/permissions")] = {"/": {"Datastore.Audit": 1}}
        res = cm.test_node("pve-1")
        self.assertFalse(res["ok"])
        self.assertIn("Sys.Audit", res["steps"][-1]["message"])


# ------------------------------------------------------- HTTP + RBAC ---

IDENTITIES = {
    # token alias -> (username, scope, src, oidc user id, role)
    "admin": ("oidc:admin", rbac.SCOPE_ADMIN, "oidc", 1, rbac.ROLE_ADMIN),
    "user": ("oidc:user", rbac.SCOPE_USER, "oidc", 2, rbac.ROLE_USER),
    "ro": ("oidc:ro", rbac.SCOPE_READONLY, "oidc", 3, rbac.ROLE_READONLY),
    "user2": ("oidc:user2", rbac.SCOPE_USER, "oidc", 4, rbac.ROLE_USER),
    "local": ("admin", rbac.SCOPE_ADMIN, "local", None, None),
    "localro": ("apitoken", rbac.SCOPE_READONLY, "local", None, None),
}


class HttpBase(ClusterBase):
    def setUp(self):
        super().setUp()
        self.start_all()
        cm.discover(force=True)
        app = Flask(__name__)
        app.register_blueprint(cluster_bp)
        app.before_request(gw.enforce)

        @app.route("/api/system")
        @jwt_middleware.require_auth
        def local_system():
            return jsonify({"hostname": "pve", "local": True})

        @app.route("/api/vms/<int:vmid>/control", methods=["POST"])
        @jwt_middleware.require_auth
        def local_control(vmid):
            return jsonify({"local_control": vmid})

        @app.route("/api/hardware")
        @jwt_middleware.require_auth
        def local_hw():
            return jsonify({"local": True})

        @app.route("/api/system/power/reboot", methods=["POST"])
        @jwt_middleware.require_admin_scope
        def local_reboot():
            return jsonify({"rebooting": "LOCAL"})

        self.app = app
        self.client = app.test_client()

        def info(token):
            i = IDENTITIES.get(token)
            return {"username": i[0], "scope": i[1], "src": i[2], "sid": "sid-" + token} if i else None

        def user(sid):
            i = IDENTITIES[sid[4:]]
            return {"id": i[3], "role": i[4]}

        import oidc_manager
        auth_cfg = {"enabled": True, "declined": False}
        self.extra = [
            mock.patch.object(auth_manager, "load_auth_config", lambda: auth_cfg),
            mock.patch.object(jwt_middleware, "load_auth_config", lambda: auth_cfg),
            mock.patch.object(auth_manager, "get_session_info", info),
            mock.patch.object(jwt_middleware, "verify_token_full",
                              lambda t: (IDENTITIES[t][0], IDENTITIES[t][1]) if t in IDENTITIES else (None, None)),
            mock.patch.object(oidc_manager, "get_session_user", user),
        ]
        for p in self.extra:
            p.start()

    def tearDown(self):
        for p in self.extra:
            p.stop()
        super().tearDown()

    def req(self, method, path, who="admin", node=None, **kw):
        headers = kw.pop("headers", {})
        if who:
            headers["Authorization"] = f"Bearer {who}"
        if node:
            headers[gw.NODE_HEADER] = node
        return self.client.open(path, method=method, headers=headers, **kw)

    def set_perms(self, **perms):
        cfg = cm.load_config()
        cfg["permissions"] = {"role_nodes": {"user": ["@local"], "readonly": ["@local"]}, "user_rules": {}}
        cfg["permissions"].update(perms)
        cm.save_config(cfg)


class NodeSwitchingTests(HttpBase):
    def test_no_header_and_local_header_use_local_handlers(self):
        self.assertEqual(self.req("GET", "/api/system").get_json()["hostname"], "pve")
        self.assertTrue(self.req("GET", "/api/system", node="pve").get_json()["local"])

    def test_switching_nodes_returns_each_nodes_data_without_relogin(self):
        seen = {}
        for node in ("pve-1", "pve-2", "pve-3"):
            r = self.req("GET", "/api/system", who="admin", node=node)
            self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
            seen[node] = r.get_json()
            self.assertEqual(r.headers[gw.NODE_HEADER], node)
        self.assertEqual([seen[n]["hostname"] for n in seen], ["pve-1", "pve-2", "pve-3"])
        self.assertEqual([seen[n]["cpu_usage"] for n in seen], [11.0, 22.0, 33.0])
        d = seen["pve-1"]
        self.assertEqual((d["memory_total"], d["memory_used"], d["memory_usage"]), (8.0, 2.0, 25.0))
        self.assertEqual((d["uptime"], d["cpu_cores"], d["cpu_threads"]), ("1:01:40", 4, 8))
        self.assertEqual((d["proxmox_version"], d["kernel_version"]), ("8.2.4", "6.8.4-2-pve"))
        self.assertEqual(d["load_average"], [0.1, 0.2, 0.3])

    def test_remote_endpoints_return_local_shapes(self):
        r = self.req("GET", "/api/vms", node="pve-1").get_json()
        self.assertEqual({v["vmid"] for v in r}, {201, 301})
        self.assertTrue(all(v["node"] == "pve-1" for v in r))
        st = self.req("GET", "/api/proxmox-storage", node="pve-1").get_json()["storage"][0]
        self.assertEqual((st["name"], st["status"], st["total"], st["percent"]), ("local", "active", 100.0, 10.0))
        net = self.req("GET", "/api/network/summary", node="pve-1").get_json()
        self.assertEqual((net["bridge_total_count"], net["physical_total_count"]), (1, 1))
        summ = self.req("GET", "/api/storage/summary", node="pve-1").get_json()
        self.assertEqual((summ["disk_count"], summ["used"]), (1, 40.0))
        met = self.req("GET", "/api/node/metrics?timeframe=day", node="pve-1").get_json()
        self.assertEqual(met["node"], "pve-1")
        self.assertAlmostEqual(met["period_stats"]["cpu"]["avg"], 20.0)
        self.assertEqual(self.req("GET", "/api/node/metrics?timeframe=bad", node="pve-1").status_code, 400)

    def test_older_pve_with_sparse_status_does_not_crash(self):
        self.servers["pve-2"].data[("GET", "/nodes/pve-2/status")] = {"uptime": 5}
        r = self.req("GET", "/api/system", node="pve-2")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["memory_usage"], 0)

    def test_vm_detail_comes_from_the_hosting_node(self):
        self.servers["pve-2"].data[("GET", "/nodes/pve-2/qemu/202/config")] = {"name": "vm202", "digest": "x", "cores": 2}
        self.servers["pve-2"].data[("GET", "/nodes/pve-2/qemu/202/status/current")] = {"status": "running"}
        r = self.req("GET", "/api/vms/202", node="pve-2").get_json()
        self.assertEqual((r["node"], r["vm_type"], r["config"]["cores"]), ("pve-2", "qemu", 2))
        self.assertNotIn("digest", r["config"])
        # a guest that lives on pve-1 is NOT served when addressed through pve-2
        self.assertEqual(self.req("GET", "/api/vms/201", node="pve-2").status_code, 404)

    def test_invalid_conflicting_and_unknown_nodes(self):
        self.assertEqual(self.req("GET", "/api/system", node="../../etc").status_code, 400)
        self.assertEqual(self.req("GET", "/api/system?pmx_node=pve-1", node="pve-2").status_code, 400)
        r = self.req("GET", "/api/system", node="ghost")
        self.assertEqual((r.status_code, r.get_json()["error"]), (403, "node_forbidden"))

    def test_query_selector_works_for_non_header_clients(self):
        r = self.req("GET", "/api/system?pmx_node=pve-1")
        self.assertEqual(r.get_json()["hostname"], "pve-1")

    def test_unsupported_node_scoped_route_never_returns_local_data(self):
        r = self.req("GET", "/api/hardware", node="pve-1")
        self.assertEqual((r.status_code, r.get_json()["error"]), (501, "node_unsupported"))
        r = self.req("POST", "/api/system/power/reboot", node="pve-1")
        self.assertEqual(r.status_code, 501)          # must not reboot the LOCAL node
        self.assertNotIn("LOCAL", r.get_data(as_text=True))

    def test_instance_level_routes_ignore_node_selector(self):
        r = self.req("GET", "/api/cluster/nodes", node="pve-1")
        self.assertEqual(r.status_code, 200)

    def test_unauthenticated_remote_request_is_401(self):
        r = self.req("GET", "/api/system", who=None, node="pve-1")
        self.assertEqual(r.status_code, 401)
        r = self.req("GET", "/api/system", who="bogus", node="pve-1")
        self.assertEqual(r.status_code, 401)


class OfflineAndFailureTests(HttpBase):
    def test_offline_node_message_and_other_nodes_unaffected(self):
        self.servers["pve-2"].stop()
        r = self.req("GET", "/api/system", node="pve-2")
        self.assertEqual(r.status_code, 503)
        body = r.get_json()
        self.assertEqual((body["error"], body["message"]), ("node_offline", "Node offline – Daten derzeit nicht verfügbar"))
        self.assertEqual(self.req("GET", "/api/system", node="pve-1").status_code, 200)
        self.assertEqual(self.req("GET", "/api/system").status_code, 200)

    def test_cluster_member_offline_in_corosync(self):
        self.pvesh.nodes[3] = ("pve-3", 4, "127.0.0.4", 0, 0)
        cm.discover(force=True)
        r = self.req("GET", "/api/system", node="pve-3")
        self.assertEqual((r.status_code, r.get_json()["error"]), (503, "node_offline"))

    def test_cached_data_is_served_with_timestamp_when_node_dies(self):
        with mock.patch.object(gw.cm, "node_call", wraps=cm.node_call):
            self.req("GET", "/api/vms", node="pve-1")
        cm._cache.clear()
        # warm cache with ttl so the entry can go stale
        cm.node_call("pve-1", "GET", "/nodes/pve-1/status", ttl=4)
        key = ("pve-1", "GET /nodes/pve-1/status []")
        cm._cache[key] = (cm._cache[key][0] - 60, cm._cache[key][1])     # expired, still < STALE_MAX_AGE
        self.servers["pve-1"].stop()
        r = self.req("GET", "/api/system", node="pve-1")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers.get("X-ProxMenux-Stale"), "1")
        self.assertGreater(int(r.headers["X-ProxMenux-Cached-At"]), 0)

    def test_tls_error_is_502_not_401(self):
        self.configure(ca_file=str(self.other_ca_file))
        cm._cache.clear()
        r = self.req("GET", "/api/system", node="pve-1")
        self.assertEqual((r.status_code, r.get_json()["error"]), (502, "node_tls"))

    def test_token_rejected_is_502_so_the_user_stays_logged_in(self):
        self.servers["pve-1"].token = (TOKEN_ID, "rotated")
        r = self.req("GET", "/api/system", node="pve-1")
        self.assertEqual((r.status_code, r.get_json()["error"]), (502, "node_auth"))

    def test_token_without_rights_is_reported(self):
        self.servers["pve-1"].deny_prefixes = ("/nodes/",)
        r = self.req("GET", "/api/system", node="pve-1")
        self.assertEqual((r.status_code, r.get_json()["error"]), (502, "node_forbidden"))

    def test_timeout_is_504(self):
        self.servers["pve-1"].delay = 1.0
        with mock.patch.object(cm, "READ_TIMEOUT", 0.2), mock.patch.object(cm, "GET_ATTEMPTS", 1):
            r = self.req("GET", "/api/system", node="pve-1")
        self.assertEqual((r.status_code, r.get_json()["error"]), (504, "node_timeout"))

    def test_central_connection_loss_dashboard_endpoints_still_answer(self):
        self.pvesh.fail = "error"
        cm.discover(force=True)
        self.assertEqual(self.req("GET", "/api/cluster/nodes").status_code, 200)
        self.assertEqual(self.req("GET", "/api/system").status_code, 200)
        self.assertEqual(self.req("GET", "/api/system", node="pve-1").status_code, 200)

    def test_node_removed_from_cluster_is_unknown_afterwards(self):
        self.pvesh.nodes = [n for n in self.pvesh.nodes if n[0] != "pve-3"]
        cm.discover(force=True)
        self.assertEqual(self.req("GET", "/api/system", node="pve-3").status_code, 403)

    def test_internal_error_in_a_handler_is_contained(self):
        boom = mock.Mock(side_effect=RuntimeError("boom"))
        routes = [("GET", gw.REMOTE_ROUTES[0][1], boom, False)]
        with mock.patch.object(gw, "REMOTE_ROUTES", routes):
            r = self.req("GET", "/api/system", node="pve-1")
        self.assertEqual(r.status_code, 502)
        self.assertNotIn("boom", r.get_data(as_text=True))

    def test_guests_endpoint_reports_offline_nodes_as_errors(self):
        self.servers["pve-2"].stop()
        self.pvesh.nodes[2] = ("pve-2", 3, "127.0.0.3", 0, 0)
        cm.discover(force=True)
        body = self.req("GET", "/api/cluster/guests").get_json()
        self.assertEqual({g["vmid"] for g in body["guests"]}, {100, 201, 301})
        self.assertEqual(body["errors"]["pve-2"]["message"], "Node offline – Daten derzeit nicht verfügbar")


class PermissionTests(HttpBase):
    def test_admin_group_sees_and_reaches_all_nodes(self):
        names = {n["name"] for n in self.req("GET", "/api/cluster/nodes", who="admin").get_json()["nodes"]}
        self.assertEqual(names, {"pve", "pve-1", "pve-2", "pve-3"})
        for n in ("pve-1", "pve-2", "pve-3"):
            self.assertEqual(self.req("GET", "/api/system", who="admin", node=n).status_code, 200)

    def test_users_and_readonly_only_get_released_nodes(self):
        self.set_perms(role_nodes={"user": ["pve", "pve-1"], "readonly": ["pve-2"]})
        self.assertEqual(self.req("GET", "/api/system", who="user", node="pve-1").status_code, 200)
        self.assertEqual(self.req("GET", "/api/system", who="user", node="pve-2").status_code, 403)
        self.assertEqual(self.req("GET", "/api/system", who="ro", node="pve-2").status_code, 200)
        self.assertEqual(self.req("GET", "/api/system", who="ro", node="pve-1").status_code, 403)
        # the local node is denied too when it is not released
        self.assertEqual(self.req("GET", "/api/system", who="ro").status_code, 403)
        names = {n["name"] for n in self.req("GET", "/api/cluster/nodes", who="user").get_json()["nodes"]}
        self.assertEqual(names, {"pve", "pve-1"})

    def test_default_is_backwards_compatible_local_only(self):
        self.assertEqual(self.req("GET", "/api/system", who="user").status_code, 200)
        self.assertEqual(self.req("GET", "/api/system", who="user", node="pve-1").status_code, 403)

    def test_per_user_allow_extends_role(self):
        self.set_perms(user_rules={"2": {"allow": ["pve-3"], "deny": []}})
        self.assertEqual(self.req("GET", "/api/system", who="user", node="pve-3").status_code, 200)
        self.assertEqual(self.req("GET", "/api/system", who="user2", node="pve-3").status_code, 403)

    def test_per_user_deny_beats_role_and_even_admin(self):
        self.set_perms(role_nodes={"user": ["*"], "readonly": []},
                       user_rules={"2": {"allow": [], "deny": ["pve-2"]}, "1": {"allow": [], "deny": ["pve-3"]}})
        self.assertEqual(self.req("GET", "/api/system", who="user", node="pve-2").status_code, 403)
        self.assertEqual(self.req("GET", "/api/system", who="user2", node="pve-2").status_code, 200)
        self.assertEqual(self.req("GET", "/api/system", who="admin", node="pve-3").status_code, 403)
        self.assertEqual(self.req("GET", "/api/system", who="admin", node="pve-2").status_code, 200)

    def test_wildcard_role(self):
        self.set_perms(role_nodes={"user": ["*"], "readonly": []})
        self.assertEqual(self.req("GET", "/api/system", who="user", node="pve-3").status_code, 200)

    def test_local_accounts_and_api_tokens_keep_full_access(self):
        self.set_perms(role_nodes={"user": [], "readonly": []})
        for who in ("local", "localro"):
            self.assertEqual(self.req("GET", "/api/system", who=who, node="pve-2").status_code, 200)

    def test_unknown_and_forbidden_nodes_look_identical_for_users(self):
        self.set_perms(role_nodes={"user": ["pve"], "readonly": []})
        a = self.req("GET", "/api/system", who="user", node="pve-2")
        b = self.req("GET", "/api/system", who="user", node="ghost")
        self.assertEqual((a.status_code, a.get_json()), (b.status_code, b.get_json()))

    def test_scope_is_enforced_on_remote_nodes(self):
        self.set_perms(role_nodes={"user": ["*"], "readonly": ["*"]})
        self.configure(allow_remote_control=True)
        r = self.req("POST", "/api/vms/201/control", who="ro", node="pve-1", json={"action": "start"})
        self.assertEqual(r.status_code, 403)
        r = self.req("POST", "/api/system/power/reboot", who="user", node="pve-1")
        self.assertEqual(r.status_code, 403)

    def test_remote_power_control_needs_switch_and_user_scope(self):
        self.set_perms(role_nodes={"user": ["*"], "readonly": []})
        path = "/api/vms/201/control"
        r = self.req("POST", path, who="user", node="pve-1", json={"action": "start"})
        self.assertEqual((r.status_code, r.get_json()["error"]), (403, "remote_control_disabled"))
        self.assertEqual(self.servers["pve-1"].posts, [])
        self.configure(allow_remote_control=True)
        self.servers["pve-1"].data[("POST", "/nodes/pve-1/qemu/201/status/start")] = UPID.format(n="pve-1", t="qmstart", v="201")
        r = self.req("POST", path, who="user", node="pve-1", json={"action": "start"})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertTrue(r.get_json()["task"].startswith("UPID:"))
        self.assertEqual(len(self.servers["pve-1"].posts), 1)
        # invalid action and wrong node/vmid pairing are refused before any POST
        self.assertEqual(self.req("POST", path, who="user", node="pve-1", json={"action": "destroy"}).status_code, 400)
        self.assertEqual(self.req("POST", "/api/vms/202/control", who="user", node="pve-1", json={"action": "start"}).status_code, 404)
        self.assertEqual(len(self.servers["pve-1"].posts), 1)

    def test_idor_guest_on_forbidden_node_via_local_route(self):
        """A user limited to the local node must not control a guest that lives
        on another node by omitting/choosing the node selector."""
        self.set_perms(role_nodes={"user": ["pve", "pve-1"], "readonly": []})
        cm.list_guests(["pve", "pve-1", "pve-2", "pve-3"])         # discovery keeps this cache warm
        r = self.req("POST", "/api/vms/202/control", who="user", node="pve", json={"action": "stop"})
        self.assertEqual((r.status_code, r.get_json()["error"]), (403, "node_forbidden"))
        r = self.req("POST", "/api/vms/202/control", who="user", json={"action": "stop"})
        self.assertEqual(r.status_code, 403)
        # allowed node still works
        self.assertEqual(self.req("POST", "/api/vms/100/control", who="user", node="pve", json={"action": "stop"}).status_code, 200)

    def test_idor_default_permissions_local_only_cannot_touch_other_nodes_guests(self):
        # untouched default config (users: local node only), cold cache, no header
        r = self.req("POST", "/api/vms/202/control", who="user", json={"action": "stop"})
        self.assertEqual((r.status_code, r.get_json()["error"]), (403, "node_forbidden"))
        r = self.req("POST", "/api/vms/100/control", who="user", json={"action": "stop"})
        self.assertEqual(r.status_code, 200)             # own node's guest still works
        self.assertEqual(self.req("POST", "/api/vms/202/control", who="admin", json={"action": "stop"}).status_code, 200)

    def test_idor_guest_check_works_with_a_cold_cache(self):
        self.set_perms(role_nodes={"user": ["pve"], "readonly": []})
        cm._cache.clear()                       # discovery has not warmed the guest map yet
        r = self.req("POST", "/api/vms/202/control", who="user", json={"action": "stop"})
        self.assertEqual((r.status_code, r.get_json()["error"]), (403, "node_forbidden"))
        self.assertEqual(self.servers["pve-2"].posts, [])

    def test_central_token_cannot_be_used_to_exceed_the_users_rights(self):
        self.set_perms(role_nodes={"user": ["pve"], "readonly": []})
        before = self.servers["pve-2"].hits
        for method, path in (("GET", "/api/system"), ("GET", "/api/vms"), ("POST", "/api/vms/202/control")):
            r = self.req(method, path, who="user", node="pve-2", json={"action": "stop"} if method == "POST" else None)
            self.assertEqual(r.status_code, 403)
        self.assertEqual(self.servers["pve-2"].hits, before)      # no request ever left for pve-2

    def test_settings_endpoints_are_admin_only(self):
        for who in ("user", "ro"):
            for method, path in (("GET", "/api/cluster/settings"), ("PUT", "/api/cluster/settings"),
                                 ("POST", "/api/cluster/discover"), ("POST", "/api/cluster/test"),
                                 ("GET", "/api/cluster/audit")):
                self.assertEqual(self.req(method, path, who=who, json={}).status_code, 403, (who, path))
        self.assertEqual(self.req("GET", "/api/cluster/settings", who=None).status_code, 401)

    def test_non_admin_does_not_learn_internal_addresses(self):
        self.set_perms(role_nodes={"user": ["*"], "readonly": []})
        nodes = self.req("GET", "/api/cluster/nodes", who="user").get_json()["nodes"]
        self.assertTrue(all("ip" not in n and "ssl_fingerprint" not in n for n in nodes))
        nodes = self.req("GET", "/api/cluster/nodes", who="admin").get_json()["nodes"]
        self.assertTrue(all("ip" in n for n in nodes))

    def test_guest_list_is_filtered_by_node_permission(self):
        self.set_perms(role_nodes={"user": ["pve", "pve-2"], "readonly": []})
        ids = {g["vmid"] for g in self.req("GET", "/api/cluster/guests", who="user").get_json()["guests"]}
        self.assertEqual(ids, {100, 202})

    def test_rate_limit_on_remote_requests(self):
        gw.remote_read_limiter.max = 3
        try:
            codes = [self.req("GET", "/api/system", node="pve-1").status_code for _ in range(5)]
        finally:
            gw.remote_read_limiter.max = 600
        self.assertEqual(codes[:3], [200] * 3)
        self.assertEqual(codes[3:], [429, 429])

    def test_audit_log_records_denials_and_actions_without_secrets(self):
        self.set_perms(role_nodes={"user": ["pve"], "readonly": []})
        self.req("GET", "/api/system", who="user", node="pve-2")
        self.configure(allow_remote_control=True)
        self.set_perms(role_nodes={"user": ["*"], "readonly": []})
        self.servers["pve-1"].data[("POST", "/nodes/pve-1/qemu/201/status/start")] = UPID.format(n="pve-1", t="qmstart", v="201")
        self.req("POST", "/api/vms/201/control", who="user", node="pve-1", json={"action": "start"})
        events = self.req("GET", "/api/cluster/audit").get_json()["events"]
        kinds = [e["event"] for e in events]
        self.assertIn("deny_node", kinds)
        self.assertIn("remote_action", kinds)
        deny = next(e for e in events if e["event"] == "deny_node")
        self.assertEqual((deny["user"], deny["node"]), ("oidc:user", "pve-2"))
        raw = (self.cfgdir / "cluster-audit.log").read_text()
        self.assertNotIn(SECRET, raw)


class SettingsRouteTests(HttpBase):
    def test_settings_roundtrip_never_returns_the_secret(self):
        r = self.req("PUT", "/api/cluster/settings", json={"token_id": TOKEN_ID, "token_secret": "new-secret-value",
                                                          "discovery_interval": 120})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertNotIn("new-secret-value", r.get_data(as_text=True))
        got = self.req("GET", "/api/cluster/settings").get_json()
        self.assertTrue(got["settings"]["token_secret_set"])
        self.assertNotIn("new-secret-value", json.dumps(got))
        self.assertNotIn("token_secret_enc", got["settings"])
        self.assertEqual(cm.decrypt_secret(cm.load_config()["token_secret_enc"]), "new-secret-value")

    def test_empty_secret_keeps_the_stored_one(self):
        self.req("PUT", "/api/cluster/settings", json={"token_secret": ""})
        self.assertEqual(cm.decrypt_secret(cm.load_config()["token_secret_enc"]), SECRET)

    def test_invalid_settings_rejected(self):
        self.assertEqual(self.req("PUT", "/api/cluster/settings", json={"tls_mode": "insecure"}).status_code, 400)
        self.assertEqual(self.req("PUT", "/api/cluster/settings", json=["x"]).status_code, 400)

    def test_permissions_can_be_saved_and_take_effect_immediately(self):
        r = self.req("PUT", "/api/cluster/settings", json={"permissions": {
            "role_nodes": {"user": ["pve", "pve-3"], "readonly": []},
            "user_rules": {"2": {"allow": [], "deny": ["pve-3"]}}}})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.req("GET", "/api/system", who="user", node="pve-3").status_code, 403)
        # user2 has no rule of its own and shares the role list -> allowed
        self.assertEqual(self.req("GET", "/api/system", who="user2", node="pve-3").status_code, 200)

    def test_manual_discovery_and_connection_test_routes(self):
        d = self.req("POST", "/api/cluster/discover").get_json()
        self.assertTrue(d["success"])
        self.assertEqual(len(d["nodes"]), 4)
        t = self.req("POST", "/api/cluster/test", json={"node": "pve-1"}).get_json()
        self.assertTrue(t["results"][0]["ok"])
        allr = self.req("POST", "/api/cluster/test", json={}).get_json()["results"]
        self.assertEqual(len(allr), 4)
        self.assertEqual(self.req("POST", "/api/cluster/test", json={"node": "../x"}).status_code, 400)

    def test_admin_actions_are_rate_limited(self):
        gw.admin_limiter.max = 2
        try:
            codes = [self.req("POST", "/api/cluster/discover").status_code for _ in range(4)]
        finally:
            gw.admin_limiter.max = 20
        self.assertEqual(codes, [200, 200, 429, 429])

    def test_disabling_cluster_blocks_remote_access(self):
        self.req("PUT", "/api/cluster/settings", json={"enabled": False})
        self.assertEqual(self.req("GET", "/api/system", node="pve-1").status_code, 404)
        self.assertEqual(self.req("GET", "/api/system").status_code, 200)


class FastPathTests(HttpBase):
    def test_single_node_setup_does_no_identity_work(self):
        with mock.patch.object(node_access, "identity_from_request") as ident:
            r = self.req("GET", "/api/system", who="admin")
        self.assertEqual(r.status_code, 200)
        ident.assert_not_called()


if __name__ == "__main__":
    unittest.main()
