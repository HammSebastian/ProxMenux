# Multi-node management (one ProxMenux instance for the whole cluster)

Run **one** public ProxMenux Monitor (for example `https://proxmenux.s6-kanzlei.com` on node
`pve`). It discovers every node of the Proxmox VE cluster and manages them over the **internal
network** through the official Proxmox VE API. Nothing is installed on the other nodes. The
domain never changes when you switch nodes: the node is just a selector in the dashboard.

* [Architecture](#architecture)
* [Setup on the Proxmox nodes (API token)](#setup-on-the-proxmox-nodes)
* [Configuration in ProxMenux](#configuration-in-proxmenux)
* [Permissions (Authentik groups, per user)](#permissions)
* [What works for other nodes](#what-works-for-other-nodes)
* [Failure behaviour](#failure-behaviour)
* [Security assessment](#security-assessment)
* [Troubleshooting](#troubleshooting)

## Architecture

```
Browser ──HTTPS──▶ proxmenux.s6-kanzlei.com ──▶ ProxMenux on node "pve"  (single public entry)
                                                  │
        every /api/* request                      │  cluster_gateway.enforce()  (before_request)
        X-ProxMenux-Node: pve-2   ───────────────▶│   1. node name syntax check
                                                  │   2. session + rbac scope  (same rules as the routes)
                                                  │   3. node_access.can_access(user, node)
                                                  │   4. guest routes: access to the node HOSTING the vmid
                                                  │   5. rate limit, audit log
                                                  ▼
                       local node ────────────▶ existing Flask handlers, unchanged (pvesh / pmxcfs)
                       other node ────────────▶ cluster_manager.node_call()  ──HTTPS+token──▶ https://<internal-ip>:8006/api2/json
```

Modules (all in `AppImage/scripts/`):

| Module | Role |
| --- | --- |
| `cluster_manager.py` | Config + Fernet-encrypted token (`cluster.json`, `cluster.key`), strict TLS transport, node registry, discovery, per-node calls (timeouts, retries, circuit breaker, TTL cache, stale-on-error), parallel fan-out, connection test |
| `node_access.py` | Per-node authorisation: OIDC role lists + per-user allow/deny |
| `cluster_gateway.py` | `before_request` hook, audit log, rate limits, remote handlers that return the **same JSON shapes** as the local handlers |
| `flask_cluster_routes.py` | `/api/cluster/*` (nodes, guests, settings, discover, test, audit) |

Frontend: `lib/node-context.tsx` (nodes + selection), `components/node-selector.tsx`,
`components/node-status-banner.tsx`, `components/cluster-settings.tsx` (Settings → Cluster
Management); the node header is added centrally in `lib/api-config.ts`.

### Why not just query `/cluster/resources` locally?

`flask_server.py` (≈24k lines) reads almost everything from the local host (`psutil`, `/proc`,
`pvesh`, pmxcfs, `lsblk`, `smartctl`, …). Only the guest list, discovery and node metrics are
cluster-wide at the PVE level. Rewriting every handler for remote hosts is neither safe nor
possible through the PVE API (SMART, sensors, terminal, host backups, … have no API). So:

* the **local node** keeps using the existing handlers - zero behaviour change for it;
* **other nodes** are served by gateway handlers that translate PVE API answers into the
  response shapes the dashboard already understands (`/api/system`, `/api/system-info`,
  `/api/vms`, `/api/vms/<id>`, `/api/vms/<id>/control`, `/api/storage/summary`,
  `/api/proxmox-storage`, `/api/network/summary`, `/api/node/metrics`);
* every other node-scoped route **fails closed** with `501 node_unsupported` when another node is
  selected - it never silently returns the local node's data (a reboot request for `pve-2` can
  never reboot `pve`).

Discovery uses `pvesh get /cluster/status` and `/nodes` on the local node (the official API, no
token needed) and probes each node's API (`GET /version`) in parallel.

## Setup on the Proxmox nodes

API users and tokens live in the cluster file system, so **one token works on every node** - do
this once, on any node (as root):

```bash
# 1. a dedicated user without a password (cannot log in, only holds the token)
pveum user add proxmenux@pve --comment "ProxMenux Monitor"

# 2. read-only role for the whole cluster
pveum acl modify / --users proxmenux@pve --roles PVEAuditor

# 3. API token with privilege separation: its rights are the intersection of user and token ACLs
pveum user token add proxmenux@pve monitor --privsep 1
#   -> prints the secret ONCE. Copy it.

# 4. give the TOKEN (not only the user) the same read role
pveum acl modify / --tokens 'proxmenux@pve!monitor' --roles PVEAuditor
```

`PVEAuditor` = `Sys.Audit`, `VM.Audit`, `Datastore.Audit`, `Pool.Audit` (read only). That is all
needed for monitoring.

**Optional - power control of guests on other nodes** (start/stop/shutdown/reboot). Keep it
disabled unless you need it, and scope it as narrowly as you can:

```bash
pveum acl modify /vms --tokens 'proxmenux@pve!monitor' --roles PVEVMUser   # VM.PowerMgmt, VM.Console, ...
# or a dedicated role with only VM.PowerMgmt:
pveum role add ProxMenuxPower --privs "VM.PowerMgmt"
pveum acl modify /vms --tokens 'proxmenux@pve!monitor' --roles ProxMenuxPower
```

Then enable *Allow power control of guests on other nodes* in ProxMenux. Never give the token
`Administrator`, `PVEAdmin` or a root password.

**Network:** the nodes must reach each other on TCP 8006 (they already do inside a cluster). The
public reverse proxy must **not** expose port 8006 of the nodes; only `proxmenux.s6-kanzlei.com`
is public.

### Certificates

PVE nodes use certificates signed by the cluster CA (`/etc/pve/pve-root-ca.pem`, readable on
every node). ProxMenux verifies them against that CA **including the node IP/hostname** - there
is no "ignore certificate errors" option. Three modes:

| Mode | Use when |
| --- | --- |
| `ca` (default) | Nodes use the PVE-generated certificates. CA file defaults to `/etc/pve/pve-root-ca.pem`. |
| `fingerprint` | You prefer pinning each node's certificate (SHA-256 shown in the PVE GUI under *Node → System → Certificates*). A node without a pinned fingerprint is not contacted. Use this if your Python/OpenSSL rejects the PVE CA's extensions (strict X.509 validation). |
| `system` | Nodes use publicly trusted certificates (e.g. ACME) **and** are addressed by hostname (see *Node addresses*). |

## Configuration in ProxMenux

Settings → **Cluster Management** (administrators only):

1. *API token ID* `proxmenux@pve!monitor`, *API token secret* (write-only; stored encrypted).
2. Choose the TLS mode. Press **Test all connections** - each node shows: internal address ✓,
   TLS certificate and API token ✓, read permissions ✓, required privileges ✓, and whether the
   token may control guests.
3. Discovery is **on by default** (every 60 s). **Discover nodes now** triggers it manually.
   New nodes appear automatically, removed nodes disappear.
4. Optional: *Allow power control of guests on other nodes*.

Files (in the ProxMenux config dir, mode 0600): `cluster.json` (settings + encrypted secret),
`cluster.key` (Fernet key), `cluster-state.json` (last known node list),
`cluster-audit.log` (JSON lines, rotated).

Node addresses come from the cluster (`/cluster/status`, the corosync address). They must be
**internal** (RFC 1918, ULA, loopback, 100.64/10). Public, link-local, multicast or unspecified
addresses are rejected and never contacted. A per-node override (`node_addresses`, e.g. a
hostname for `system` mode) is validated the same way - for hostnames **every** resolved address
must be internal.

## Permissions

Integrated with the OIDC (Authentik) roles. Authorisation is evaluated **on the server for every
request**; the UI only mirrors it.

| Identity | Nodes |
| --- | --- |
| `proxmenux-admins` (role *admin*) | all nodes |
| `proxmenux-users` (*user*) | the nodes released for this group (default: only the node running ProxMenux) |
| `proxmenux-readonly` (*readonly*) | the nodes released for this group (default: only the local node) |
| per user (OIDC user id) | **allow** (adds a node) or **deny** (removes it - deny always wins, even for admins) |
| local ProxMenux account / local API tokens | all nodes (as before) |

Existing rbac rules still apply on top: a *readonly* session cannot do anything but `GET`, a
*user* session only the explicit allow-list in `rbac.py` (guest power control, update checks,
backups, custom links). Configure it under Settings → Cluster Management → *Node permissions*
(group checkboxes per node; per-user inherit/allow/deny table).

The central API token is **only a transport**: it is used after the caller passed every check
above and only for the allow-listed remote operations. A user cannot reach a node, a guest or an
operation through it that the user could not reach directly.

## What works for other nodes

| Area | Other node |
| --- | --- |
| Overview: CPU, RAM, uptime, load, version, kernel; Proxmox storage; network interfaces; storage summary; node metrics charts | yes |
| VM/LXC list across **all** nodes with a *Node* column and node filter; details/power actions are loaded from the node that **hosts** the guest | yes (details: config + current status; power control optional) |
| Cluster / quorum / node status | yes (Settings → Cluster Management) |
| Settings, Profile, About, Identity Provider | instance-level; always the ProxMenux instance |
| Hardware (SMART, sensors, GPU), Storage tab details, Network tab (latency), System logs, Security, Terminal, Host backup, Audit, Apps | **local node only** for now - shows *"not available for this node yet"* (HTTP 501) |

## Failure behaviour

* **Node offline** (not a quorum member, no TCP answer): `503`, UI banner
  *Node offline – Daten derzeit nicht verfügbar*. Other nodes and the local dashboard are
  unaffected. If a recent answer is cached (< 15 min) it is shown instead and marked with
  `X-ProxMenux-Stale`/`X-ProxMenux-Cached-At`; the VM list marks such rows.
* **TLS / token / permission problems** are `502` (never `401`/`403`, so the browser session is
  not dropped) with a specific code (`node_tls`, `node_auth`, `node_forbidden`), shown as a
  warning banner.
* **Timeouts** (`3 s` connect, `8 s` read, one retry for GET) → `504`. After 3 consecutive
  failures a node is skipped for 5 s … 60 s (circuit breaker) so a dead node cannot slow the
  dashboard.
* **No quorum**: reported in the cluster status; reads keep working per node.
* **Node removed from the cluster**: disappears at the next discovery; requests for it get `403`.
* **Central connection lost** (`pvesh` fails): last known node list is kept, the error is shown
  under *Last error*; the local dashboard keeps working.
* Different PVE versions: handlers only read documented fields and default missing ones.

## Security assessment

| Topic | Measure |
| --- | --- |
| Transport | HTTPS only, certificate verified (cluster CA / pinned SHA-256 / system store) **with hostname/IP check**; no insecure mode, no fallback; missing CA/fingerprint = no connection. Redirects and environment proxies are disabled. |
| Target restriction (SSRF) | Only addresses from the cluster registry or validated overrides; all must be internal; node names from clients are matched against the registry and never used to build URLs. |
| Secrets | Token secret Fernet-encrypted at rest (`cluster.key`, 0600), write-only API, never in responses, logs or the frontend. Token should be read-only (`PVEAuditor`), privilege-separated. |
| Authorisation | Server-side on every request; deny by default for unknown routes on other nodes (`501`); node access (groups + per-user allow/deny); guest routes also check the node that hosts the vmid (IDOR); unknown and forbidden nodes are indistinguishable (`403`). |
| Privilege escalation | rbac scope is checked before any remote call; remote mutations only for allow-listed operations, only with the admin switch *and* the token privilege; Task IDs validated. |
| Abuse | Per-user rate limits (reads 600/min, writes 30/min, admin actions 20/min), bounded caches and fan-out, circuit breaker. |
| Audit | `cluster-audit.log` (JSON lines): denied node/guest access, remote actions with result, discovery, tests, settings changes (key names only). |
| Residual risk | A compromised ProxMenux host holds the token: use the least privilege roles above, restrict `:8006` to the cluster/management network, rotate the token periodically (`pveum user token remove` + add, then update the secret). Python/OpenSSL strict validation may reject the PVE CA - use `fingerprint` mode then. |

## Troubleshooting

| Symptom in *Test connections* | Meaning / fix |
| --- | --- |
| TLS certificate could not be verified | wrong CA file, node certificate replaced, address not in the certificate SAN → check the CA path, or use `fingerprint` mode |
| API token rejected | wrong ID/secret, token expired or removed; re-create and re-enter the secret |
| API token lacks the required permissions | add `PVEAuditor` for the **token** (privilege separation) |
| Node address is not an internal address | the cluster reports a public address; set an internal override or fix the corosync address |
| Node offline | not a quorum member / unreachable on :8006 |
