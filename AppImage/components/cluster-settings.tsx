"use client"

import { useCallback, useEffect, useState } from "react"
import { Loader2, RefreshCw, ShieldCheck } from "lucide-react"
import { Badge } from "./ui/badge"
import { Button } from "./ui/button"
import { Input } from "./ui/input"
import { Label } from "./ui/label"
import { Switch } from "./ui/switch"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card"
import { fetchApi } from "../lib/api-config"
import { useT } from "../lib/i18n/provider"
import type { ClusterNode, ClusterSummary } from "../lib/node-context"

interface Perms {
  role_nodes: { user: string[]; readonly: string[] }
  user_rules: Record<string, { allow: string[]; deny: string[] }>
}

interface Settings {
  enabled: boolean
  discovery_enabled: boolean
  discovery_interval: number
  tls_mode: "ca" | "fingerprint" | "system"
  ca_file: string
  api_port: number
  token_id: string
  token_secret_set: boolean
  fingerprints: Record<string, string>
  allow_remote_control: boolean
  permissions: Perms
}

interface Discovery {
  enabled: boolean
  interval: number
  last_sync: number | null
  last_error: string | null
  running: boolean
}

interface StepResult {
  step: string
  ok: boolean
  code?: string
  message?: string
  ms?: number
}
interface TestResult {
  node: string
  ok: boolean
  steps: StepResult[]
  version?: string | null
  can_control?: boolean
  error?: string
}
interface OidcUser {
  id: number
  username: string
  role: string
}
interface AuditEvent {
  ts: string
  event: string
  user?: string
  node?: string
  path?: string
}

const statusClass: Record<string, string> = {
  online: "bg-green-500/10 text-green-500 border-green-500/20",
  degraded: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  offline: "bg-red-500/10 text-red-500 border-red-500/20",
}

const fmtTime = (ts: number | null | undefined) => (ts ? new Date(ts * 1000).toLocaleString() : "–")

/**
 * Settings → Cluster Management. Administrator only (the backend enforces it;
 * non-admins just get nothing rendered). The API-token secret is write-only.
 */
export function ClusterSettings() {
  const t = useT()
  const [settings, setSettings] = useState<Settings | null>(null)
  const [cluster, setCluster] = useState<ClusterSummary | null>(null)
  const [disc, setDisc] = useState<Discovery | null>(null)
  const [nodes, setNodes] = useState<ClusterNode[]>([])
  const [forbidden, setForbidden] = useState(false)
  const [secret, setSecret] = useState("")
  const [busy, setBusy] = useState("")
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null)
  const [tests, setTests] = useState<Record<string, TestResult>>({})
  const [users, setUsers] = useState<OidcUser[]>([])
  const [audit, setAudit] = useState<AuditEvent[]>([])

  const load = useCallback(async () => {
    try {
      const d = await fetchApi<{ settings: Settings; cluster: ClusterSummary; discovery: Discovery; nodes: ClusterNode[] }>(
        "/api/cluster/settings",
      )
      setSettings(d.settings)
      setCluster(d.cluster)
      setDisc(d.discovery)
      setNodes(d.nodes)
      fetchApi<{ users: OidcUser[] }>("/api/auth/oidc/users").then((u) => setUsers(u.users || [])).catch(() => setUsers([]))
      fetchApi<{ events: AuditEvent[] }>("/api/cluster/audit?limit=15").then((a) => setAudit(a.events || [])).catch(() => {})
    } catch {
      setForbidden(true)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  if (forbidden || !settings) return null

  const patch = <K extends keyof Settings>(key: K, value: Settings[K]) => setSettings((s) => (s ? { ...s, [key]: value } : s))
  const flash = (ok: boolean, text: string) => setMessage({ ok, text })

  const save = async () => {
    setBusy("save")
    try {
      const body: Record<string, unknown> = {
        enabled: settings.enabled,
        discovery_enabled: settings.discovery_enabled,
        discovery_interval: Number(settings.discovery_interval),
        tls_mode: settings.tls_mode,
        ca_file: settings.ca_file,
        api_port: Number(settings.api_port),
        token_id: settings.token_id,
        fingerprints: settings.fingerprints,
        allow_remote_control: settings.allow_remote_control,
        permissions: settings.permissions,
      }
      if (secret) body.token_secret = secret
      const r = await fetchApi<{ settings: Settings }>("/api/cluster/settings", { method: "PUT", body: JSON.stringify(body) })
      setSettings(r.settings)
      setSecret("")
      flash(true, t("cluster.settings.saved"))
    } catch (e) {
      flash(false, e instanceof Error ? e.message : t("cluster.settings.saveFailed"))
    } finally {
      setBusy("")
    }
  }

  const discover = async () => {
    setBusy("discover")
    try {
      const r = await fetchApi<{ success: boolean; cluster: ClusterSummary; discovery: Discovery; nodes: ClusterNode[]; result: { error?: string } }>(
        "/api/cluster/discover",
        { method: "POST" },
      )
      setCluster(r.cluster)
      setDisc(r.discovery)
      setNodes(r.nodes)
      flash(r.success, r.success ? t("cluster.discovery.done") : r.result?.error || t("cluster.discovery.failed"))
    } catch (e) {
      flash(false, e instanceof Error ? e.message : t("cluster.discovery.failed"))
    } finally {
      setBusy("")
    }
  }

  const runTest = async (node?: string) => {
    setBusy(`test:${node ?? "*"}`)
    try {
      const r = await fetchApi<{ results: TestResult[] }>("/api/cluster/test", {
        method: "POST",
        body: JSON.stringify(node ? { node } : {}),
      })
      setTests((prev) => ({ ...prev, ...Object.fromEntries(r.results.map((x) => [x.node, x])) }))
      void load()
    } catch (e) {
      flash(false, e instanceof Error ? e.message : t("cluster.test.failed"))
    } finally {
      setBusy("")
    }
  }

  const names = nodes.map((n) => n.name)
  const roleList = (role: "user" | "readonly") => settings.permissions.role_nodes[role] || []
  const toggleRole = (role: "user" | "readonly", node: string) => {
    const cur = roleList(role)
    const next = cur.includes(node) ? cur.filter((x) => x !== node) : [...cur, node]
    patch("permissions", { ...settings.permissions, role_nodes: { ...settings.permissions.role_nodes, [role]: next } })
  }
  const userNodeState = (uid: number, node: string): "inherit" | "allow" | "deny" => {
    const r = settings.permissions.user_rules[String(uid)]
    return r?.deny.includes(node) ? "deny" : r?.allow.includes(node) ? "allow" : "inherit"
  }
  const setUserNode = (uid: number, node: string, state: "inherit" | "allow" | "deny") => {
    const rules = { ...settings.permissions.user_rules }
    const cur = rules[String(uid)] || { allow: [], deny: [] }
    const allow = cur.allow.filter((n) => n !== node)
    const deny = cur.deny.filter((n) => n !== node)
    if (state === "allow") allow.push(node)
    if (state === "deny") deny.push(node)
    if (allow.length || deny.length) rules[String(uid)] = { allow, deny }
    else delete rules[String(uid)]
    patch("permissions", { ...settings.permissions, user_rules: rules })
  }

  return (
    <Card data-testid="cluster-settings">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5" />
          {t("cluster.settings.title")}
        </CardTitle>
        <CardDescription>{t("cluster.settings.description")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {message && (
          <p role="status" className={`text-sm ${message.ok ? "text-green-500" : "text-red-500"}`}>
            {message.text}
          </p>
        )}

        {/* Status */}
        <section className="space-y-2">
          <h3 className="font-medium">{t("cluster.status.title")}</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
            <div><span className="text-muted-foreground">{t("cluster.status.name")}</span><div>{cluster?.name ?? t("cluster.status.standalone")}</div></div>
            <div><span className="text-muted-foreground">{t("cluster.status.quorum")}</span><div>{cluster?.quorate == null ? "–" : cluster.quorate ? t("cluster.status.quorate") : t("cluster.status.noQuorum")}</div></div>
            <div><span className="text-muted-foreground">{t("cluster.status.nodes")}</span><div>{cluster?.node_count ?? 0} ({cluster?.online ?? 0} {t("cluster.status.online")}, {cluster?.offline ?? 0} {t("cluster.status.offline")})</div></div>
            <div><span className="text-muted-foreground">{t("cluster.discovery.lastSync")}</span><div>{fmtTime(disc?.last_sync)}</div></div>
            <div><span className="text-muted-foreground">{t("cluster.discovery.status")}</span><div>{disc?.running ? t("cluster.discovery.running") : disc?.enabled ? t("cluster.discovery.active") : t("cluster.discovery.disabled")}</div></div>
            <div className="col-span-2"><span className="text-muted-foreground">{t("cluster.discovery.lastError")}</span><div className={disc?.last_error ? "text-red-500" : ""}>{disc?.last_error || "–"}</div></div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" onClick={discover} disabled={!!busy}>
              {busy === "discover" ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-2" />}
              {t("cluster.discovery.now")}
            </Button>
            <Button variant="outline" size="sm" onClick={() => runTest()} disabled={!!busy}>
              {busy === "test:*" && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              {t("cluster.test.all")}
            </Button>
          </div>
        </section>

        {/* Nodes */}
        <section className="space-y-2">
          <h3 className="font-medium">{t("cluster.nodes.title")}</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-muted-foreground">
                  <th className="pr-3 py-1">{t("cluster.nodes.name")}</th>
                  <th className="pr-3">{t("cluster.nodes.address")}</th>
                  <th className="pr-3">{t("cluster.nodes.version")}</th>
                  <th className="pr-3">{t("cluster.nodes.state")}</th>
                  <th className="pr-3">{t("cluster.nodes.api")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {nodes.map((n) => {
                  const tr = tests[n.name]
                  return (
                    <tr key={n.name} className="border-t border-border align-top">
                      <td className="pr-3 py-2 font-medium">{n.name}{n.local ? ` (${t("cluster.selector.thisNode")})` : ""}</td>
                      <td className="pr-3">{n.ip ?? "–"}</td>
                      <td className="pr-3">{n.pve_version ?? "–"}</td>
                      <td className="pr-3"><Badge variant="outline" className={statusClass[n.status]}>{t(`cluster.status.${n.status}`)}</Badge></td>
                      <td className="pr-3">
                        {n.api_status === "ok" ? t("cluster.nodes.apiOk") : n.api_error || n.api_status}
                        {tr && (
                          <ul className="mt-1 text-xs space-y-0.5" data-testid={`test-${n.name}`}>
                            {tr.steps.map((s, i) => (
                              <li key={i} className={s.ok ? "text-green-500" : "text-red-500"}>
                                {s.ok ? "✓" : "✗"} {t(`cluster.test.steps.${s.step}`)}{s.message ? `: ${s.message}` : ""}
                              </li>
                            ))}
                            {tr.can_control != null && <li className="text-muted-foreground">{tr.can_control ? t("cluster.test.canControl") : t("cluster.test.readOnly")}</li>}
                          </ul>
                        )}
                      </td>
                      <td>
                        <Button variant="ghost" size="sm" onClick={() => runTest(n.name)} disabled={!!busy}>
                          {busy === `test:${n.name}` ? <Loader2 className="h-4 w-4 animate-spin" /> : t("cluster.test.one")}
                        </Button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </section>

        {/* Connection */}
        <section className="space-y-3">
          <h3 className="font-medium">{t("cluster.connection.title")}</h3>
          <div className="flex items-center justify-between">
            <Label>{t("cluster.connection.enabled")}</Label>
            <Switch checked={settings.enabled} onCheckedChange={(v) => patch("enabled", v)} />
          </div>
          <div className="flex items-center justify-between">
            <Label>{t("cluster.connection.autoDiscovery")}</Label>
            <Switch checked={settings.discovery_enabled} onCheckedChange={(v) => patch("discovery_enabled", v)} />
          </div>
          <div className="grid md:grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label>{t("cluster.connection.interval")}</Label>
              <Input type="number" min={15} max={3600} value={settings.discovery_interval} onChange={(e) => patch("discovery_interval", Number(e.target.value))} />
            </div>
            <div className="space-y-1">
              <Label>{t("cluster.connection.port")}</Label>
              <Input type="number" value={settings.api_port} onChange={(e) => patch("api_port", Number(e.target.value))} />
            </div>
            <div className="space-y-1">
              <Label>{t("cluster.connection.tokenId")}</Label>
              <Input placeholder="proxmenux@pve!monitor" value={settings.token_id} onChange={(e) => patch("token_id", e.target.value)} autoComplete="off" />
            </div>
            <div className="space-y-1">
              <Label>{t("cluster.connection.tokenSecret")}</Label>
              <Input
                type="password"
                autoComplete="new-password"
                placeholder={settings.token_secret_set ? t("cluster.connection.secretKept") : ""}
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label>{t("cluster.connection.tlsMode")}</Label>
              <select
                className="h-9 w-full rounded-md border border-input bg-transparent px-2 text-sm"
                value={settings.tls_mode}
                onChange={(e) => patch("tls_mode", e.target.value as Settings["tls_mode"])}
              >
                <option value="ca">{t("cluster.connection.tls.ca")}</option>
                <option value="fingerprint">{t("cluster.connection.tls.fingerprint")}</option>
                <option value="system">{t("cluster.connection.tls.system")}</option>
              </select>
            </div>
            {settings.tls_mode === "ca" && (
              <div className="space-y-1">
                <Label>{t("cluster.connection.caFile")}</Label>
                <Input value={settings.ca_file} onChange={(e) => patch("ca_file", e.target.value)} />
              </div>
            )}
          </div>
          {settings.tls_mode === "fingerprint" && (
            <div className="space-y-2">
              <Label>{t("cluster.connection.fingerprints")}</Label>
              {nodes.filter((n) => !n.local).map((n) => (
                <div key={n.name} className="flex items-center gap-2">
                  <span className="w-24 text-sm">{n.name}</span>
                  <Input
                    className="font-mono text-xs"
                    placeholder="AA:BB:…"
                    value={settings.fingerprints[n.name] ?? ""}
                    onChange={(e) => patch("fingerprints", { ...settings.fingerprints, [n.name]: e.target.value })}
                  />
                </div>
              ))}
              <p className="text-xs text-muted-foreground">{t("cluster.connection.fingerprintHint")}</p>
            </div>
          )}
          <div className="flex items-center justify-between">
            <div>
              <Label>{t("cluster.connection.remoteControl")}</Label>
              <p className="text-xs text-muted-foreground">{t("cluster.connection.remoteControlHint")}</p>
            </div>
            <Switch checked={settings.allow_remote_control} onCheckedChange={(v) => patch("allow_remote_control", v)} />
          </div>
        </section>

        {/* Permissions */}
        <section className="space-y-3">
          <h3 className="font-medium">{t("cluster.permissions.title")}</h3>
          <p className="text-sm text-muted-foreground">{t("cluster.permissions.description")}</p>
          {(["user", "readonly"] as const).map((role) => (
            <div key={role} className="space-y-1">
              <Label>{t(`cluster.permissions.role.${role}`)}</Label>
              <div className="flex flex-wrap gap-3 text-sm">
                {names.map((n) => (
                  <label key={n} className="inline-flex items-center gap-1">
                    <input
                      type="checkbox"
                      checked={roleList(role).includes(n) || roleList(role).includes("*") || (n === (nodes.find((x) => x.local)?.name) && roleList(role).includes("@local"))}
                      disabled={roleList(role).includes("*")}
                      onChange={() => {
                        const local = nodes.find((x) => x.local)?.name
                        // an inherited "@local" entry is made explicit before it can be unticked
                        if (n === local && roleList(role).includes("@local")) {
                          const next = roleList(role).filter((x) => x !== "@local")
                          patch("permissions", { ...settings.permissions, role_nodes: { ...settings.permissions.role_nodes, [role]: next } })
                        } else toggleRole(role, n)
                      }}
                    />
                    {n}
                  </label>
                ))}
              </div>
            </div>
          ))}
          <p className="text-xs text-muted-foreground">{t("cluster.permissions.adminNote")}</p>
          {users.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-muted-foreground">
                    <th className="pr-3 py-1">{t("cluster.permissions.user")}</th>
                    {names.map((n) => <th key={n} className="pr-3">{n}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id} className="border-t border-border">
                      <td className="pr-3 py-1">{u.username} <span className="text-xs text-muted-foreground">({u.role})</span></td>
                      {names.map((n) => (
                        <td key={n} className="pr-3">
                          <select
                            className="h-8 rounded-md border border-input bg-transparent px-1 text-xs"
                            value={userNodeState(u.id, n)}
                            onChange={(e) => setUserNode(u.id, n, e.target.value as "inherit" | "allow" | "deny")}
                            aria-label={`${u.username} ${n}`}
                          >
                            <option value="inherit">{t("cluster.permissions.inherit")}</option>
                            <option value="allow">{t("cluster.permissions.allow")}</option>
                            <option value="deny">{t("cluster.permissions.deny")}</option>
                          </select>
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <Button onClick={save} disabled={!!busy}>
          {busy === "save" && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
          {t("cluster.settings.save")}
        </Button>

        {/* Audit */}
        {audit.length > 0 && (
          <section className="space-y-1">
            <h3 className="font-medium">{t("cluster.audit.title")}</h3>
            <ul className="text-xs font-mono space-y-0.5">
              {audit.map((a, i) => (
                <li key={i}>{a.ts} {a.event} {a.user ?? ""} {a.node ?? ""} {a.path ?? ""}</li>
              ))}
            </ul>
          </section>
        )}
      </CardContent>
    </Card>
  )
}
