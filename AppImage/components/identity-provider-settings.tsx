"use client"

import { useCallback, useEffect, useState } from "react"
import { AlertCircle, CheckCircle, KeyRound, Loader2 } from "lucide-react"
import { Button } from "./ui/button"
import { Input } from "./ui/input"
import { Label } from "./ui/label"
import { Switch } from "./ui/switch"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card"
import { fetchApi } from "../lib/api-config"
import { useT } from "../lib/i18n/provider"

interface LastStatus {
  ok: boolean
  message: string
  kind: string
  checked_at: number
}

interface IdpSettings {
  enabled: boolean
  provider_name: string
  issuer: string
  client_id: string
  client_secret_set: boolean
  scopes: string
  group_claim: string
  admin_group: string
  user_group: string
  readonly_group: string
  auto_provision: boolean
  default_role: string
  allow_local_login: boolean
  oidc_logout: boolean
  session_timeout_minutes: number
  public_url: string
  redirect_uri: string
  last_status: LastStatus | null
}

interface IdpUser {
  id: number
  username: string
  email: string | null
  display_name: string | null
  role: string
  groups: string[]
  disabled: boolean
  last_login: number | null
}

/**
 * Settings → Authentication → Identity Provider (OpenID Connect / Authentik).
 * Admin-only: the backend enforces this; the card simply shows the error if a
 * non-admin session opens it. The client secret is write-only — the API never
 * returns it, an empty field keeps the stored value.
 */
export function IdentityProviderSettings() {
  const t = useT()
  const [available, setAvailable] = useState(true)
  const [unavailableReason, setUnavailableReason] = useState("")
  const [form, setForm] = useState<IdpSettings | null>(null)
  const [secret, setSecret] = useState("")
  const [busy, setBusy] = useState(false)
  const [errors, setErrors] = useState<string[]>([])
  const [notice, setNotice] = useState("")
  const [warnings, setWarnings] = useState<string[]>([])
  const [discovery, setDiscovery] = useState<Record<string, unknown> | null>(null)
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null)
  const [users, setUsers] = useState<IdpUser[]>([])
  const [forbidden, setForbidden] = useState(false)

  const loadUsers = useCallback(async () => {
    try {
      const data = await fetchApi<{ users: IdpUser[] }>("/api/auth/oidc/users")
      setUsers(data.users || [])
    } catch {
      setUsers([])
    }
  }, [])

  const load = useCallback(async () => {
    try {
      const data = await fetchApi<{
        available: boolean
        unavailable_reason: string
        settings: IdpSettings
        warnings: string[]
      }>("/api/auth/oidc/settings")
      setAvailable(data.available)
      setUnavailableReason(data.unavailable_reason)
      const s = data.settings
      if (!s.public_url && typeof window !== "undefined") s.public_url = window.location.origin
      setForm(s)
      setWarnings(data.warnings || [])
      void loadUsers()
    } catch {
      setForbidden(true)
    }
  }, [loadUsers])

  useEffect(() => {
    void load()
  }, [load])

  if (forbidden || !form) {
    return null // not an administrator (or still loading): nothing to show
  }

  const set = <K extends keyof IdpSettings>(key: K, value: IdpSettings[K]) =>
    setForm((f) => (f ? { ...f, [key]: value } : f))

  const redirectUri = `${(form.public_url || "").replace(/\/+$/, "")}/api/auth/oidc/callback`

  const save = async () => {
    setBusy(true)
    setErrors([])
    setNotice("")
    try {
      const body: Record<string, unknown> = {
        enabled: form.enabled,
        provider_name: form.provider_name,
        issuer: form.issuer,
        client_id: form.client_id,
        scopes: form.scopes,
        group_claim: form.group_claim,
        admin_group: form.admin_group,
        user_group: form.user_group,
        readonly_group: form.readonly_group,
        auto_provision: form.auto_provision,
        default_role: form.default_role,
        allow_local_login: form.allow_local_login,
        oidc_logout: form.oidc_logout,
        session_timeout_minutes: Number(form.session_timeout_minutes),
        public_url: form.public_url,
      }
      if (secret) body.client_secret = secret
      const data = await fetchApi<{ settings: IdpSettings; warnings: string[] }>("/api/auth/oidc/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      })
      setForm(data.settings)
      setWarnings(data.warnings || [])
      setSecret("")
      setNotice(t("idp.saved"))
    } catch (err) {
      const e = err as { body?: { errors?: string[] }; message?: string }
      setErrors(e.body?.errors?.length ? e.body.errors : [e.message || t("idp.saveFailed")])
    } finally {
      setBusy(false)
    }
  }

  const runTest = async () => {
    setBusy(true)
    setTestResult(null)
    setDiscovery(null)
    try {
      const data = await fetchApi<{
        ok: boolean
        message: string
        discovery: Record<string, unknown> | null
        settings: IdpSettings
      }>("/api/auth/oidc/test", { method: "POST" })
      setTestResult({ ok: data.ok, message: data.message })
      setDiscovery(data.discovery)
      setForm((f) => (f ? { ...f, last_status: data.settings.last_status } : f))
    } catch (err) {
      setTestResult({ ok: false, message: (err as Error).message })
    } finally {
      setBusy(false)
    }
  }

  const patchUser = async (u: IdpUser, disabled: boolean) => {
    await fetchApi(`/api/auth/oidc/users/${u.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ disabled }),
    })
    void loadUsers()
  }

  const removeUser = async (u: IdpUser) => {
    await fetchApi(`/api/auth/oidc/users/${u.id}`, { method: "DELETE" })
    void loadUsers()
  }

  const field = (id: string, label: string, value: string, onChange: (v: string) => void, extra?: {
    type?: string
    placeholder?: string
    hint?: string
  }) => (
    <div className="space-y-1">
      <Label htmlFor={id} className="text-sm">
        {label}
      </Label>
      <Input
        id={id}
        type={extra?.type || "text"}
        value={value}
        placeholder={extra?.placeholder}
        onChange={(e) => onChange(e.target.value)}
        autoComplete="off"
        className="text-base"
      />
      {extra?.hint && <p className="text-xs text-muted-foreground">{extra.hint}</p>}
    </div>
  )

  const toggle = (id: string, label: string, value: boolean, onChange: (v: boolean) => void, hint?: string) => (
    <div className="flex items-start justify-between gap-4">
      <div>
        <Label htmlFor={id} className="text-sm">
          {label}
        </Label>
        {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
      </div>
      <Switch id={id} checked={value} onCheckedChange={onChange} />
    </div>
  )

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <KeyRound className="h-5 w-5 text-blue-500" />
          <CardTitle>{t("idp.title")}</CardTitle>
        </div>
        <CardDescription>{t("idp.description")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!available && (
          <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-3 text-sm text-yellow-600">
            {t("idp.unavailable")}: {unavailableReason}
          </div>
        )}
        {errors.length > 0 && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 flex items-start gap-2">
            <AlertCircle className="h-5 w-5 text-red-500 flex-shrink-0 mt-0.5" />
            <ul className="text-sm text-red-500 list-disc pl-4">
              {errors.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          </div>
        )}
        {notice && (
          <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-3 flex items-center gap-2 text-sm text-green-500">
            <CheckCircle className="h-5 w-5" /> {notice}
          </div>
        )}
        {warnings.map((w) => (
          <p key={w} className="text-xs text-yellow-600">
            {w}
          </p>
        ))}

        {toggle("idp-enabled", t("idp.enable"), form.enabled, (v) => set("enabled", v), t("idp.enableHint"))}

        <div className="grid gap-4 md:grid-cols-2">
          {field("idp-name", t("idp.providerName"), form.provider_name, (v) => set("provider_name", v))}
          {field("idp-issuer", t("idp.issuer"), form.issuer, (v) => set("issuer", v), {
            placeholder: "https://auth.example.com/application/o/proxmenux/",
          })}
          {field("idp-client-id", t("idp.clientId"), form.client_id, (v) => set("client_id", v))}
          {field("idp-secret", t("idp.clientSecret"), secret, setSecret, {
            type: "password",
            placeholder: form.client_secret_set ? "••••••••" : "",
            hint: form.client_secret_set ? t("idp.secretKeep") : t("idp.secretRequired"),
          })}
          {field("idp-public", t("idp.publicUrl"), form.public_url, (v) => set("public_url", v), {
            hint: `${t("idp.redirectUri")}: ${redirectUri}`,
          })}
          {field("idp-scopes", t("idp.scopes"), form.scopes, (v) => set("scopes", v))}
          {field("idp-group-claim", t("idp.groupClaim"), form.group_claim, (v) => set("group_claim", v))}
          {field("idp-timeout", t("idp.sessionTimeout"), String(form.session_timeout_minutes),
            (v) => set("session_timeout_minutes", Number(v.replace(/\D/g, "")) || 0), {
            hint: t("idp.sessionTimeoutHint"),
          })}
        </div>

        <h3 className="text-sm font-semibold pt-2">{t("idp.groupMapping")}</h3>
        <p className="text-xs text-muted-foreground">{t("idp.groupMappingHint")}</p>
        <div className="grid gap-4 md:grid-cols-3">
          {field("idp-admin", t("idp.adminGroup"), form.admin_group, (v) => set("admin_group", v))}
          {field("idp-user", t("idp.userGroup"), form.user_group, (v) => set("user_group", v))}
          {field("idp-ro", t("idp.readonlyGroup"), form.readonly_group, (v) => set("readonly_group", v))}
        </div>

        <div className="space-y-1">
          <Label htmlFor="idp-default-role" className="text-sm">
            {t("idp.defaultRole")}
          </Label>
          <select
            id="idp-default-role"
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-base"
            value={form.default_role}
            onChange={(e) => set("default_role", e.target.value)}
          >
            <option value="none">{t("idp.roleNone")}</option>
            <option value="readonly">{t("idp.roleReadonly")}</option>
            <option value="user">{t("idp.roleUser")}</option>
            <option value="admin">{t("idp.roleAdmin")}</option>
          </select>
          <p className="text-xs text-muted-foreground">{t("idp.defaultRoleHint")}</p>
        </div>

        {toggle("idp-provision", t("idp.autoProvision"), form.auto_provision, (v) => set("auto_provision", v),
          t("idp.autoProvisionHint"))}
        {toggle("idp-local", t("idp.allowLocal"), form.allow_local_login, (v) => set("allow_local_login", v),
          t("idp.allowLocalHint"))}
        {toggle("idp-logout", t("idp.oidcLogout"), form.oidc_logout, (v) => set("oidc_logout", v),
          t("idp.oidcLogoutHint"))}

        <div className="flex flex-wrap gap-2 pt-2">
          <Button onClick={save} disabled={busy || !available} className="bg-blue-500 hover:bg-blue-600">
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : t("idp.save")}
          </Button>
          <Button variant="outline" onClick={runTest} disabled={busy || !available}>
            {t("idp.testConnection")}
          </Button>
        </div>

        {testResult && (
          <div className={`text-sm ${testResult.ok ? "text-green-500" : "text-red-500"}`}>
            {testResult.ok ? t("idp.testOk") : t("idp.testFailed")}: {testResult.message}
          </div>
        )}
        {form.last_status && (
          <p className="text-xs text-muted-foreground">
            {t("idp.lastStatus")}: {form.last_status.ok ? t("idp.statusOk") : t("idp.statusFailed")} —{" "}
            {form.last_status.message} ({new Date(form.last_status.checked_at * 1000).toLocaleString()})
          </p>
        )}
        {discovery && (
          <details className="text-xs">
            <summary className="cursor-pointer">{t("idp.discoveryDocument")}</summary>
            <pre className="mt-2 overflow-auto rounded bg-muted p-2">{JSON.stringify(discovery, null, 2)}</pre>
          </details>
        )}

        <h3 className="text-sm font-semibold pt-2">{t("idp.users")}</h3>
        {users.length === 0 ? (
          <p className="text-xs text-muted-foreground">{t("idp.noUsers")}</p>
        ) : (
          <div className="space-y-2">
            {users.map((u) => (
              <div key={u.id} className="flex flex-wrap items-center justify-between gap-2 rounded border p-2 text-sm">
                <div>
                  <span className="font-medium">{u.display_name || u.username}</span>{" "}
                  <span className="text-muted-foreground">
                    ({u.username}
                    {u.email ? `, ${u.email}` : ""}) — {u.role}
                    {u.disabled ? ` — ${t("idp.disabled")}` : ""}
                  </span>
                </div>
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" onClick={() => patchUser(u, !u.disabled)}>
                    {u.disabled ? t("idp.enableUser") : t("idp.disableUser")}
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => removeUser(u)}>
                    {t("idp.deleteUser")}
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
