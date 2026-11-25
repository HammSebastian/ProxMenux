/**
 * API Configuration for ProxMenux Monitor
 * Handles API URL generation with automatic proxy detection
 */
// Resolve wording only for a generic transport failure. Normal responses and
// backend error payloads keep the transport free of locale-loading work.
async function apiFailure(...args: Parameters<typeof import("./api-errors").apiFailure>): Promise<string> {
  const messages = await import("./api-errors")
  return messages.apiFailure(...args)
}

// ---------------------------------------------------------------------------
// Multi-node selection. Lives in this module on purpose: the transport must
// stay free of imports (see tests/test_api_import_boundaries.cjs).
//
// The browser only sends the node NAME; the backend resolves it against its
// own registry and authorises it on every request - nothing here is trusted.
// ---------------------------------------------------------------------------

export const NODE_STORAGE_KEY = "proxmenux-selected-node"
export const NODE_HEADER = "X-ProxMenux-Node"
export const NODE_CHANGED_EVENT = "proxmenux-node-changed"

// Instance-level endpoints (they configure ProxMenux itself): never node-routed.
// Keep in sync with GLOBAL_PREFIXES in AppImage/scripts/cluster_gateway.py.
const GLOBAL_PREFIXES = [
  "/api/auth/",
  "/api/cluster/",
  "/api/notifications/",
  "/api/proxmenux/",
  "/api/platform",
  "/api/monitor-links",
  "/api/apps/",
  "/api/updates/",
  "/api/lxc-updates/",
  "/api/health/settings",
  "/api/health/thresholds",
  "/api/health/disk-exclusions",
  "/api/health/storage-exclusions",
  "/api/health/interface-exclusions",
  "/api/health/dismissed",
  "/api/health/acknowledge",
  "/api/health/un-acknowledge",
  "/api/health/disks",
  "/api/health/interfaces",
  "/api/health/remote-storages",
]

const NODE_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/
const GUEST_PATH = /^\/api\/(?:vms|lxc)\/(\d+)(?:[/?]|$)/

// vmid -> hosting node, filled by the guest list. Guest requests are routed to
// the node that really hosts the guest, whatever node is selected.
const guestNodes = new Map<number, string>()

export function getSelectedNode(): string | null {
  if (typeof window === "undefined") return null
  try {
    const v = window.localStorage.getItem(NODE_STORAGE_KEY)
    return v && NODE_NAME.test(v) ? v : null
  } catch {
    return null
  }
}

export function storeSelectedNode(name: string | null): void {
  if (typeof window === "undefined") return
  try {
    if (name) window.localStorage.setItem(NODE_STORAGE_KEY, name)
    else window.localStorage.removeItem(NODE_STORAGE_KEY)
  } catch {
    // private mode: selection only lives in React state
  }
  window.dispatchEvent(new CustomEvent(NODE_CHANGED_EVENT, { detail: name }))
}

export function registerGuestNodes(guests: Array<{ vmid: number; node?: string }>): void {
  for (const g of guests) {
    if (g.node && NODE_NAME.test(g.node)) guestNodes.set(Number(g.vmid), g.node)
  }
}

export function isGlobalEndpoint(endpoint: string): boolean {
  return GLOBAL_PREFIXES.some((p) => endpoint.startsWith(p))
}

/** Node header for one request, or {} when it must not be node-routed. */
export function nodeHeadersFor(endpoint: string): Record<string, string> {
  if (isGlobalEndpoint(endpoint)) return {}
  const guest = GUEST_PATH.exec(endpoint)
  const node = (guest && guestNodes.get(Number(guest[1]))) || getSelectedNode()
  return node ? { [NODE_HEADER]: node } : {}
}

/**
 * API Server Port Configuration
 * Default: 8008 (production)
 * Can be changed to 8009 for beta testing
 * This can also be set via NEXT_PUBLIC_API_PORT environment variable
 */
export const API_PORT = process.env.NEXT_PUBLIC_API_PORT || "8008"

/**
 * Gets the base URL for API calls
 * Automatically detects if running behind a proxy by checking if we're on a standard port
 *
 * @returns Base URL for API endpoints
 */
export function getApiBaseUrl(): string {
  if (typeof window === "undefined") {
    return ""
  }

  const { protocol, hostname, port } = window.location

  // If accessing via standard ports (80/443) or no port, assume we're behind a proxy
  // In this case, use relative URLs so the proxy handles routing
  const isStandardPort = port === "" || port === "80" || port === "443"

  if (isStandardPort) {
    return ""
  } else {
    return `${protocol}//${hostname}:${API_PORT}`
  }
}

/**
 * Constructs a full API URL
 *
 * @param endpoint - API endpoint path (e.g., '/api/system')
 * @returns Full API URL
 */
export function getApiUrl(endpoint: string): string {
  const baseUrl = getApiBaseUrl()

  // Ensure endpoint starts with /
  const normalizedEndpoint = endpoint.startsWith("/") ? endpoint : `/${endpoint}`

  return `${baseUrl}${normalizedEndpoint}`
}

/**
 * Gets the JWT token from localStorage
 *
 * @returns JWT token or null if not authenticated
 */
export function getAuthToken(): string | null {
  if (typeof window === "undefined") {
    return null
  }
  return localStorage.getItem("proxmenux-auth-token")
}

/**
 * Fetches data from an API endpoint with error handling
 *
 * @param endpoint - API endpoint path
 * @param options - Fetch options
 * @returns Promise with the response data
 */
export async function fetchApi<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = getApiUrl(endpoint)

  const token = getAuthToken()

  // Multi-node: tell the backend which node this request is for. An explicit
  // header from the caller wins; instance-level endpoints are never routed.
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...nodeHeadersFor(endpoint),
    ...(options?.headers as Record<string, string>),
  }

  if (token) {
    headers["Authorization"] = `Bearer ${token}`
  }

  const response = await fetch(url, {
    ...options,
    headers,
    cache: "no-store",
  })

    if (!response.ok) {
      if (response.status === 401) {
        // Token is missing, expired, or signed under a previous JWT_SECRET
        // (rotated per-install). Drop the stale token and force a single
        // reload so the page-level auth gate (`app/page.tsx`) can render
        // <Login> instead of cascading 401s from every authenticated
        // component on mount.
        //
        // Only react when we actually had a token to invalidate. A 401
        // without any token in localStorage means the caller is the
        // Login screen itself, or a leftover fetch from a recently
        // unmounted Dashboard — reloading there does nothing but waste
        // the user's keystrokes and can leave the cascade flag set
        // forever, swallowing the very 401 that we'd want to recover
        // from after a successful re-login. The fix: bail out early
        // if we have no token to invalidate.
        if (typeof window !== "undefined") {
          let hadToken = false
          try {
            hadToken = !!localStorage.getItem("proxmenux-auth-token")
          } catch {
            // private browsing — assume yes so we attempt recovery.
            hadToken = true
          }
          if (!hadToken) {
            throw new Error(await apiFailure("unauthorized", { endpoint }))
          }
          try {
            localStorage.removeItem("proxmenux-auth-token")
          } catch {
            // localStorage might be unavailable in private browsing — ignore.
          }
          try {
            if (!sessionStorage.getItem("proxmenux-auth-401-handled")) {
              sessionStorage.setItem("proxmenux-auth-401-handled", "1")
              window.location.reload()
            }
          } catch {
            // sessionStorage unavailable — fall back to a plain reload.
            window.location.reload()
          }
        }
        throw new Error(await apiFailure("unauthorized", { endpoint }))
      }
      // Try to surface the backend's JSON error payload instead of a
      // bare `500 INTERNAL SERVER ERROR`. The Flask routes consistently
      // return `{error: "..."}` on failure (e.g. /api/vms/<id>/control
      // includes the pvesh stderr — telling the user "no space left on
      // device" is infinitely more useful than the raw status text).
      //
      // We also attach the FULL parsed JSON body to the thrown Error
      // as `.body` so callers that want the optional `details` /
      // `suggestion` fields (e.g. /api/node/metrics) can render them
      // without re-fetching. Callers that just read `err.message`
      // keep working exactly as before.
      try {
        const ct = response.headers.get("content-type") || ""
        if (ct.includes("application/json")) {
          const body = await response.json()
          const detail =
            (body && (body.error || body.message)) || ""
          if (detail) {
            const e: Error & { body?: unknown; status?: number } = new Error(detail)
            e.body = body
            e.status = response.status
            throw e
          }
        }
      } catch (parseErr) {
        // Backend-supplied detail (the explicit `throw new Error(detail)`
        // above) MUST propagate so the UI shows "path does not exist…"
        // instead of the generic "API request failed: 400 BAD REQUEST".
        // Only swallow when the JSON itself failed to parse — that's a
        // real SyntaxError and falling through to the generic message
        // is the right behaviour there.
        if (!(parseErr instanceof SyntaxError)) {
          throw parseErr
        }
      }
      throw new Error(await apiFailure("http", { status: response.status, statusText: response.statusText }))
    }

    // Check content type to ensure we're getting JSON
    const contentType = response.headers.get("content-type")
    if (!contentType || !contentType.includes("application/json")) {
      const text = await response.text()
      console.error("fetchApi: Expected JSON but got:", contentType, "- Body preview:", text.substring(0, 200))
      throw new Error(await apiFailure("unexpectedContentType", { contentType: contentType || await apiFailure("unknownContentType") }))
    }

    try {
      return await response.json()
    } catch (jsonError) {
      console.error("fetchApi: JSON parse error for", endpoint, "-", jsonError)
      throw new Error(await apiFailure("invalidJson", { endpoint }))
    }
}
