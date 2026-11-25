"use client"

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react"
import { fetchApi } from "./api-config"
import { getSelectedNode, storeSelectedNode } from "./api-config"

export interface ClusterNode {
  name: string
  node_id?: number | null
  local: boolean
  online: boolean
  status: "online" | "offline" | "degraded"
  cluster?: string | null
  pve_version?: string | null
  api_status: string
  api_error?: string | null
  cpu?: number | null
  maxcpu?: number | null
  mem?: number | null
  maxmem?: number | null
  disk?: number | null
  maxdisk?: number | null
  uptime?: number | null
  last_seen?: number | null
  last_checked?: number | null
  ip?: string
}

export interface ClusterSummary {
  name: string | null
  quorate: boolean | null
  standalone: boolean
  node_count: number
  online: number
  offline: number
}

interface NodesResponse {
  success: boolean
  enabled: boolean
  cluster: ClusterSummary
  discovery: { enabled: boolean; last_sync: number | null; interval: number }
  local_node: string
  default_node: string | null
  nodes: ClusterNode[]
}

interface NodeContextValue {
  nodes: ClusterNode[]
  cluster: ClusterSummary | null
  localNode: string | null
  selected: string | null
  selectedInfo: ClusterNode | null
  /** More than one node is visible to this user: show selector and node column. */
  multiNode: boolean
  isRemote: boolean
  isOffline: boolean
  selectNode: (name: string) => void
  refresh: () => Promise<void>
}

const NodeContext = createContext<NodeContextValue>({
  nodes: [],
  cluster: null,
  localNode: null,
  selected: null,
  selectedInfo: null,
  multiNode: false,
  isRemote: false,
  isOffline: false,
  selectNode: () => {},
  refresh: async () => {},
})

const POLL_MS = 15000

/**
 * Loads the nodes this user may see and owns the selected node. The selection
 * is kept in localStorage so a reload keeps it, and it survives token refresh:
 * switching nodes never touches the login session.
 */
export function NodeProvider({ children }: { children: ReactNode }) {
  const [data, setData] = useState<NodesResponse | null>(null)
  const [selected, setSelected] = useState<string | null>(() => getSelectedNode())
  const selectedRef = useRef(selected)
  selectedRef.current = selected

  const refresh = useCallback(async () => {
    try {
      const res = await fetchApi<NodesResponse>("/api/cluster/nodes")
      setData(res)
      const names = res.nodes.map((n) => n.name)
      const current = selectedRef.current
      // Stored node vanished (removed from the cluster) or is no longer permitted.
      if (!current || !names.includes(current)) {
        const fallback = res.default_node && names.includes(res.default_node) ? res.default_node : names[0] ?? null
        if (fallback !== current) {
          selectedRef.current = fallback
          setSelected(fallback)
          storeSelectedNode(fallback)
        }
      }
    } catch {
      // Keep the last known list: a failing poll must not blank the selector.
    }
  }, [])

  useEffect(() => {
    void refresh()
    const id = setInterval(() => {
      if (document.visibilityState === "visible") void refresh()
    }, POLL_MS)
    return () => clearInterval(id)
  }, [refresh])

  const selectNode = useCallback((name: string) => {
    selectedRef.current = name
    setSelected(name)
    storeSelectedNode(name)
  }, [])

  const value = useMemo<NodeContextValue>(() => {
    const nodes = data?.nodes ?? []
    const info = nodes.find((n) => n.name === selected) ?? null
    const localNode = data?.local_node ?? null
    return {
      nodes,
      cluster: data?.cluster ?? null,
      localNode,
      selected,
      selectedInfo: info,
      multiNode: !!data?.enabled && nodes.length > 1,
      isRemote: !!selected && !!localNode && selected !== localNode,
      isOffline: info ? info.status === "offline" : false,
      selectNode,
      refresh,
    }
  }, [data, selected, selectNode, refresh])

  return <NodeContext.Provider value={value}>{children}</NodeContext.Provider>
}

export function useNode() {
  return useContext(NodeContext)
}
