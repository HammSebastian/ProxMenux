"use client"

import { AlertTriangle, ServerOff } from "lucide-react"
import { Button } from "./ui/button"
import { useNode } from "../lib/node-context"
import { useT } from "../lib/i18n/provider"

/** Tabs whose data can be served for another node (see docs/multi-node). */
export const REMOTE_TABS = ["overview", "vms", "settings", "about", "profile", "admin"]

/** Banner under the header: selected node offline / API problem. */
export function NodeStatusBanner() {
  const t = useT()
  const { selectedInfo, isRemote } = useNode()
  if (!selectedInfo) return null
  if (selectedInfo.status === "offline") {
    return (
      <div role="alert" className="bg-red-500/10 border-b border-red-500/20 px-6 py-3" data-testid="node-offline-banner">
        <div className="container mx-auto flex items-center gap-2 text-red-500">
          <ServerOff className="h-5 w-5 shrink-0" />
          <span className="font-medium">{t("cluster.nodeOffline")}</span>
          <span className="text-sm text-red-500/80">({selectedInfo.name})</span>
        </div>
      </div>
    )
  }
  if (isRemote && selectedInfo.status === "degraded") {
    return (
      <div role="alert" className="bg-yellow-500/10 border-b border-yellow-500/20 px-6 py-3" data-testid="node-degraded-banner">
        <div className="container mx-auto flex items-center gap-2 text-yellow-600 dark:text-yellow-400">
          <AlertTriangle className="h-5 w-5 shrink-0" />
          <span className="font-medium">{t("cluster.nodeDegraded", { node: selectedInfo.name })}</span>
          <span className="text-sm opacity-80">{selectedInfo.api_error ?? ""}</span>
        </div>
      </div>
    )
  }
  return null
}

/**
 * Wraps a tab whose content only exists for the local node. For another node
 * it explains that instead of showing (or requesting) local data.
 */
export function RemoteGate({ children }: { children: React.ReactNode }) {
  const t = useT()
  const { isRemote, localNode, selected, selectNode } = useNode()
  if (!isRemote) return <>{children}</>
  return (
    <div className="rounded-lg border border-border bg-card p-6 space-y-3" data-testid="remote-unsupported">
      <p className="font-medium">{t("cluster.unsupported.title", { node: selected ?? "" })}</p>
      <p className="text-sm text-muted-foreground">{t("cluster.unsupported.body")}</p>
      {localNode && (
        <Button variant="outline" size="sm" onClick={() => selectNode(localNode)}>
          {t("cluster.unsupported.switchLocal", { node: localNode })}
        </Button>
      )}
    </div>
  )
}
