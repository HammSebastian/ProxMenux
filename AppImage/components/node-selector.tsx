"use client"

import { Server } from "lucide-react"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select"
import { useNode, type ClusterNode } from "../lib/node-context"
import { useT } from "../lib/i18n/provider"

function dot(node: ClusterNode) {
  const color =
    node.status === "online" ? "bg-green-500" : node.status === "degraded" ? "bg-yellow-500" : "bg-red-500"
  return <span className={`inline-block h-2 w-2 rounded-full ${color}`} aria-hidden />
}

/**
 * Central node dropdown. Hidden on single-node installs. Switching only
 * changes which node the dashboard queries - no re-login, no page reload.
 */
export function NodeSelector({ compact = false }: { compact?: boolean }) {
  const t = useT()
  const { nodes, selected, selectNode, multiNode } = useNode()
  if (!multiNode || !selected) return null
  return (
    <div onClick={(e) => e.stopPropagation()} className="flex items-center">
      <Select value={selected} onValueChange={selectNode}>
        <SelectTrigger
          aria-label={t("cluster.selector.label")}
          className={compact ? "h-8 w-[130px] text-xs" : "h-9 w-[190px]"}
          data-testid="node-selector"
        >
          <div className="flex items-center gap-2 min-w-0">
            <Server className="h-4 w-4 shrink-0 text-muted-foreground" />
            <SelectValue />
          </div>
        </SelectTrigger>
        <SelectContent>
          {nodes.map((n) => (
            <SelectItem key={n.name} value={n.name}>
              <span className="flex items-center gap-2">
                {dot(n)}
                <span>{n.name}</span>
                {n.local && <span className="text-xs text-muted-foreground">({t("cluster.selector.thisNode")})</span>}
                {n.status === "offline" && <span className="text-xs text-red-500">{t("cluster.status.offline")}</span>}
              </span>
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )
}
