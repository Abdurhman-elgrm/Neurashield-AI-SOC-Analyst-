import { useState } from "react"
import { X } from "lucide-react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "react-router-dom"
import { Button } from "@/components/ui/Button"
import { createInvestigation } from "../api/investigationsApi"

interface Props {
  open: boolean
  onClose: () => void
  prefillAlertId?: string
  prefillTitle?: string
}

type Severity = "critical" | "high" | "medium" | "low"

const SEV_COLORS: Record<Severity, { text: string; bg: string; border: string }> = {
  critical: { text: "#EF4444", bg: "rgba(239,68,68,0.15)",  border: "rgba(239,68,68,0.4)"  },
  high:     { text: "#F97316", bg: "rgba(249,115,22,0.15)", border: "rgba(249,115,22,0.4)" },
  medium:   { text: "#F59E0B", bg: "rgba(245,158,11,0.15)", border: "rgba(245,158,11,0.4)" },
  low:      { text: "#3B82F6", bg: "rgba(59,130,246,0.15)", border: "rgba(59,130,246,0.4)" },
}

export function CreateInvestigationModal({
  open,
  onClose,
  prefillAlertId,
  prefillTitle = "",
}: Props) {
  const navigate   = useNavigate()
  const qc         = useQueryClient()
  const [title, setTitle]       = useState(prefillTitle)
  const [desc, setDesc]         = useState("")
  const [severity, setSeverity] = useState<Severity>("medium")

  const create = useMutation({
    mutationFn: () =>
      createInvestigation({
        title: title.trim(),
        description: desc.trim() || undefined,
        severity,
        alert_ids: prefillAlertId ? [prefillAlertId] : [],
      }),
    onSuccess: (inv) => {
      qc.invalidateQueries({ queryKey: ["investigations"] })
      onClose()
      navigate(`/investigations/${inv.investigation_id}`)
    },
  })

  if (!open) return null

  return (
    <div
      style={{
        position: "fixed", inset: 0, zIndex: 100,
        background: "rgba(0,0,0,0.7)",
        display: "flex", alignItems: "center", justifyContent: "center",
      }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 480,
          background: "#111111",
          border: "1px solid rgba(255,255,255,0.08)",
          borderRadius: 10,
          overflow: "hidden",
        }}
      >
        {/* Header */}
        <div style={{
          padding: "16px 20px",
          borderBottom: "1px solid rgba(255,255,255,0.06)",
          display: "flex", alignItems: "center", justifyContent: "space-between",
        }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, fontFamily: "'Space Grotesk', sans-serif", color: "#F5F7FA" }}>
              New Investigation
            </div>
            <div style={{ fontSize: 11, color: "#5C6373", marginTop: 2 }}>
              Manually open a new investigation case
            </div>
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "#5C6373", cursor: "pointer", padding: 4 }}>
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: 20 }}>

          {/* Title */}
          <div style={{ marginBottom: 16 }}>
            <label style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1px", color: "#5C6373", display: "block", marginBottom: 6 }}>
              Title *
            </label>
            <input
              className="inp"
              style={{ width: "100%", height: 36 }}
              placeholder="e.g. Suspicious lateral movement detected"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              autoFocus
            />
          </div>

          {/* Description */}
          <div style={{ marginBottom: 16 }}>
            <label style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1px", color: "#5C6373", display: "block", marginBottom: 6 }}>
              Description
            </label>
            <textarea
              className="inp"
              style={{ width: "100%", height: 72, resize: "none", paddingTop: 8, paddingBottom: 8 }}
              placeholder="What triggered this investigation?"
              value={desc}
              onChange={(e) => setDesc(e.target.value)}
            />
          </div>

          {/* Severity */}
          <div style={{ marginBottom: 24 }}>
            <label style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1px", color: "#5C6373", display: "block", marginBottom: 8 }}>
              Severity
            </label>
            <div style={{ display: "flex", gap: 6 }}>
              {(["critical", "high", "medium", "low"] as Severity[]).map((s) => {
                const c = SEV_COLORS[s]
                const active = severity === s
                return (
                  <button
                    key={s}
                    onClick={() => setSeverity(s)}
                    style={{
                      flex: 1, padding: "6px 0",
                      borderRadius: 6, fontSize: 10, fontWeight: 700,
                      textTransform: "uppercase", letterSpacing: "0.08em",
                      fontFamily: "'JetBrains Mono', monospace",
                      cursor: "pointer", transition: "all 120ms",
                      color:      active ? c.text   : "#5C6373",
                      background: active ? c.bg     : "transparent",
                      border:     `1px solid ${active ? c.border : "rgba(255,255,255,0.07)"}`,
                    }}
                  >
                    {s}
                  </button>
                )
              })}
            </div>
          </div>

          {/* Error */}
          {create.isError && (
            <div style={{ marginBottom: 12, fontSize: 11, color: "#F87171", background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: 6, padding: "8px 12px" }}>
              Failed to create investigation. Please try again.
            </div>
          )}

          {/* Actions */}
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
            <Button variant="ghost" size="md" onClick={onClose}>
              Cancel
            </Button>
            <Button
              variant="primary"
              size="md"
              disabled={!title.trim()}
              loading={create.isPending}
              onClick={() => create.mutate()}
            >
              Create Investigation
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
