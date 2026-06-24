import React, { useState } from "react"
import { User, UserCheck, CheckCircle2, Circle, Clock, ChevronDown, ChevronRight } from "lucide-react"
import { formatDistanceToNowStrict } from "date-fns"
import { ScorePanel } from "./ScorePanel"
import { IOCPanel } from "./IOCPanel"
import { MITREPanel } from "./MITREPanel"
import type { InvestigationDetail } from "../hooks/useInvestigationDetail"

interface Props {
  inv: InvestigationDetail
}

// ─── Status history timeline ──────────────────────────────────────────────────

const STATUS_COLORS: Record<string, string> = {
  new:            "#9CA3AF",
  active:         "#F59E0B",
  triaged:        "#3B82F6",
  investigating:  "#10B981",
  contained:      "#F97316",
  resolved:       "#10B981",
  closed:         "#4B5563",
  false_positive: "#EF4444",
}

function StatusHistoryPanel({ inv }: { inv: InvestigationDetail }) {
  const [expanded, setExpanded] = useState(false)

  // Build a synthetic timeline from available timestamps
  const events: Array<{ status: string; at: string | null; label: string }> = [
    { status: "new",    at: inv.created_at,  label: "Created" },
    { status: "active", at: inv.created_at,  label: "Opened"  },
  ]

  if ((inv as any).triaged_at)       events.push({ status: "triaged",       at: (inv as any).triaged_at,       label: "Triaged"       })
  if ((inv as any).investigating_at) events.push({ status: "investigating",  at: (inv as any).investigating_at, label: "Investigating"  })
  if ((inv as any).contained_at)     events.push({ status: "contained",      at: (inv as any).contained_at,     label: "Contained"     })
  if (inv.resolved_at)               events.push({ status: "resolved",       at: inv.resolved_at,               label: "Resolved"      })
  if ((inv as any).closed_at)        events.push({ status: "closed",         at: (inv as any).closed_at,        label: "Closed"        })

  let currentIdx = 0
  for (let i = events.length - 1; i >= 0; i--) {
    if (events[i].at != null) { currentIdx = i; break }
  }
  const visibleEvents = expanded ? events : events.slice(Math.max(0, currentIdx - 1), currentIdx + 2)

  return (
    <div style={{
      background: "#0D0D0D",
      border: "1px solid rgba(255,255,255,0.06)",
      borderRadius: 8,
      padding: "10px 12px",
    }}>
      <button
        onClick={() => setExpanded((v) => !v)}
        style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          width: "100%", background: "none", border: "none", cursor: "pointer",
          marginBottom: visibleEvents.length > 0 ? 10 : 0,
        }}
      >
        <span style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1.5px", color: "#5C6373" }}>
          Status History
        </span>
        {expanded
          ? <ChevronDown size={11} style={{ color: "#5C6373" }} />
          : <ChevronRight size={11} style={{ color: "#5C6373" }} />}
      </button>

      {visibleEvents.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 0, position: "relative" }}>
          {/* Vertical line */}
          <div style={{
            position: "absolute", left: 7, top: 8, bottom: 8,
            width: 1, background: "rgba(255,255,255,0.06)",
          }} />

          {visibleEvents.map((ev, i) => {
            const isCurrent = ev.status === inv.status
            const isPast    = ev.at != null
            const color     = STATUS_COLORS[ev.status] ?? "#9CA3AF"

            return (
              <div key={`${ev.status}-${i}`} style={{ display: "flex", alignItems: "flex-start", gap: 8, padding: "4px 0", position: "relative" }}>
                {/* Dot */}
                <div style={{ flexShrink: 0, marginTop: 1, zIndex: 1 }}>
                  {isCurrent
                    ? <CheckCircle2 size={15} style={{ color }} />
                    : isPast
                    ? <CheckCircle2 size={15} style={{ color: `${color}60` }} />
                    : <Circle       size={15} style={{ color: "rgba(255,255,255,0.1)" }} />}
                </div>

                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
                    <span style={{
                      fontSize: 11, fontWeight: isCurrent ? 700 : 500,
                      color: isCurrent ? color : isPast ? "#8B95A7" : "#3A4150",
                    }}>
                      {ev.label}
                    </span>
                    {isCurrent && (
                      <span style={{
                        fontSize: 8, fontWeight: 700, textTransform: "uppercase",
                        color, background: `${color}15`,
                        border: `1px solid ${color}30`,
                        padding: "0 4px", borderRadius: 3,
                        fontFamily: "'JetBrains Mono', monospace",
                      }}>
                        NOW
                      </span>
                    )}
                  </div>
                  {ev.at && (
                    <div style={{ fontSize: 10, color: "#3A4150", marginTop: 1, fontFamily: "'JetBrains Mono', monospace" }}>
                      {formatDistanceToNowStrict(new Date(ev.at), { addSuffix: true })}
                    </div>
                  )}
                </div>
              </div>
            )
          })}

          {!expanded && events.length > visibleEvents.length && (
            <button
              onClick={() => setExpanded(true)}
              style={{
                fontSize: 10, color: "#3B82F6", background: "none", border: "none",
                cursor: "pointer", textAlign: "left", padding: "4px 0 0 24px",
              }}
            >
              +{events.length - visibleEvents.length} more events
            </button>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Case metadata ─────────────────────────────────────────────────────────────

function CaseMetaPanel({ inv }: { inv: InvestigationDetail }) {
  const rows: Array<[string, string | number | undefined | null]> = [
    ["Case ID",   `INC-${inv.investigation_id.replace(/-/g, "").slice(0, 8).toUpperCase()}`],
    ["TP Prob",   `${(inv.tp_probability * 100).toFixed(0)}%`],
    ["FP Prob",   `${(inv.fp_probability * 100).toFixed(0)}%`],
    ["Notes",     inv.note_count],
    ["Evidence",  inv.evidence_count],
    ["Verdict",   inv.verdict?.replace(/_/g, " ") ?? "Pending"],
    ["Source",    inv.source ?? "Unknown"],
  ]

  return (
    <div style={{
      background: "#0D0D0D",
      border: "1px solid rgba(255,255,255,0.06)",
      borderRadius: 8,
      padding: "10px 12px",
    }}>
      <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1.5px", color: "#5C6373", marginBottom: 8 }}>
        Case Info
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
        {rows.map(([label, value]) => (
          <div key={label} style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span style={{ fontSize: 10, color: "#5C6373", textTransform: "uppercase", letterSpacing: "0.5px" }}>
              {label}
            </span>
            <span style={{
              fontSize: 11, color: "#B0B8C9",
              fontFamily: "'JetBrains Mono', monospace",
              fontWeight: 600,
            }}>
              {value ?? "—"}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Assigned analyst card ─────────────────────────────────────────────────────

function AssignedAnalystCard({ inv }: { inv: InvestigationDetail }) {
  const isAssigned = !!inv.assigned_to

  return (
    <div style={{
      background: isAssigned ? "rgba(37,99,235,0.06)" : "rgba(249,115,22,0.05)",
      border: `1px solid ${isAssigned ? "rgba(59,130,246,0.2)" : "rgba(249,115,22,0.2)"}`,
      borderRadius: 8,
      padding: "10px 12px",
      display: "flex",
      alignItems: "center",
      gap: 10,
    }}>
      {isAssigned ? (
        <>
          {/* Avatar */}
          <div style={{
            width: 32, height: 32, borderRadius: "50%", flexShrink: 0,
            background: "linear-gradient(135deg, #2563EB 0%, #38BDF8 100%)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 11, fontWeight: 700, color: "#fff",
          }}>
            {(inv as any).assigned_to_name
              ? (inv as any).assigned_to_name.split(" ").map((w: string) => w[0]).join("").toUpperCase().slice(0, 2)
              : (inv.assigned_to ?? "?").slice(0, 2).toUpperCase()}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1px", color: "#5C6373" }}>
              Assigned To
            </div>
            <div style={{ fontSize: 12, fontWeight: 600, color: "#F5F7FA", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {(inv as any).assigned_to_name ?? inv.assigned_to}
            </div>
          </div>
          <UserCheck size={14} style={{ color: "#3B82F6", flexShrink: 0 }} />
        </>
      ) : (
        <>
          <div style={{
            width: 32, height: 32, borderRadius: "50%", flexShrink: 0,
            background: "rgba(249,115,22,0.1)",
            display: "flex", alignItems: "center", justifyContent: "center",
          }}>
            <User size={14} style={{ color: "#F97316" }} />
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1px", color: "#5C6373" }}>
              Assigned To
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <span style={{ fontSize: 11, color: "#F97316", fontWeight: 600 }}>Unassigned</span>
              <span style={{
                fontSize: 8, fontWeight: 700, padding: "0 4px", borderRadius: 3,
                background: "rgba(249,115,22,0.1)", color: "#F97316",
                border: "1px solid rgba(249,115,22,0.25)",
                fontFamily: "'JetBrains Mono', monospace",
              }}>
                ACTION NEEDED
              </span>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

// ─── SLA card ─────────────────────────────────────────────────────────────────

function SLACard({ inv }: { inv: InvestigationDetail }) {
  const createdMs  = new Date(inv.created_at).getTime()
  const terminal   = ["resolved", "closed", "false_positive"].includes(inv.status)
  const endMs      = terminal && inv.resolved_at
    ? new Date(inv.resolved_at).getTime()
    : Date.now()
  const ageMs      = Math.max(0, endMs - createdMs)
  const ageH       = ageMs / 3_600_000
  const limitH     = inv.threat_score >= 80 ? 1 : inv.threat_score >= 60 ? 4 : 24
  const pct        = Math.min(100, (ageH / limitH) * 100)
  const breached   = !terminal && ageH > limitH
  const nearBreach = !terminal && ageH > limitH * 0.75

  const barColor   = breached ? "#EF4444" : nearBreach ? "#F59E0B" : "#10B981"

  const h = Math.floor(ageH)
  const m = Math.floor((ageH - h) * 60)
  const timeStr = h > 0 ? `${h}h ${m}m` : `${m}m`

  return (
    <div style={{
      background: "#0D0D0D",
      border: `1px solid ${breached ? "rgba(239,68,68,0.3)" : "rgba(255,255,255,0.06)"}`,
      borderRadius: 8, padding: "10px 12px",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
        <span style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1.5px", color: "#5C6373" }}>
          SLA Timer
        </span>
        <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
          <Clock size={10} style={{ color: barColor }} />
          <span style={{ fontSize: 12, fontWeight: 800, color: barColor, fontFamily: "'JetBrains Mono', monospace" }}>
            {timeStr}
          </span>
        </div>
      </div>

      {/* Progress bar */}
      <div style={{ height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2, marginBottom: 6 }}>
        <div style={{
          height: "100%", borderRadius: 2,
          width: `${pct}%`,
          background: barColor,
          transition: "width 1s linear",
          boxShadow: breached ? `0 0 6px ${barColor}80` : "none",
        }} />
      </div>

      <div style={{ display: "flex", justifyContent: "space-between" }}>
        <span style={{ fontSize: 10, color: "#5C6373" }}>
          {breached ? "SLA BREACHED" : nearBreach ? "Approaching SLA" : terminal ? "Resolved" : "Within SLA"}
        </span>
        <span style={{ fontSize: 10, color: "#3A4150", fontFamily: "'JetBrains Mono', monospace" }}>
          limit: {limitH}h
        </span>
      </div>
    </div>
  )
}

// ─── InvLeftSidebar ───────────────────────────────────────────────────────────

export const InvLeftSidebar = React.memo(function InvLeftSidebar({ inv }: Props) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <AssignedAnalystCard inv={inv} />
      <SLACard inv={inv} />
      <ScorePanel score={inv.threat_score} confidence={inv.confidence} />
      <StatusHistoryPanel inv={inv} />
      <IOCPanel inv={inv} />
      <MITREPanel steps={inv.attack_progression} />
      <CaseMetaPanel inv={inv} />
    </div>
  )
})
