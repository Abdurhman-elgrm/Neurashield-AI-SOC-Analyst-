import { useState, useEffect } from "react"
import { useNavigate } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"
import { formatDistanceToNowStrict } from "date-fns"
import {
  Plus, RefreshCw, GitMerge, User, X, AlertTriangle,
  Clock, Flame, ShieldAlert, Users, Search, Network,
  Tag, CheckCircle2, Timer,
} from "lucide-react"
import { Button } from "@/components/ui/Button"
import { listInvestigations } from "./api/investigationsApi"
import type { InvestigationListItem } from "./api/investigationsApi"
import { CreateInvestigationModal } from "./components/CreateInvestigationModal"
import { GraphPage } from "../graph/GraphPage"

// ─── SLA thresholds (hours per severity band) ─────────────────────────────────

const SLA_HOURS: Record<string, number> = {
  CRITICAL: 1,
  HIGH:     4,
  MEDIUM:   24,
  LOW:      72,
}

function getSLAStatus(inv: InvestigationListItem): {
  breached: boolean;
  nearBreach: boolean;
  elapsed: string;
  color: string;
} {
  const { label } = scoreToSev(inv.threat_score)
  const limitH = SLA_HOURS[label] ?? 24
  const ageMs  = Date.now() - new Date(inv.created_at).getTime()
  const ageH   = ageMs / 3_600_000
  const terminal = ["resolved", "closed", "false_positive"].includes(inv.status)

  const h = Math.floor(ageH)
  const m = Math.floor((ageH - h) * 60)
  const elapsed = h > 0 ? `${h}h ${m}m` : `${m}m`

  if (terminal) return { breached: false, nearBreach: false, elapsed, color: "#4B5563" }
  if (ageH > limitH)        return { breached: true,  nearBreach: false, elapsed, color: "#EF4444" }
  if (ageH > limitH * 0.75) return { breached: false, nearBreach: true,  elapsed, color: "#F59E0B" }
  return { breached: false, nearBreach: false, elapsed, color: "#10B981" }
}

// ─── Badge helpers ────────────────────────────────────────────────────────────

function scoreToSev(score: number): { label: string; color: string; bg: string } {
  if (score >= 80) return { label: "CRITICAL", color: "#FCA5A5", bg: "rgba(239,68,68,0.12)"  }
  if (score >= 60) return { label: "HIGH",     color: "#FDB07A", bg: "rgba(249,115,22,0.12)" }
  if (score >= 30) return { label: "MEDIUM",   color: "#FCD34D", bg: "rgba(245,158,11,0.12)" }
  return             { label: "LOW",       color: "#93C5FD", bg: "rgba(59,130,246,0.12)"  }
}

const STATUS_STYLES: Record<string, { color: string; bg: string }> = {
  new:           { color: "#9CA3AF", bg: "rgba(156,163,175,0.1)" },
  active:        { color: "#FCD34D", bg: "rgba(245,158,11,0.1)"  },
  triaged:       { color: "#93C5FD", bg: "rgba(59,130,246,0.1)"  },
  investigating: { color: "#6EE7B7", bg: "rgba(16,185,129,0.1)"  },
  contained:     { color: "#FDB07A", bg: "rgba(249,115,22,0.1)"  },
  resolved:      { color: "#6EE7B7", bg: "rgba(16,185,129,0.1)"  },
  closed:        { color: "#4B5563", bg: "rgba(75,85,99,0.08)"   },
  false_positive:{ color: "#FCA5A5", bg: "rgba(239,68,68,0.08)"  },
}

function timeAgo(iso: string) {
  try { return formatDistanceToNowStrict(new Date(iso), { addSuffix: true }) }
  catch { return "—" }
}

// ─── Quick filter strip ───────────────────────────────────────────────────────

type QuickFilter = "all" | "mine" | "unassigned" | "high_score" | "sla_breached"

const QUICK_FILTERS: Array<{
  id: QuickFilter; label: string; icon: React.ElementType; color: string;
}> = [
  { id: "all",          label: "All",           icon: GitMerge,   color: "#8B95A7" },
  { id: "mine",         label: "Assigned to Me", icon: User,       color: "#818CF8" },
  { id: "unassigned",   label: "Unassigned",    icon: Users,      color: "#F59E0B" },
  { id: "high_score",   label: "High Score ≥80", icon: Flame,      color: "#EF4444" },
  { id: "sla_breached", label: "SLA Breached",  icon: AlertTriangle, color: "#F97316" },
]

// ─── SLA badge ────────────────────────────────────────────────────────────────

function SLABadge({ inv }: { inv: InvestigationListItem }) {
  const sla = getSLAStatus(inv)
  const terminal = ["resolved", "closed", "false_positive"].includes(inv.status)
  if (terminal) return <span style={{ fontSize: 10, color: "#4B5563", fontFamily: "monospace" }}>—</span>

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
      <span style={{
        display: "inline-flex", alignItems: "center", gap: 4,
        padding: "2px 7px", borderRadius: 4,
        fontSize: 9, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace",
        background: `${sla.color}18`, color: sla.color,
        border: `1px solid ${sla.color}30`,
      }}>
        <Clock size={9} style={{ flexShrink: 0 }} />
        {sla.elapsed}
        {sla.breached && " ⚠"}
      </span>
    </div>
  )
}

// ─── SevBadge ─────────────────────────────────────────────────────────────────

function SevBadge({ score }: { score: number }) {
  const { label, color, bg } = scoreToSev(score)
  return (
    <span style={{
      display: "inline-flex", alignItems: "center",
      padding: "2px 7px", borderRadius: 4,
      fontSize: 9, fontWeight: 700,
      fontFamily: "'JetBrains Mono', monospace",
      textTransform: "uppercase" as const, color, background: bg,
    }}>
      {label}
    </span>
  )
}

function StatusBadge({ status }: { status: string }) {
  const s = STATUS_STYLES[status] ?? { color: "#9CA3AF", bg: "rgba(156,163,175,0.1)" }
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      padding: "2px 8px", borderRadius: 9999,
      fontSize: 9, fontWeight: 700,
      fontFamily: "'JetBrains Mono', monospace",
      textTransform: "uppercase" as const, color: s.color, background: s.bg,
    }}>
      <span style={{ width: 5, height: 5, borderRadius: "50%", background: s.color, flexShrink: 0 }} />
      {status.replace(/_/g, " ")}
    </span>
  )
}

function SourceBadge({ source }: { source: string | null }) {
  const isManual = source === "manual"
  return (
    <span style={{
      fontSize: 9, fontWeight: 600,
      padding: "1px 6px", borderRadius: 3,
      fontFamily: "'JetBrains Mono', monospace",
      textTransform: "uppercase" as const,
      color:      isManual ? "#93C5FD" : "#9CA3AF",
      background: isManual ? "rgba(59,130,246,0.12)" : "rgba(156,163,175,0.08)",
    }}>
      {isManual ? "MANUAL" : "AUTO"}
    </span>
  )
}

// ─── Summary counts ───────────────────────────────────────────────────────────

function SummaryBand({ items }: { items: InvestigationListItem[] }) {
  const activeCount    = items.filter(i => ["active","investigating","triaged"].includes(i.status)).length
  const breachedCount  = items.filter(i => getSLAStatus(i).breached).length
  const criticalCount  = items.filter(i => i.threat_score >= 80).length
  const unassigned     = items.filter(i => !i.assigned_to && !["resolved","closed","false_positive"].includes(i.status)).length

  const stats = [
    { label: "Active",       value: activeCount,   color: "#F59E0B", icon: Activity2    },
    { label: "SLA Breached", value: breachedCount, color: "#EF4444", icon: AlertTriangle },
    { label: "Critical",     value: criticalCount, color: "#EF4444", icon: ShieldAlert   },
    { label: "Unassigned",   value: unassigned,    color: "#F97316", icon: Users         },
  ]
  return (
    <div style={{
      display: "flex", gap: 10,
      padding: "10px 0",
      flexShrink: 0,
      borderBottom: "1px solid rgba(255,255,255,0.05)",
    }}>
      {stats.map(({ label, value, color, icon: Icon }) => (
        <div key={label} style={{
          display: "flex", alignItems: "center", gap: 10,
          padding: "8px 14px", borderRadius: 8,
          background: value > 0 ? `${color}0d` : "rgba(255,255,255,0.02)",
          border: `1px solid ${value > 0 ? `${color}25` : "rgba(255,255,255,0.06)"}`,
          minWidth: 120, flexShrink: 0,
        }}>
          <div style={{
            width: 30, height: 30, borderRadius: 7,
            background: value > 0 ? `${color}18` : "rgba(255,255,255,0.04)",
            display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
          }}>
            <Icon size={13} style={{ color: value > 0 ? color : "#374151" }} />
          </div>
          <div>
            <div style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 20, fontWeight: 800,
              color: value > 0 ? color : "#374151",
              lineHeight: 1,
            }}>
              {value}
            </div>
            <div style={{
              fontSize: 9, color: "#4B5563", marginTop: 3,
              fontWeight: 700, textTransform: "uppercase" as const,
              letterSpacing: "0.8px",
            }}>
              {label}
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

function Activity2({ size }: { size: number }) {
  return <Clock size={size} />
}

// ─── Row ──────────────────────────────────────────────────────────────────────

function InvRow({ inv, onClick }: { inv: InvestigationListItem; onClick: () => void }) {
  const [hover, setHover] = useState(false)
  const sla = getSLAStatus(inv)
  const sev = scoreToSev(inv.threat_score)
  const displayTitle = inv.title || inv.executive_summary || "Untitled investigation"
  const borderColor = sla.breached ? "#EF4444" : sev.color

  return (
    <tr
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        borderLeft: `3px solid ${hover ? borderColor : `${borderColor}55`}`,
        borderBottom: "1px solid rgba(255,255,255,0.04)",
        cursor: "pointer", transition: "all 120ms",
        background: hover
          ? `${borderColor}08`
          : sla.breached
          ? "rgba(239,68,68,0.02)"
          : "transparent",
      }}
    >
      {/* Score + sev */}
      <td style={{ padding: "10px 12px", whiteSpace: "nowrap" as const }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 16, fontWeight: 800,
              color: sev.color,
            }}>
              {inv.threat_score}
            </span>
            <SevBadge score={inv.threat_score} />
          </div>
          <div style={{ width: 56, height: 3, background: "rgba(255,255,255,0.06)", borderRadius: 2, overflow: "hidden" }}>
            <div style={{ height: "100%", width: `${inv.threat_score}%`, background: sev.color, borderRadius: 2, opacity: 0.8 }} />
          </div>
        </div>
      </td>

      {/* Title */}
      <td style={{ padding: "10px 12px", maxWidth: 340 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{
            fontSize: 12, fontWeight: 600, color: "#F5F7FA",
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" as const,
          }}>
            {displayTitle}
          </span>
          {inv.ai_analysis_json && (
            <span style={{
              fontSize: 9, padding: "1px 5px",
              background: "rgba(99,102,241,0.15)",
              border: "1px solid rgba(99,102,241,0.3)",
              borderRadius: 4, color: "#818CF8",
              fontWeight: 700, letterSpacing: "0.5px",
              flexShrink: 0,
              fontFamily: "'JetBrains Mono', monospace",
            }}>
              AI
            </span>
          )}
          {sla.breached && (
            <span style={{
              fontSize: 9, padding: "1px 5px",
              background: "rgba(239,68,68,0.12)",
              border: "1px solid rgba(239,68,68,0.3)",
              borderRadius: 4, color: "#FCA5A5",
              fontWeight: 700, flexShrink: 0,
              fontFamily: "'JetBrains Mono', monospace",
            }}>
              SLA⚠
            </span>
          )}
        </div>
        {inv.executive_summary && inv.title && (
          <div style={{
            fontSize: 10, color: "#5C6373", marginTop: 2,
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" as const,
            maxWidth: 320,
          }}>
            {inv.executive_summary}
          </div>
        )}
      </td>

      {/* Source */}
      <td style={{ padding: "10px 12px" }}>
        <SourceBadge source={inv.source} />
      </td>

      {/* Status */}
      <td style={{ padding: "10px 12px" }}>
        <StatusBadge status={inv.status} />
      </td>

      {/* SLA timer */}
      <td style={{ padding: "10px 12px" }}>
        <SLABadge inv={inv} />
      </td>

      {/* Assigned */}
      <td style={{ padding: "10px 12px" }}>
        {inv.assigned_to ? (
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div
              title={inv.assigned_to_name ?? inv.assigned_to}
              style={{
                width: 24, height: 24, borderRadius: "50%",
                background: "linear-gradient(135deg, #2563EB, #38BDF8)",
                display: "inline-flex", alignItems: "center", justifyContent: "center",
                fontSize: 9, fontWeight: 700, color: "#fff", flexShrink: 0,
              }}>
              {inv.assigned_to_name
                ? inv.assigned_to_name.split(" ").filter(Boolean).map((w: string) => w[0]).join("").toUpperCase().slice(0, 2)
                : inv.assigned_to.slice(0, 2).toUpperCase()}
            </div>
            {inv.assigned_to_name && (
              <span style={{ fontSize: 10, color: "#8B95A7", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" as const, maxWidth: 80 }}>
                {inv.assigned_to_name.split(" ")[0]}
              </span>
            )}
          </div>
        ) : (
          <span style={{
            fontSize: 9, color: "#F97316", fontFamily: "monospace", fontWeight: 600,
            background: "rgba(249,115,22,0.08)", border: "1px solid rgba(249,115,22,0.2)",
            padding: "2px 5px", borderRadius: 3,
          }}>
            UNASSIGNED
          </span>
        )}
      </td>

      {/* Age */}
      <td style={{ padding: "10px 12px" }}>
        <span style={{ fontSize: 11, color: "#5C6373", fontFamily: "'JetBrains Mono', monospace" }}>
          {timeAgo(inv.created_at)}
        </span>
      </td>
    </tr>
  )
}

// ─── Skeleton rows ────────────────────────────────────────────────────────────

function SkeletonRows() {
  return (
    <>
      {Array.from({ length: 6 }).map((_, i) => (
        <tr key={i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
          <td style={{ padding: "10px 12px" }}><span className="skel" style={{ width: 90,  height: 18, display: "block", borderRadius: 4 }} /></td>
          <td style={{ padding: "10px 12px" }}><span className="skel" style={{ width: 240, height: 14, display: "block", borderRadius: 4 }} /></td>
          <td style={{ padding: "10px 12px" }}><span className="skel" style={{ width: 50,  height: 16, display: "block", borderRadius: 4 }} /></td>
          <td style={{ padding: "10px 12px" }}><span className="skel" style={{ width: 90,  height: 18, display: "block", borderRadius: 4 }} /></td>
          <td style={{ padding: "10px 12px" }}><span className="skel" style={{ width: 60,  height: 16, display: "block", borderRadius: 4 }} /></td>
          <td style={{ padding: "10px 12px" }}><span className="skel" style={{ width: 24,  height: 24, borderRadius: "50%", display: "block" }} /></td>
          <td style={{ padding: "10px 12px" }}><span className="skel" style={{ width: 60,  height: 12, display: "block", borderRadius: 4 }} /></td>
        </tr>
      ))}
    </>
  )
}

// ─── Empty state ──────────────────────────────────────────────────────────────

function EmptyState({ onNew, hasFilters }: { onNew: () => void; hasFilters: boolean }) {
  return (
    <tr>
      <td colSpan={7}>
        <div style={{ textAlign: "center", padding: "80px 0" }}>
          <GitMerge size={40} style={{ color: "#3A4150", margin: "0 auto 16px", display: "block" }} />
          <div style={{ fontSize: 15, fontWeight: 600, color: "#5C6373", marginBottom: 8 }}>
            {hasFilters ? "No investigations match these filters" : "No investigations yet"}
          </div>
          <div style={{ fontSize: 12, color: "#3A4150", marginBottom: 24, maxWidth: 360, margin: "0 auto 24px" }}>
            {hasFilters
              ? "Try adjusting your filters or quick-filter selection."
              : "Investigations are created automatically when alerts correlate, or create one manually."}
          </div>
          <Button variant="primary" onClick={onNew}>
            <Plus size={14} />
            New Investigation
          </Button>
        </div>
      </td>
    </tr>
  )
}

// ─── Status filter tabs ───────────────────────────────────────────────────────

const STATUS_FILTERS: Array<{ label: string; value: string | undefined }> = [
  { label: "All",           value: undefined        },
  { label: "New",           value: "new"            },
  { label: "Active",        value: "active"         },
  { label: "Triaged",       value: "triaged"        },
  { label: "Investigating", value: "investigating"  },
  { label: "Contained",     value: "contained"      },
  { label: "Resolved",      value: "resolved"       },
  { label: "Closed",        value: "closed"         },
  { label: "False Positive",value: "false_positive" },
]

const TIME_RANGES: Array<{ label: string; value: string | undefined }> = [
  { label: "All time",    value: undefined },
  { label: "Last hour",   value: "1h"      },
  { label: "Last 24h",    value: "24h"     },
  { label: "Last 7 days", value: "7d"      },
  { label: "Last 30 days",value: "30d"     },
]

function timeRangeToIso(range: string | undefined): string | undefined {
  if (!range) return undefined
  const ms: Record<string, number> = {
    "1h":  3_600_000,
    "24h": 86_400_000,
    "7d":  604_800_000,
    "30d": 2_592_000_000,
  }
  return new Date(Date.now() - (ms[range] ?? 0)).toISOString()
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export function InvestigationsPage() {
  const navigate = useNavigate()
  const [pageTab, setPageTab] = useState<'list' | 'graph'>('list')
  const [showModal,     setShowModal]     = useState(false)
  const [statusFilter,  setStatusFilter]  = useState<string | undefined>(undefined)
  const [quickFilter,   setQuickFilter]   = useState<QuickFilter>("all")
  const [titleSearch,   setTitleSearch]   = useState("")
  const [debouncedSearch, setDebouncedSearch] = useState("")
  const [minScore,      setMinScore]      = useState<number | "">("")
  const [fromTs,        setFromTs]        = useState<string | undefined>(undefined)

  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(titleSearch), 400)
    return () => clearTimeout(t)
  }, [titleSearch])

  // Sync quick filter → underlying params
  useEffect(() => {
    if (quickFilter === "high_score") setMinScore(80)
    else if (quickFilter === "all" || quickFilter === "unassigned" || quickFilter === "sla_breached" || quickFilter === "mine") setMinScore("")
  }, [quickFilter])

  const apiMinScore = quickFilter === "high_score"
    ? 80
    : minScore !== "" ? Number(minScore) : undefined

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["investigations", {
      status: statusFilter,
      title_search: debouncedSearch || undefined,
      min_score: apiMinScore,
      assigned_to_me: (quickFilter === "mine") || undefined,
      from_ts: timeRangeToIso(fromTs),
    }],
    queryFn: () => listInvestigations({
      status: statusFilter,
      title_search: debouncedSearch || undefined,
      min_score: apiMinScore,
      assigned_to_me: (quickFilter === "mine") || undefined,
      from_ts: timeRangeToIso(fromTs),
      limit: 100,
    }),
    staleTime: 30_000,
    refetchInterval: 60_000,
    retry: 1,
  })

  const rawItems: InvestigationListItem[] = (data as any)?.data ?? []

  // Client-side post-filtering for quick filters that need computed fields
  const items = quickFilter === "unassigned"
    ? rawItems.filter(i => !i.assigned_to && !["resolved","closed","false_positive"].includes(i.status))
    : quickFilter === "sla_breached"
    ? rawItems.filter(i => getSLAStatus(i).breached)
    : rawItems

  const total: number = (data as any)?.total ?? 0
  const hasFilters = !!(titleSearch || minScore !== "" || fromTs || quickFilter !== "all")

  const PAGE_TABS = [
    { id: 'list',  label: 'Investigations', icon: GitMerge },
    { id: 'graph', label: 'Attack Graph',   icon: Network  },
  ]

  if (pageTab === 'graph') {
    return (
      <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 50px - 40px)", overflow: "hidden" }}>
        <div style={{ display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.06)', flexShrink: 0 }}>
          {PAGE_TABS.map(({ id, label, icon: Icon }) => {
            const active = pageTab === id
            return (
              <button key={id} onClick={() => setPageTab(id as 'list' | 'graph')} style={{
                display: 'flex', alignItems: 'center', gap: 7,
                padding: '14px 4px', marginRight: 24,
                fontSize: 13, fontWeight: active ? 600 : 400,
                color: active ? '#E2E8F0' : '#4B5563',
                background: 'none', border: 'none',
                borderBottom: `2px solid ${active ? '#3B82F6' : 'transparent'}`,
                marginBottom: -1, cursor: 'pointer', transition: 'all 120ms',
              }}>
                <Icon size={13} style={{ color: active ? '#60A5FA' : '#374151' }} />
                {label}
              </button>
            )
          })}
        </div>
        <div style={{ flex: 1, overflow: 'hidden' }}>
          <GraphPage />
        </div>
      </div>
    )
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 50px - 40px)", overflow: "hidden" }}>

      {/* Page tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.06)', flexShrink: 0 }}>
        {PAGE_TABS.map(({ id, label, icon: Icon }) => {
          const active = pageTab === id
          return (
            <button key={id} onClick={() => setPageTab(id as 'list' | 'graph')} style={{
              display: 'flex', alignItems: 'center', gap: 7,
              padding: '14px 4px', marginRight: 24,
              fontSize: 13, fontWeight: active ? 600 : 400,
              color: active ? '#E2E8F0' : '#4B5563',
              background: 'none', border: 'none',
              borderBottom: `2px solid ${active ? '#3B82F6' : 'transparent'}`,
              marginBottom: -1, cursor: 'pointer', transition: 'all 120ms',
            }}>
              <Icon size={13} style={{ color: active ? '#60A5FA' : '#374151' }} />
              {label}
            </button>
          )
        })}
      </div>

      {/* Page header */}
      <div style={{
        paddingBottom: 12,
        borderBottom: "1px solid rgba(255,255,255,0.06)",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        flexShrink: 0,
        paddingTop: 14,
      }}>
        <div>
          <h1 style={{ fontSize: 17, fontWeight: 800, fontFamily: "'Space Grotesk', sans-serif", color: "#F5F7FA", margin: 0 }}>
            Investigations
          </h1>
          <p style={{ fontSize: 12, color: "#5C6373", marginTop: 2, marginBottom: 0 }}>
            {isLoading ? "Loading…" : (
              <><span style={{ color: "#F5F7FA", fontWeight: 500 }}>{total.toLocaleString()}</span> total</>
            )}
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <button
            onClick={() => refetch()}
            style={{ background: "none", border: "none", cursor: "pointer", color: "#5C6373", padding: 6, borderRadius: 6 }}
            title="Refresh"
          >
            <RefreshCw size={14} />
          </button>
          <Button variant="primary" size="sm" onClick={() => setShowModal(true)}>
            <Plus size={13} />
            New Investigation
          </Button>
        </div>
      </div>

      {/* Summary band */}
      {!isLoading && rawItems.length > 0 && <SummaryBand items={rawItems} />}

      {/* Quick filter strip */}
      <div style={{
        display: "flex", alignItems: "center", gap: 6,
        padding: "8px 0 6px", flexShrink: 0,
        borderBottom: "1px solid rgba(255,255,255,0.04)",
        overflowX: "auto",
      }}>
        {QUICK_FILTERS.map(({ id, label, icon: Icon, color }) => {
          const active = quickFilter === id
          return (
            <button
              key={id}
              onClick={() => setQuickFilter(id)}
              style={{
                display: "flex", alignItems: "center", gap: 6,
                padding: "5px 12px", borderRadius: 6, flexShrink: 0,
                fontSize: 11, fontWeight: 600, cursor: "pointer",
                transition: "all 120ms", whiteSpace: "nowrap" as const,
                background: active ? `${color}18` : "rgba(255,255,255,0.03)",
                border: `1px solid ${active ? `${color}40` : "rgba(255,255,255,0.07)"}`,
                color: active ? color : "#5C6373",
              }}
            >
              <Icon size={11} />
              {label}
            </button>
          )
        })}

        <div style={{ flex: 1 }} />

        {/* Status filter tabs */}
        <div style={{
          display: "flex", gap: 2,
          background: "rgba(255,255,255,0.03)",
          border: "1px solid rgba(255,255,255,0.06)",
          borderRadius: 6, padding: 2,
        }}>
          {STATUS_FILTERS.slice(0, 5).map((f) => (
            <button
              key={String(f.value ?? "all")}
              onClick={() => setStatusFilter(f.value)}
              style={{
                padding: "3px 10px", borderRadius: 4,
                fontSize: 10, fontWeight: 600, cursor: "pointer",
                transition: "all 100ms", border: "none",
                background: statusFilter === f.value ? "rgba(59,130,246,0.15)" : "transparent",
                color: statusFilter === f.value ? "#93C5FD" : "#5C6373",
              }}
            >
              {f.label}
            </button>
          ))}
          <select
            value={statusFilter ?? ""}
            onChange={(e) => setStatusFilter(e.target.value || undefined)}
            style={{
              background: "transparent", border: "none", color: "#5C6373",
              fontSize: 10, cursor: "pointer", outline: "none",
              padding: "3px 6px",
            }}
          >
            <option value="">More status…</option>
            {STATUS_FILTERS.slice(5).map((f) => (
              <option key={String(f.value)} value={f.value ?? ""}>{f.label}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Search bar row */}
      <div style={{
        display: "flex", alignItems: "center", gap: 8,
        padding: "8px 0",
        borderBottom: "1px solid rgba(255,255,255,0.04)",
        flexShrink: 0, flexWrap: "wrap" as const,
      }}>
        <div style={{ position: "relative", flex: 1, minWidth: 200 }}>
          <Search size={12} style={{ position: "absolute", left: 9, top: "50%", transform: "translateY(-50%)", color: "#5C6373" }} />
          <input
            className="inp"
            value={titleSearch}
            onChange={(e) => setTitleSearch(e.target.value)}
            placeholder="Search title or summary…"
            style={{ paddingLeft: 28, width: "100%", height: 32 }}
          />
        </div>
        <input
          className="inp"
          type="number"
          min={0} max={100}
          value={minScore}
          onChange={(e) => {
            setMinScore(e.target.value === "" ? "" : Number(e.target.value))
            if (quickFilter === "high_score") setQuickFilter("all")
          }}
          placeholder="Score ≥"
          style={{ width: 90, height: 32 }}
        />
        <select
          className="inp"
          value={fromTs ?? ""}
          onChange={(e) => setFromTs(e.target.value || undefined)}
          style={{ width: 130, height: 32 }}
        >
          {TIME_RANGES.map((r) => (
            <option key={String(r.value ?? "")} value={r.value ?? ""}>{r.label}</option>
          ))}
        </select>
        {hasFilters && (
          <button
            onClick={() => {
              setTitleSearch(""); setMinScore(""); setFromTs(undefined)
              setQuickFilter("all"); setStatusFilter(undefined)
            }}
            style={{
              fontSize: 11, color: "#5C6373",
              background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.07)",
              padding: "0 10px", height: 32, borderRadius: 6, cursor: "pointer",
              display: "flex", alignItems: "center", gap: 4,
            }}
          >
            <X size={11} /> Clear
          </button>
        )}
      </div>

      {/* Table */}
      <div style={{ flex: 1, overflowY: "auto" }}>
        <table className="data-table">
          <thead style={{ position: "sticky", top: 0, background: "#050505", zIndex: 10 }}>
            <tr>
              <th style={{ width: 120 }}>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                  <ShieldAlert size={10} /> SEVERITY
                </span>
              </th>
              <th>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                  <GitMerge size={10} /> TITLE
                </span>
              </th>
              <th style={{ width: 80 }}>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                  <Tag size={10} /> SOURCE
                </span>
              </th>
              <th style={{ width: 130 }}>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                  <CheckCircle2 size={10} /> STATUS
                </span>
              </th>
              <th style={{ width: 100 }}>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                  <Timer size={10} /> SLA TIMER
                </span>
              </th>
              <th style={{ width: 120 }}>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                  <User size={10} /> ASSIGNED
                </span>
              </th>
              <th style={{ width: 90 }}>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                  <Clock size={10} /> AGE
                </span>
              </th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <SkeletonRows />
            ) : items.length === 0 ? (
              <EmptyState onNew={() => setShowModal(true)} hasFilters={hasFilters} />
            ) : (
              items.map((inv) => (
                <InvRow
                  key={inv.investigation_id}
                  inv={inv}
                  onClick={() => navigate(`/investigations/${inv.investigation_id}`)}
                />
              ))
            )}
          </tbody>
        </table>
      </div>

      <CreateInvestigationModal open={showModal} onClose={() => setShowModal(false)} />
    </div>
  )
}
