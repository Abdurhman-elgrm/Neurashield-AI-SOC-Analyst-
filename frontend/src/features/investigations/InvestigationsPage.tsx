import { useState } from "react"
import { useNavigate } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"
import { formatDistanceToNowStrict } from "date-fns"
import { Plus, RefreshCw, GitMerge } from "lucide-react"
import { Button } from "@/components/ui/Button"
import { listInvestigations } from "./api/investigationsApi"
import type { InvestigationListItem } from "./api/investigationsApi"
import { CreateInvestigationModal } from "./components/CreateInvestigationModal"

// ─── Helpers ──────────────────────────────────────────────────────────────────

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

// ─── Cells ────────────────────────────────────────────────────────────────────

function SevBadge({ score }: { score: number }) {
  const { label, color, bg } = scoreToSev(score)
  return (
    <span style={{
      display: "inline-flex", alignItems: "center",
      padding: "2px 7px", borderRadius: 4,
      fontSize: 9, fontWeight: 700,
      fontFamily: "'JetBrains Mono', monospace",
      textTransform: "uppercase", color, background: bg,
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
      textTransform: "uppercase", color: s.color, background: s.bg,
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
      textTransform: "uppercase",
      color:      isManual ? "#93C5FD" : "#9CA3AF",
      background: isManual ? "rgba(59,130,246,0.12)" : "rgba(156,163,175,0.08)",
    }}>
      {isManual ? "MANUAL" : "AUTO"}
    </span>
  )
}

// ─── Row ──────────────────────────────────────────────────────────────────────

function InvRow({ inv, onClick }: { inv: InvestigationListItem; onClick: () => void }) {
  const [hover, setHover] = useState(false)
  const displayTitle = inv.title || inv.executive_summary || "Untitled investigation"

  return (
    <tr
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        borderLeft: "3px solid transparent",
        borderBottom: "1px solid rgba(255,255,255,0.04)",
        cursor: "pointer", transition: "background 120ms",
        background: hover ? "rgba(255,255,255,0.025)" : "transparent",
      }}
    >
      <td style={{ padding: "9px 12px" }}>
        <SevBadge score={inv.threat_score} />
      </td>
      <td style={{ padding: "9px 12px", maxWidth: 320 }}>
        <div style={{
          fontSize: 12, fontWeight: 600, color: "#F5F7FA",
          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
        }}>
          {displayTitle}
        </div>
      </td>
      <td style={{ padding: "9px 12px" }}>
        <SourceBadge source={inv.source} />
      </td>
      <td style={{ padding: "9px 12px" }}>
        <StatusBadge status={inv.status} />
      </td>
      <td style={{ padding: "9px 12px" }}>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 700, color: scoreToSev(inv.threat_score).color }}>
          {inv.threat_score}
        </span>
      </td>
      <td style={{ padding: "9px 12px" }}>
        {inv.assigned_to ? (
          <div style={{
            width: 24, height: 24, borderRadius: "50%",
            background: "linear-gradient(135deg, #2563EB, #38BDF8)",
            display: "inline-flex", alignItems: "center", justifyContent: "center",
            fontSize: 9, fontWeight: 700, color: "#fff",
          }}>
            {inv.assigned_to.slice(0, 2).toUpperCase()}
          </div>
        ) : (
          <span style={{ color: "#3A4150", fontSize: 12 }}>—</span>
        )}
      </td>
      <td style={{ padding: "9px 12px" }}>
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
      {Array.from({ length: 5 }).map((_, i) => (
        <tr key={i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
          <td style={{ padding: "9px 12px" }}><span className="skel" style={{ width: 60,  height: 18, display: "block" }} /></td>
          <td style={{ padding: "9px 12px" }}><span className="skel" style={{ width: 220, height: 14, display: "block" }} /></td>
          <td style={{ padding: "9px 12px" }}><span className="skel" style={{ width: 50,  height: 16, display: "block" }} /></td>
          <td style={{ padding: "9px 12px" }}><span className="skel" style={{ width: 80,  height: 18, display: "block" }} /></td>
          <td style={{ padding: "9px 12px" }}><span className="skel" style={{ width: 32,  height: 14, display: "block" }} /></td>
          <td style={{ padding: "9px 12px" }}><span className="skel" style={{ width: 24,  height: 24, borderRadius: "50%", display: "block" }} /></td>
          <td style={{ padding: "9px 12px" }}><span className="skel" style={{ width: 60,  height: 12, display: "block" }} /></td>
        </tr>
      ))}
    </>
  )
}

// ─── Empty state ──────────────────────────────────────────────────────────────

function EmptyState({ onNew }: { onNew: () => void }) {
  return (
    <tr>
      <td colSpan={7}>
        <div style={{ textAlign: "center", padding: "80px 0" }}>
          <GitMerge size={40} style={{ color: "#3A4150", margin: "0 auto 16px", display: "block" }} />
          <div style={{ fontSize: 15, fontWeight: 600, color: "#5C6373", marginBottom: 8 }}>
            No investigations yet
          </div>
          <div style={{ fontSize: 12, color: "#3A4150", marginBottom: 24 }}>
            Investigations are created automatically when NEURASHIELD correlates
            alerts, or you can open one manually.
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

// ─── Filter tabs ──────────────────────────────────────────────────────────────

const STATUS_FILTERS: Array<{ label: string; value: string | undefined }> = [
  { label: "All",           value: undefined       },
  { label: "New",           value: "new"           },
  { label: "Investigating", value: "investigating"  },
  { label: "Contained",     value: "contained"     },
  { label: "Closed",        value: "closed"        },
]

// ─── Page ─────────────────────────────────────────────────────────────────────

export function InvestigationsPage() {
  const navigate = useNavigate()
  const [showModal,    setShowModal]    = useState(false)
  const [statusFilter, setStatusFilter] = useState<string | undefined>(undefined)

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["investigations", { status: statusFilter }],
    queryFn:  () => listInvestigations({ status: statusFilter, limit: 50 }),
    staleTime: 30_000,
    refetchInterval: 60_000,
    retry: 1,
  })

  // Backend returns PaginatedResponse shape: { data: [], ... }
  const items: InvestigationListItem[] = (data as any)?.data ?? []
  const total: number = (data as any)?.total ?? 0

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 50px - 40px)", overflow: "hidden" }}>

      {/* Page header */}
      <div style={{
        paddingBottom: 12,
        borderBottom: "1px solid rgba(255,255,255,0.06)",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        flexShrink: 0,
      }}>
        <div>
          <h1 style={{ fontSize: 17, fontWeight: 800, fontFamily: "'Space Grotesk', sans-serif", color: "#F5F7FA" }}>
            Investigations
          </h1>
          <p style={{ fontSize: 12, color: "#5C6373", marginTop: 2 }}>
            {isLoading ? "Loading…" : (
              <><span style={{ color: "#F5F7FA", fontWeight: 500 }}>{total}</span> total</>
            )}
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <button
            onClick={() => refetch()}
            style={{ background: "none", border: "none", cursor: "pointer", color: "#5C6373", padding: 6, borderRadius: 6 }}
          >
            <RefreshCw size={14} />
          </button>
          <Button variant="primary" size="sm" onClick={() => setShowModal(true)}>
            <Plus size={13} />
            New Investigation
          </Button>
        </div>
      </div>

      {/* Filter bar */}
      <div style={{
        display: "flex", alignItems: "center", gap: 4,
        padding: "8px 0",
        borderBottom: "1px solid rgba(255,255,255,0.04)",
        flexShrink: 0,
      }}>
        {STATUS_FILTERS.map((f) => (
          <button
            key={String(f.value ?? "all")}
            onClick={() => setStatusFilter(f.value)}
            style={{
              padding: "4px 12px", borderRadius: 6,
              fontSize: 11, fontWeight: 600, cursor: "pointer",
              transition: "all 120ms", border: "1px solid transparent",
              background: statusFilter === f.value ? "rgba(59,130,246,0.12)" : "transparent",
              color:      statusFilter === f.value ? "#93C5FD" : "#5C6373",
              borderColor: statusFilter === f.value ? "rgba(59,130,246,0.3)" : "transparent",
            }}
          >
            {f.label}
          </button>
        ))}
      </div>

      {/* Table */}
      <div style={{ flex: 1, overflowY: "auto" }}>
        <table className="data-table">
          <thead style={{ position: "sticky", top: 0, background: "#050505", zIndex: 10 }}>
            <tr>
              <th style={{ width: 80  }}>SEV</th>
              <th>TITLE</th>
              <th style={{ width: 80  }}>SOURCE</th>
              <th style={{ width: 130 }}>STATUS</th>
              <th style={{ width: 60  }}>SCORE</th>
              <th style={{ width: 60  }}>ASSIGNED</th>
              <th style={{ width: 90  }}>AGE</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <SkeletonRows />
            ) : items.length === 0 ? (
              <EmptyState onNew={() => setShowModal(true)} />
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

      {/* Create modal */}
      <CreateInvestigationModal
        open={showModal}
        onClose={() => setShowModal(false)}
      />
    </div>
  )
}
