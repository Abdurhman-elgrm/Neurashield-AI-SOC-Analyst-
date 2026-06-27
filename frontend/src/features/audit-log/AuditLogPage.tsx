import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Download, Search, ChevronDown, ChevronRight } from "lucide-react";
import { auditApi } from "@/api/audit";
import type { AuditEvent } from "@/api/audit";
import { cn } from "@/lib/utils";

// ─── Helpers ──────────────────────────────────────────────────────────────────

const DESTRUCTIVE_ACTIONS = new Set(["delete", "close", "quarantine", "revoke", "status_change"]);

function isDestructive(action: string): boolean {
  return DESTRUCTIVE_ACTIONS.has(action.toLowerCase().split(".")[0] ?? "");
}

function JsonDiff({ oldVal, newVal }: { oldVal: unknown; newVal: unknown }) {
  const fmt = (v: unknown) =>
    typeof v === "object" ? JSON.stringify(v, null, 2) : String(v ?? "—");

  return (
    <div className="mt-2 grid grid-cols-2 gap-2 text-2xs font-mono">
      <div className="bg-red-500/5 border border-red-500/20 rounded p-2">
        <p className="text-red-400 font-bold mb-1">Before</p>
        <pre className="text-text-secondary whitespace-pre-wrap break-all">{fmt(oldVal)}</pre>
      </div>
      <div className="bg-green-500/5 border border-green-500/20 rounded p-2">
        <p className="text-green-400 font-bold mb-1">After</p>
        <pre className="text-text-secondary whitespace-pre-wrap break-all">{fmt(newVal)}</pre>
      </div>
    </div>
  );
}

// ─── Row ──────────────────────────────────────────────────────────────────────

function AuditRow({ event }: { event: AuditEvent }) {
  const [expanded, setExpanded] = useState(false);
  const destructive = isDestructive(event.action);

  return (
    <>
      <tr
        className={cn(
          "border-b border-border/50 cursor-pointer hover:bg-bg-elevated/50 transition-colors",
          destructive && "bg-amber-500/3",
        )}
        onClick={() => setExpanded((v) => !v)}
      >
        <td className="px-3 py-2.5 font-mono text-2xs text-text-muted whitespace-nowrap">
          {new Date(event.timestamp).toLocaleString([], { dateStyle: "short", timeStyle: "medium" })}
        </td>
        <td className="px-3 py-2.5 text-xs text-text-secondary">{event.actor_name}</td>
        <td className="px-3 py-2.5">
          <span className={cn(
            "text-xs font-medium",
            destructive ? "text-amber-400" : "text-text-secondary",
          )}>
            {event.action}
          </span>
        </td>
        <td className="px-3 py-2.5 text-xs text-text-muted">
          <span className="text-2xs bg-bg-elevated px-1.5 py-0.5 rounded">{event.resource_type}</span>
          {" "}{event.resource_title || event.resource_id?.slice(0, 12) || "—"}
        </td>
        <td className="px-3 py-2.5 text-2xs text-text-muted font-mono">{event.ip_address}</td>
        <td className="px-3 py-2.5 text-text-muted">
          {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-border/50">
          <td colSpan={6} className="px-4 pb-3">
            <JsonDiff oldVal={event.old_value} newVal={event.new_value} />
          </td>
        </tr>
      )}
    </>
  );
}

// ─── AuditLogPage ─────────────────────────────────────────────────────────────

export function AuditLogPage() {
  useEffect(() => { document.title = "Audit Log — NEURASHIELD"; }, []);

  const [page,     setPage]     = useState(1);
  const [actor,    setActor]    = useState("");
  const [action,   setAction]   = useState("");
  const [resType,  setResType]  = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["audit", page, actor, action, resType],
    queryFn:  () => auditApi.list({ page, actor: actor || undefined, action: action || undefined, resourceType: resType || undefined }),
    staleTime: 30_000,
  });

  const handleExport = () => {
    const events = data?.events ?? [];
    const header = ["Timestamp","Actor","Action","Resource Type","Resource","IP Address"].join(",");
    const rows = events.map((e) => [
      e.timestamp, e.actor_name, e.action, e.resource_type, e.resource_title || e.resource_id, e.ip_address,
    ].map((v) => { const s = String(v); return s.includes(",") ? `"${s}"` : s; }).join(","));
    const csv = [header, ...rows].join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    const a = document.createElement("a"); a.href = url; a.download = "audit-log.csv"; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="pb-6">
      <div className="flex items-start justify-between mb-5 flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-extrabold text-text-primary font-display">Audit Log</h1>
          <p className="text-xs text-text-muted mt-0.5">All analyst and admin actions with before/after diffs</p>
        </div>
        <button onClick={handleExport} className="btn btn-ghost btn-sm flex items-center gap-1.5">
          <Download size={12} /> Export CSV
        </button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-2 mb-3 flex-wrap">
        <div className="relative flex-1 min-w-44">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted pointer-events-none" />
          <input type="search" placeholder="Filter by actor…" value={actor}
            onChange={(e) => setActor(e.target.value)}
            className="w-full bg-bg-elevated border border-border rounded-lg pl-7 pr-3 py-1.5 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent" />
        </div>
        <input type="search" placeholder="Action type…" value={action}
          onChange={(e) => setAction(e.target.value)}
          className="bg-bg-elevated border border-border rounded-lg px-3 py-1.5 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent w-44" />
      </div>
      {/* Resource type chips */}
      <div className="flex items-center gap-1 mb-4 flex-wrap">
        {['', 'alert', 'investigation', 'rule', 'agent', 'user', 'tenant'].map((v) => (
          <button
            key={v || 'all'}
            onClick={() => setResType(v)}
            style={{
              padding: '3px 10px', borderRadius: 5, border: 'none', cursor: 'pointer',
              fontSize: 11, fontWeight: 600, transition: 'all 100ms',
              background: resType === v ? 'rgba(59,130,246,0.12)' : 'rgba(255,255,255,0.04)',
              color: resType === v ? '#60A5FA' : '#5C6373',
            }}
          >
            {v ? v.charAt(0).toUpperCase() + v.slice(1) : 'All Resources'}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="bg-bg-card border border-border rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-bg-elevated border-b border-border">
            <tr>
              {["Timestamp","Actor","Action","Resource","IP"].map((h) => (
                <th key={h} className="text-left px-3 py-2.5 text-text-muted font-semibold uppercase tracking-wider text-2xs">{h}</th>
              ))}
              <th className="w-8" />
            </tr>
          </thead>
          <tbody>
            {isLoading
              ? Array.from({ length: 8 }, (_, i) => (
                  <tr key={i} className="border-b border-border/50">
                    {Array.from({ length: 6 }, (_, j) => <td key={j} className="px-3 py-2.5"><div className="skel h-4 rounded" /></td>)}
                  </tr>
                ))
              : (data?.events ?? []).map((e) => <AuditRow key={e.id} event={e} />)
            }
          </tbody>
        </table>

        {data && data.total > 50 && (
          <div className="flex items-center justify-between px-4 py-2.5 border-t border-border bg-bg-elevated">
            <span className="text-xs text-text-muted">
              {(page - 1) * 50 + 1}–{Math.min(page * 50, data.total)} of {data.total}
            </span>
            <div className="flex gap-1">
              <button disabled={page === 1} onClick={() => setPage(p => p - 1)} className="btn btn-ghost btn-xs">Prev</button>
              <button disabled={page * 50 >= data.total} onClick={() => setPage(p => p + 1)} className="btn btn-ghost btn-xs">Next</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
