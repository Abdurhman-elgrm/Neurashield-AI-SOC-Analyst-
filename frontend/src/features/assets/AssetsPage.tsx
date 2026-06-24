import { useEffect, useState, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Search, Download, Shield, Wifi, WifiOff, ChevronRight,
  AlertTriangle, RefreshCw,
} from "lucide-react";
import { fleetApi } from "@/api/fleet";
import type { FleetAgent } from "@/api/fleet";
import { cn } from "@/lib/utils";
import { useTenantStore } from "@/stores/tenantStore";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function riskBadge(score: number): { label: string; cls: string } {
  if (score >= 80) return { label: "Critical", cls: "bg-severity-critical/15 text-severity-critical" };
  if (score >= 60) return { label: "High",     cls: "bg-severity-high/15 text-severity-high"     };
  if (score >= 30) return { label: "Medium",   cls: "bg-severity-medium/15 text-severity-medium" };
  return               { label: "Low",      cls: "bg-severity-low/15 text-severity-low"      };
}

function escCsv(v: string | number): string {
  const s = String(v);
  return s.includes(",") || s.includes('"') ? `"${s.replace(/"/g, '""')}"` : s;
}

// ─── Asset Drawer ─────────────────────────────────────────────────────────────

function AssetDrawer({ agent, onClose }: { agent: FleetAgent; onClose: () => void }) {
  const badge = riskBadge(agent.risk_score);
  return (
    <div className="fixed inset-y-0 right-0 w-96 bg-bg-card border-l border-border z-50 flex flex-col shadow-2xl">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <h2 className="text-sm font-bold text-text-primary">{agent.hostname}</h2>
        <button onClick={onClose} className="text-text-muted hover:text-text-primary transition-colors">✕</button>
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        <div className="grid grid-cols-2 gap-3">
          {[
            { label: "OS", value: `${agent.os_type} ${agent.os_version}` },
            { label: "Agent Version", value: agent.agent_version },
            { label: "IP Address", value: agent.ip_address },
            { label: "Status", value: agent.status },
            { label: "Last Seen", value: new Date(agent.last_seen).toLocaleString() },
            { label: "Risk Score", value: (
              <span className={cn("px-2 py-0.5 rounded text-xs font-bold", badge.cls)}>{badge.label} ({agent.risk_score})</span>
            )},
          ].map((f) => (
            <div key={f.label}>
              <p className="text-2xs text-text-muted uppercase tracking-wider mb-0.5">{f.label}</p>
              <p className="text-xs text-text-primary">{f.value}</p>
            </div>
          ))}
        </div>

        <div className="bg-bg-elevated rounded-lg p-3">
          <p className="text-2xs font-bold uppercase tracking-wider text-text-muted mb-2">Alert Summary</p>
          <div className="flex gap-4">
            <div className="text-center">
              <p className="text-2xl font-extrabold font-mono text-severity-critical">{agent.critical_alert_count}</p>
              <p className="text-2xs text-text-muted">Critical</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-extrabold font-mono text-text-primary">{agent.open_alert_count}</p>
              <p className="text-2xs text-text-muted">Total Open</p>
            </div>
          </div>
        </div>

        {agent.tags.length > 0 && (
          <div>
            <p className="text-2xs font-bold uppercase tracking-wider text-text-muted mb-2">Tags</p>
            <div className="flex flex-wrap gap-1">
              {agent.tags.map((t) => (
                <span key={t} className="px-2 py-0.5 rounded bg-bg-elevated text-xs text-text-secondary">{t}</span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── AssetsPage ───────────────────────────────────────────────────────────────

export function AssetsPage() {
  useEffect(() => { document.title = "Asset Risk Posture — NEURASHIELD"; }, []);

  const hasRole    = useTenantStore((s) => s.hasRole);
  const [search,   setSearch]   = useState("");
  const [osFilter, setOsFilter] = useState("");
  const [selected, setSelected] = useState<FleetAgent | null>(null);
  const [page,     setPage]     = useState(1);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["fleet", "agents", page, search, osFilter],
    queryFn:  () => fleetApi.list({ page, search: search || undefined, os: osFilter || undefined }),
    staleTime: 30_000,
  });

  const handleExport = useCallback(() => {
    const agents = data?.agents ?? [];
    const header = ["Hostname","OS","IP","Status","Last Seen","Open Alerts","Critical Alerts","Risk Score","Tags"].join(",");
    const rows = agents.map((a) => [
      a.hostname, `${a.os_type} ${a.os_version}`, a.ip_address, a.status,
      a.last_seen, a.open_alert_count, a.critical_alert_count, a.risk_score,
      a.tags.join("|"),
    ].map(escCsv).join(","));
    const csv = [header, ...rows].join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    const a = document.createElement("a"); a.href = url; a.download = "assets.csv"; a.click();
    URL.revokeObjectURL(url);
  }, [data]);

  return (
    <div className="pb-6">
      <div className="flex items-start justify-between mb-5 flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-extrabold text-text-primary font-display">Asset Risk Posture</h1>
          <p className="text-xs text-text-muted mt-0.5">Host inventory with live risk scoring</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => void refetch()} className="btn btn-ghost btn-sm flex items-center gap-1.5">
            <RefreshCw size={12} /> Refresh
          </button>
          <button onClick={handleExport} className="btn btn-ghost btn-sm flex items-center gap-1.5">
            <Download size={12} /> Export CSV
          </button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-2 mb-4 flex-wrap">
        <div className="relative flex-1 min-w-52">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted pointer-events-none" />
          <input
            type="search"
            placeholder="Search hostname…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-bg-elevated border border-border rounded-lg pl-8 pr-3 py-1.5 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
          />
        </div>
        <div style={{
          display: 'flex', gap: 2,
          background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)',
          borderRadius: 7, padding: 3,
        }}>
          {[
            { value: '', label: 'All OS' },
            { value: 'windows', label: 'Windows' },
            { value: 'linux',   label: 'Linux'   },
            { value: 'macos',   label: 'macOS'   },
          ].map(({ value, label }) => (
            <button key={value || 'all'} onClick={() => setOsFilter(value)} style={{
              padding: '4px 10px', borderRadius: 4, border: 'none', cursor: 'pointer',
              fontSize: 11, fontWeight: 600, transition: 'all 100ms',
              background: osFilter === value ? 'rgba(59,130,246,0.12)' : 'transparent',
              color: osFilter === value ? '#60A5FA' : '#5C6373',
            }}>
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Stats strip */}
      {data?.stats && (
        <div className="grid grid-cols-4 gap-3 mb-4">
          {[
            { label: "Total Agents",   value: data.stats.total,              color: "#8B95A7" },
            { label: "Online",         value: `${data.stats.online_pct.toFixed(0)}%`, color: "#10B981" },
            { label: "Critical Alerts",value: data.stats.critical_alerts_active, color: "#EF4444" },
            { label: "Need Update",    value: data.stats.agents_need_update,  color: "#F59E0B" },
          ].map((s) => (
            <div key={s.label} className="bg-bg-card border border-border rounded-lg p-3 text-center">
              <p className="text-xl font-extrabold font-mono" style={{ color: s.color }}>{s.value}</p>
              <p className="text-2xs text-text-muted uppercase tracking-wider mt-0.5">{s.label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Table */}
      <div className="bg-bg-card border border-border rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-bg-elevated border-b border-border">
            <tr>
              {["Hostname","OS","Status","Last Seen","Alerts","Risk"].map((h) => (
                <th key={h} className="text-left px-3 py-2.5 text-text-muted font-semibold uppercase tracking-wider text-2xs">{h}</th>
              ))}
              <th className="w-8" />
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              Array.from({ length: 8 }, (_, i) => (
                <tr key={i} className="border-b border-border/50">
                  {Array.from({ length: 7 }, (_, j) => <td key={j} className="px-3 py-2.5"><div className="skel h-4 rounded" /></td>)}
                </tr>
              ))
            ) : (data?.agents ?? []).map((a) => {
              const badge = riskBadge(a.risk_score);
              return (
                <tr
                  key={a.agent_id}
                  className="border-b border-border/50 hover:bg-bg-elevated/50 cursor-pointer transition-colors"
                  onClick={() => setSelected(a)}
                >
                  <td className="px-3 py-2.5 font-mono text-text-primary font-medium">{a.hostname}</td>
                  <td className="px-3 py-2.5 text-text-secondary">{a.os_type}</td>
                  <td className="px-3 py-2.5">
                    <span className={cn("flex items-center gap-1", a.status === "online" ? "text-status-online" : "text-text-muted")}>
                      {a.status === "online" ? <Wifi size={11} /> : <WifiOff size={11} />}
                      {a.status}
                    </span>
                  </td>
                  <td className="px-3 py-2.5 text-text-muted font-mono">
                    {new Date(a.last_seen).toLocaleString([], { dateStyle: "short", timeStyle: "short" })}
                  </td>
                  <td className="px-3 py-2.5">
                    {a.critical_alert_count > 0 && (
                      <span className="flex items-center gap-1 text-severity-critical">
                        <AlertTriangle size={10} /> {a.critical_alert_count}
                      </span>
                    )}
                    {a.critical_alert_count === 0 && (
                      <span className="text-text-muted">{a.open_alert_count}</span>
                    )}
                  </td>
                  <td className="px-3 py-2.5">
                    <span className={cn("px-1.5 py-0.5 rounded text-2xs font-bold", badge.cls)}>{badge.label}</span>
                  </td>
                  <td className="px-3 py-2.5 text-text-muted"><ChevronRight size={12} /></td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {/* Pagination */}
        {data && data.total > 50 && (
          <div className="flex items-center justify-between px-4 py-2.5 border-t border-border bg-bg-elevated">
            <span className="text-xs text-text-muted">
              {(page - 1) * 50 + 1}–{Math.min(page * 50, data.total)} of {data.total}
            </span>
            <div className="flex gap-1">
              <button disabled={page === 1} onClick={() => setPage(p => p - 1)}
                className="btn btn-ghost btn-xs">Prev</button>
              <button disabled={page * 50 >= data.total} onClick={() => setPage(p => p + 1)}
                className="btn btn-ghost btn-xs">Next</button>
            </div>
          </div>
        )}
      </div>

      {/* Containment actions for admins/analysts */}
      {hasRole("analyst") && (
        <div className="mt-3 flex items-center gap-2">
          <Shield size={12} className="text-text-muted" />
          <span className="text-xs text-text-muted">
            Select rows and use bulk actions to quarantine hosts — available to analyst+ roles.
          </span>
        </div>
      )}

      {/* Drawer */}
      {selected && (
        <>
          <div className="fixed inset-0 bg-black/40 z-40" onClick={() => setSelected(null)} />
          <AssetDrawer agent={selected} onClose={() => setSelected(null)} />
        </>
      )}
    </div>
  );
}
