import { useEffect, useState, useMemo } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { Wifi, WifiOff, RefreshCw, AlertTriangle, UploadCloud, Search } from "lucide-react";
import { fleetApi } from "@/api/fleet";
import { useTenantStore } from "@/stores/tenantStore";
import { toastError, toastSuccess } from "@/lib/toast";
import { extractApiError } from "@/lib/utils";
import { WidgetErrorBoundary } from "@/components/ui/WidgetErrorBoundary";

// ─── Status distribution ──────────────────────────────────────────────────────

const STATUS_COLORS = ["#10B981", "#5C6373", "#F59E0B"];

function StatusDonut({ online, offline, stale }: { online: number; offline: number; stale: number }) {
  const data = [
    { name: "Online", value: online },
    { name: "Offline", value: offline },
    { name: "Stale",  value: stale  },
  ];
  return (
    <div className="flex items-center gap-4">
      <ResponsiveContainer width={100} height={100}>
        <PieChart>
          <Pie data={data} cx="50%" cy="50%" innerRadius={28} outerRadius={46} dataKey="value">
            {data.map((_e, i) => <Cell key={i} fill={STATUS_COLORS[i]} />)}
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      <div className="space-y-1.5">
        {data.map((d, i) => (
          <div key={d.name} className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: STATUS_COLORS[i] }} />
            <span className="text-xs text-text-secondary">{d.name}</span>
            <span className="text-xs font-mono text-text-primary ml-auto pl-4">{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── FleetDashboardPage ───────────────────────────────────────────────────────

export function FleetDashboardPage() {
  useEffect(() => { document.title = "Fleet Dashboard — NEURASHIELD"; }, []);

  const hasRole = useTenantStore((s) => s.hasRole);
  const [selected, setSelected] = useState<string[]>([]);
  const [page, setPage] = useState(1);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["fleet", "agents", page],
    queryFn: () => fleetApi.list({ page }),
    staleTime: 30_000,
  });

  const { data: versionDist } = useQuery({
    queryKey: ["fleet", "version-dist"],
    queryFn: fleetApi.getVersionDistribution,
    staleTime: 300_000,
  });

  const { data: heartbeatDist } = useQuery({
    queryKey: ["fleet", "heartbeat-dist"],
    queryFn: fleetApi.getHeartbeatDistribution,
    staleTime: 60_000,
  });

  const updateMutation = useMutation({
    mutationFn: (ids: string[]) => fleetApi.bulkUpdate(ids),
    onSuccess: () => { void refetch(); setSelected([]); toastSuccess("Update scheduled", "Fleet"); },
    onError: (e) => toastError(extractApiError(e), "Update failed"),
  });

  const reinstallMutation = useMutation({
    mutationFn: (ids: string[]) => fleetApi.forceReinstall(ids),
    onSuccess: () => { void refetch(); setSelected([]); toastSuccess("Reinstall scheduled", "Fleet"); },
    onError: (e) => toastError(extractApiError(e), "Reinstall failed"),
  });

  const [agentSearch,   setAgentSearch]   = useState("");
  const [statusFilter,  setStatusFilter]  = useState("");

  const toggleSelect = (id: string) =>
    setSelected((s) => s.includes(id) ? s.filter((x) => x !== id) : [...s, id]);

  const stats = data?.stats;

  // Guard against API returning non-array values (defensive — recharts calls .map() internally)
  const safeVersionDist   = Array.isArray(versionDist)   ? versionDist   : [];
  const safeHeartbeatDist = Array.isArray(heartbeatDist) ? heartbeatDist : [];

  const filteredAgents = useMemo(() => {
    let list = data?.agents ?? [];
    if (agentSearch.trim()) {
      const q = agentSearch.toLowerCase();
      list = list.filter(a => a.hostname.toLowerCase().includes(q) || a.ip_address?.toLowerCase().includes(q));
    }
    if (statusFilter) list = list.filter(a => a.status === statusFilter);
    return list;
  }, [data?.agents, agentSearch, statusFilter]);

  const STATUS_CHIPS = [
    { value: "",        label: "All",     color: "#8B95A7" },
    { value: "online",  label: "Online",  color: "#10B981" },
    { value: "offline", label: "Offline", color: "#5C6373" },
    { value: "degraded", label: "Degraded", color: "#F59E0B" },
  ] as const;

  return (
    <div className="pb-6">
      <div className="flex items-start justify-between mb-5 flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-extrabold text-text-primary font-display">Fleet Dashboard</h1>
          <p className="text-xs text-text-muted mt-0.5">Agent health, version distribution, and bulk management</p>
        </div>
        <div className="flex items-center gap-2">
          {selected.length > 0 && hasRole("analyst") && (
            <>
              <button
                onClick={() => updateMutation.mutate(selected)}
                disabled={updateMutation.isPending}
                className="btn btn-ghost btn-sm flex items-center gap-1.5"
              >
                <UploadCloud size={12} /> Update {selected.length} agent{selected.length !== 1 ? "s" : ""}
              </button>
              <button
                onClick={() => reinstallMutation.mutate(selected)}
                disabled={reinstallMutation.isPending}
                className="btn btn-ghost btn-sm flex items-center gap-1.5 text-severity-high"
              >
                <RefreshCw size={12} /> Force Reinstall
              </button>
            </>
          )}
          <button onClick={() => void refetch()} className="btn btn-ghost btn-sm flex items-center gap-1.5">
            <RefreshCw size={12} /> Refresh
          </button>
        </div>
      </div>

      {/* KPI strip */}
      {stats && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginBottom: 16 }}>
          {[
            { label: "Total Agents",    value: stats.total,                            color: "#8B95A7", sublabel: "enrolled",        icon: Wifi         },
            { label: "Online",          value: `${stats.online_pct.toFixed(0)}%`,      color: "#10B981", sublabel: `${stats.online} agents`,   icon: Wifi         },
            { label: "Critical Alerts", value: stats.critical_alerts_active,           color: "#EF4444", sublabel: "unresolved",       icon: AlertTriangle },
            { label: "Need Update",     value: stats.agents_need_update,               color: "#F59E0B", sublabel: "behind on version", icon: UploadCloud  },
          ].map(({ label, value, color, sublabel, icon: Icon }) => (
            <div key={label} style={{
              background: "#0D0D0D",
              border: "1px solid rgba(255,255,255,0.06)",
              borderLeft: `3px solid ${color}`,
              borderRadius: 8, padding: "12px 14px",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                <Icon size={11} style={{ color, flexShrink: 0 }} />
                <span style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1.2px", color: "#5C6373" }}>{label}</span>
              </div>
              <div style={{ fontSize: 22, fontWeight: 800, color, fontFamily: "'JetBrains Mono', monospace", lineHeight: 1 }}>{value}</div>
              <div style={{ fontSize: 10, color: "#3A4150", marginTop: 4 }}>{sublabel}</div>
            </div>
          ))}
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 mb-4">
        {/* Status donut */}
        <WidgetErrorBoundary title="Agent Status">
          <div className="bg-bg-card border border-border rounded-xl p-4">
            <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted mb-3">Status Distribution</h3>
            {stats ? (
              <StatusDonut online={stats.online} offline={stats.offline} stale={stats.stale} />
            ) : <div className="skel h-24 rounded-lg" />}
          </div>
        </WidgetErrorBoundary>

        {/* Version distribution */}
        <WidgetErrorBoundary title="Version Distribution">
          <div className="bg-bg-card border border-border rounded-xl p-4">
            <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted mb-3">Agent Version Distribution</h3>
            {safeVersionDist.length === 0 ? <div className="skel h-24 rounded-lg" /> : (
              <ResponsiveContainer width="100%" height={100}>
                <BarChart data={safeVersionDist} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                  <XAxis dataKey="version" tick={{ fill: "#5C6373", fontSize: 9 }} />
                  <YAxis tick={{ fill: "#5C6373", fontSize: 9 }} />
                  <Tooltip contentStyle={{ background: "#111", border: "1px solid #1F2937", fontSize: 11 }} />
                  <Bar dataKey="count" fill="#3B82F6" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </WidgetErrorBoundary>
      </div>

      {/* Heartbeat distribution */}
      {safeHeartbeatDist.length > 0 && (
        <div style={{ background: "#0D0D0D", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 12, padding: 16, marginBottom: 12 }}>
          <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1.5px", color: "#5C6373", marginBottom: 12 }}>
            Last-Seen Distribution
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            {safeHeartbeatDist.map((h) => (
              <div key={h.bucket} style={{
                flex: 1, textAlign: "center", padding: "10px 8px",
                background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)",
                borderRadius: 8,
              }}>
                <div style={{ fontSize: 20, fontWeight: 800, fontFamily: "'JetBrains Mono', monospace", color: "#F5F7FA" }}>{h.count}</div>
                <div style={{ fontSize: 9, color: "#5C6373", marginTop: 4, fontWeight: 600 }}>{h.label}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Agent table */}
      <div style={{ background: "#0D0D0D", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 12, overflow: "hidden" }}>
        {/* Search + filter toolbar */}
        <div style={{
          display: "flex", alignItems: "center", gap: 8,
          padding: "10px 14px", borderBottom: "1px solid rgba(255,255,255,0.06)",
        }}>
          <div style={{ position: "relative", flex: 1, maxWidth: 280 }}>
            <Search size={12} style={{ position: "absolute", left: 8, top: "50%", transform: "translateY(-50%)", color: "#5C6373", pointerEvents: "none" }} />
            <input
              value={agentSearch}
              onChange={e => setAgentSearch(e.target.value)}
              placeholder="Search hostname or IP…"
              style={{
                width: "100%", paddingLeft: 26, height: 30, borderRadius: 6,
                fontSize: 12, background: "rgba(255,255,255,0.04)",
                border: "1px solid rgba(255,255,255,0.07)", color: "#F5F7FA",
                outline: "none", boxSizing: "border-box",
              }}
            />
          </div>
          <div style={{ display: "flex", gap: 2, background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: 2 }}>
            {STATUS_CHIPS.map(chip => (
              <button key={chip.value} onClick={() => setStatusFilter(chip.value)} style={{
                padding: "3px 9px", borderRadius: 4, border: "none", cursor: "pointer",
                fontSize: 11, fontWeight: 600, transition: "all 100ms",
                background: statusFilter === chip.value ? `${chip.color}18` : "transparent",
                color: statusFilter === chip.value ? chip.color : "#5C6373",
              }}>
                {chip.label}
              </button>
            ))}
          </div>
          {selected.length > 0 && (
            <span style={{ fontSize: 11, color: "#60A5FA", marginLeft: "auto" }}>
              {selected.length} selected
            </span>
          )}
          {filteredAgents.length !== (data?.agents ?? []).length && (
            <span style={{ fontSize: 11, color: "#5C6373" }}>
              {filteredAgents.length}/{data?.agents?.length ?? 0}
            </span>
          )}
        </div>

        <table className="w-full text-xs">
          <thead style={{ background: "rgba(255,255,255,0.02)", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
            <tr>
              <th style={{ width: 32, padding: "8px 12px" }} />
              {["Hostname","OS","Version","Status","Last Seen","Alerts","Update"].map((h) => (
                <th key={h} style={{ textAlign: "left", padding: "8px 12px", fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1px", color: "#3A4150" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {isLoading ? Array.from({ length: 6 }, (_, i) => (
              <tr key={i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                {Array.from({ length: 8 }, (_, j) => <td key={j} style={{ padding: "10px 12px" }}><div className="skel h-4 rounded" /></td>)}
              </tr>
            )) : filteredAgents.map((a) => (
              <tr key={a.agent_id} style={{
                borderBottom: "1px solid rgba(255,255,255,0.04)",
                background: selected.includes(a.agent_id) ? "rgba(59,130,246,0.04)" : "transparent",
                transition: "background 100ms",
              }}
              onMouseEnter={e => { if (!selected.includes(a.agent_id)) e.currentTarget.style.background = "rgba(255,255,255,0.02)"; }}
              onMouseLeave={e => { if (!selected.includes(a.agent_id)) e.currentTarget.style.background = "transparent"; }}
              >
                <td style={{ padding: "10px 12px" }}>
                  <input type="checkbox" checked={selected.includes(a.agent_id)}
                    onChange={() => toggleSelect(a.agent_id)}
                    className="accent-accent w-3 h-3" aria-label={`Select ${a.hostname}`} />
                </td>
                <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, color: "#F5F7FA", fontSize: 12 }}>{a.hostname}</td>
                <td style={{ padding: "10px 12px", color: "#8B95A7", fontSize: 11 }}>{a.os_type}</td>
                <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", color: "#5C6373", fontSize: 11 }}>{a.agent_version}</td>
                <td style={{ padding: "10px 12px" }}>
                  <span style={{
                    display: "inline-flex", alignItems: "center", gap: 5, fontSize: 11,
                    color: a.status === "online" ? "#10B981" : a.status === "stale" ? "#F59E0B" : "#5C6373",
                    fontWeight: 600,
                  }}>
                    {a.status === "online" ? <Wifi size={10} /> : <WifiOff size={10} />}
                    {a.status}
                  </span>
                </td>
                <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", color: "#5C6373", fontSize: 10 }}>
                  {new Date(a.last_seen).toLocaleString([], { dateStyle: "short", timeStyle: "short" })}
                </td>
                <td style={{ padding: "10px 12px" }}>
                  {a.open_alert_count > 0 && (
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 4, color: "#F97316", fontSize: 11, fontWeight: 600 }}>
                      <AlertTriangle size={10} /> {a.open_alert_count}
                    </span>
                  )}
                </td>
                <td style={{ padding: "10px 12px" }}>
                  {a.update_available && (
                    <span style={{
                      padding: "2px 7px", borderRadius: 4, fontSize: 9, fontWeight: 700,
                      background: "rgba(245,158,11,0.12)", color: "#F59E0B",
                      border: "1px solid rgba(245,158,11,0.25)", textTransform: "uppercase",
                    }}>
                      Update
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {data && data.total > 50 && (
          <div style={{
            display: "flex", alignItems: "center", justifyContent: "space-between",
            padding: "10px 14px", borderTop: "1px solid rgba(255,255,255,0.06)",
            background: "rgba(255,255,255,0.01)",
          }}>
            <span style={{ fontSize: 11, color: "#5C6373" }}>{(page-1)*50+1}–{Math.min(page*50, data.total)} of {data.total}</span>
            <div style={{ display: "flex", gap: 4 }}>
              <button disabled={page===1} onClick={() => setPage(p=>p-1)} className="btn btn-ghost btn-xs">Prev</button>
              <button disabled={page*50>=data.total} onClick={() => setPage(p=>p+1)} className="btn btn-ghost btn-xs">Next</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
