import { useEffect, useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, ReferenceLine,
} from "recharts";
import {
  AlertTriangle, CheckCircle, Clock, TrendingUp, TrendingDown,
  Users, ChevronLeft, ChevronRight, Download, RefreshCw,
} from "lucide-react";
import { socMetricsApi } from "@/api/soc-metrics";
import type {
  SLASummary, SLABySeverityRow, SLABreachAlert,
  AnalystSLARow, ResponseTimeBin, SLABreachPoint,
} from "@/api/soc-metrics";
import { WidgetErrorBoundary } from "@/components/ui/WidgetErrorBoundary";
import { cn } from "@/lib/utils";

// ─── Types ────────────────────────────────────────────────────────────────────

type TimeRange = "7d" | "30d" | "90d";

// ─── Sample data ─────────────────────────────────────────────────────────────

const SAMPLE_SUMMARY: SLASummary = {
  compliance_pct: 87.4,
  compliance_delta: +2.1,
  total_breaches: 34,
  breach_delta: -8,
  avg_response_minutes: 38,
  avg_resolve_minutes: 214,
  within_sla: 246,
  total: 280,
};

const SAMPLE_BY_SEVERITY: SLABySeverityRow[] = [
  { severity: "critical", target_minutes: 120,  avg_minutes: 143,  compliance_pct: 72.1, total_alerts: 28,  breached: 8  },
  { severity: "high",     target_minutes: 240,  avg_minutes: 201,  compliance_pct: 85.3, total_alerts: 74,  breached: 11 },
  { severity: "medium",   target_minutes: 480,  avg_minutes: 312,  compliance_pct: 94.2, total_alerts: 121, breached: 7  },
  { severity: "low",      target_minutes: 1440, avg_minutes: 680,  compliance_pct: 98.1, total_alerts: 57,  breached: 1  },
];

function makeTrend(days: number): SLABreachPoint[] {
  const now = Date.now();
  return Array.from({ length: days }, (_, i) => {
    const d = new Date(now - (days - i) * 86400_000);
    const label = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
    const base = 8 + Math.sin(i / 4) * 4 + Math.random() * 3;
    return { date: label, warn_breach_pct: parseFloat(base.toFixed(1)), crit_breach_pct: parseFloat((base * 0.4).toFixed(1)) };
  });
}

const SAMPLE_TREND_30: SLABreachPoint[] = makeTrend(30);
const SAMPLE_TREND_7:  SLABreachPoint[] = makeTrend(7);
const SAMPLE_TREND_90: SLABreachPoint[] = makeTrend(90);

const SAMPLE_BREACHES: SLABreachAlert[] = [
  { alert_id: "a1", title: "Lateral movement detected — DESKTOP-A",  severity: "critical", created_at: new Date(Date.now()-7_200_000).toISOString(), resolved_at: null,                                         assigned_to: "Marcus Webb",    elapsed_minutes: 120, target_minutes: 120, breach_type: "response" },
  { alert_id: "a2", title: "Encoded PowerShell execution on DC01",    severity: "critical", created_at: new Date(Date.now()-18_000_000).toISOString(), resolved_at: new Date(Date.now()-14_000_000).toISOString(), assigned_to: "Sara Kim",        elapsed_minutes: 290, target_minutes: 120, breach_type: "resolution" },
  { alert_id: "a3", title: "After-hours data access — FileServer",    severity: "high",     created_at: new Date(Date.now()-86_400_000).toISOString(), resolved_at: new Date(Date.now()-80_000_000).toISOString(), assigned_to: "James Torres",   elapsed_minutes: 380, target_minutes: 240, breach_type: "resolution" },
  { alert_id: "a4", title: "Suspicious DNS tunneling activity",       severity: "high",     created_at: new Date(Date.now()-172_800_000).toISOString(), resolved_at: null,                                        assigned_to: null,             elapsed_minutes: 1440, target_minutes: 240, breach_type: "response" },
  { alert_id: "a5", title: "Credential stuffing — Auth service",      severity: "critical", created_at: new Date(Date.now()-259_200_000).toISOString(), resolved_at: new Date(Date.now()-255_000_000).toISOString(), assigned_to: "Marcus Webb", elapsed_minutes: 185, target_minutes: 120, breach_type: "resolution" },
  { alert_id: "a6", title: "Registry run key modification detected",  severity: "medium",   created_at: new Date(Date.now()-345_600_000).toISOString(), resolved_at: new Date(Date.now()-340_000_000).toISOString(), assigned_to: "Sara Kim",    elapsed_minutes: 520, target_minutes: 480, breach_type: "resolution" },
  { alert_id: "a7", title: "WMI-based remote execution attempt",      severity: "high",     created_at: new Date(Date.now()-432_000_000).toISOString(), resolved_at: new Date(Date.now()-428_000_000).toISOString(), assigned_to: "James Torres", elapsed_minutes: 310, target_minutes: 240, breach_type: "resolution" },
  { alert_id: "a8", title: "New external IP in authentication logs",  severity: "medium",   created_at: new Date(Date.now()-518_400_000).toISOString(), resolved_at: new Date(Date.now()-512_000_000).toISOString(), assigned_to: "Priya Patel",  elapsed_minutes: 495, target_minutes: 480, breach_type: "resolution" },
];

const SAMPLE_ANALYST_SLA: AnalystSLARow[] = [
  { user_id: "u1", name: "Marcus Webb",   handled: 84, within_sla: 76, compliance_pct: 90.5, avg_response_minutes: 28,  avg_resolve_minutes: 195, open_breaches: 2 },
  { user_id: "u2", name: "Sara Kim",      handled: 71, within_sla: 62, compliance_pct: 87.3, avg_response_minutes: 41,  avg_resolve_minutes: 228, open_breaches: 3 },
  { user_id: "u3", name: "James Torres",  handled: 59, within_sla: 49, compliance_pct: 83.1, avg_response_minutes: 55,  avg_resolve_minutes: 310, open_breaches: 4 },
  { user_id: "u4", name: "Priya Patel",   handled: 66, within_sla: 59, compliance_pct: 89.4, avg_response_minutes: 32,  avg_resolve_minutes: 185, open_breaches: 1 },
];

const SAMPLE_RT_DIST: ResponseTimeBin[] = [
  { label: "<15m",  max_minutes: 15,   critical: 3,  high: 8,  medium: 18, low: 12 },
  { label: "15-30m",max_minutes: 30,   critical: 6,  high: 22, medium: 41, low: 18 },
  { label: "30-60m",max_minutes: 60,   critical: 8,  high: 28, medium: 52, low: 22 },
  { label: "1-2h",  max_minutes: 120,  critical: 5,  high: 14, medium: 28, low: 11 },
  { label: "2-4h",  max_minutes: 240,  critical: 4,  high: 9,  medium: 15, low: 8  },
  { label: "4-8h",  max_minutes: 480,  critical: 2,  high: 5,  medium: 8,  low: 4  },
  { label: ">8h",   max_minutes: 99999,critical: 4,  high: 5,  medium: 4,  low: 2  },
];

// ─── Constants ────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: "#EF4444",
  high:     "#F97316",
  medium:   "#F59E0B",
  low:      "#6B7280",
};

const SLA_TARGETS: Record<string, { respond: number; label: string }> = {
  critical: { respond: 120,  label: "2h" },
  high:     { respond: 240,  label: "4h" },
  medium:   { respond: 480,  label: "8h" },
  low:      { respond: 1440, label: "24h" },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtMinutes(m: number): string {
  if (m >= 1440) return `${(m / 1440).toFixed(1)}d`;
  if (m >= 60)   return `${(m / 60).toFixed(1)}h`;
  return `${Math.round(m)}m`;
}

function fmtTs(iso: string): string {
  try {
    return new Date(iso).toLocaleString("en-US", {
      month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false,
    });
  } catch { return iso; }
}

function complianceColor(pct: number): string {
  if (pct >= 95) return "#10B981";
  if (pct >= 85) return "#F59E0B";
  return "#EF4444";
}

function Skel({ className }: { className?: string }) {
  return <div className={cn("skel rounded-lg animate-pulse", className)} />;
}

// ─── KPI Card ─────────────────────────────────────────────────────────────────

interface KpiProps {
  label: string;
  value: string;
  sublabel?: string;
  delta?: number;
  deltaLabel?: string;
  color: string;
  icon: React.ElementType;
  loading?: boolean;
}

function KpiCard({ label, value, sublabel, delta, deltaLabel, color, icon: Icon, loading }: KpiProps) {
  const positive = delta !== undefined ? delta >= 0 : null;
  return (
    <div className="bg-bg-card border border-border rounded-xl p-4 flex flex-col gap-2.5">
      <div className="flex items-center justify-between">
        <span className="text-2xs font-bold uppercase tracking-widest text-text-muted">{label}</span>
        <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: `${color}18` }}>
          <Icon size={13} style={{ color }} />
        </div>
      </div>
      {loading ? <Skel className="h-8 w-24" /> : (
        <div className="flex items-end gap-2">
          <span className="text-2xl font-extrabold font-mono text-text-primary leading-none">{value}</span>
          {delta !== undefined && (
            <span className={cn("text-xs font-semibold flex items-center gap-0.5 mb-0.5", positive ? "text-status-online" : "text-severity-high")}>
              {positive ? <TrendingUp size={11} /> : <TrendingDown size={11} />}
              {positive ? "+" : ""}{deltaLabel ?? delta}
            </span>
          )}
        </div>
      )}
      {sublabel && <p className="text-2xs text-text-muted">{sublabel}</p>}
    </div>
  );
}

// ─── Compliance Ring ─────────────────────────────────────────────────────────

function ComplianceRing({ pct, loading }: { pct: number; loading: boolean }) {
  const R = 44;
  const C = 2 * Math.PI * R;
  const dash = (pct / 100) * C;
  const color = complianceColor(pct);

  return (
    <div className="bg-bg-card border border-border rounded-xl p-4 flex flex-col items-center justify-center gap-2">
      <span className="text-2xs font-bold uppercase tracking-widest text-text-muted">Overall SLA Compliance</span>
      {loading ? <Skel className="w-28 h-28 rounded-full" /> : (
        <div className="relative">
          <svg width={112} height={112} viewBox="0 0 112 112" className="-rotate-90">
            <circle cx={56} cy={56} r={R} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth={10} />
            <circle
              cx={56} cy={56} r={R} fill="none"
              stroke={color} strokeWidth={10}
              strokeDasharray={`${dash} ${C - dash}`}
              strokeLinecap="round"
              style={{ transition: "stroke-dasharray 0.6s ease" }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-2xl font-extrabold font-mono leading-none" style={{ color }}>{pct.toFixed(1)}%</span>
            <span className="text-2xs text-text-muted mt-1">compliance</span>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── SLA by Severity ─────────────────────────────────────────────────────────

function SLABySeveritySection({ data, loading }: { data: SLABySeverityRow[]; loading: boolean }) {
  return (
    <div className="bg-bg-card border border-border rounded-xl p-4">
      <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted mb-4">SLA Compliance by Severity</h3>
      {loading ? <div className="space-y-3">{[1,2,3,4].map(i=><Skel key={i} className="h-14" />)}</div> : (
        <div className="space-y-4">
          {data.map((row) => {
            const color = SEV_COLOR[row.severity] ?? "#6B7280";
            const compColor = complianceColor(row.compliance_pct);
            const target = SLA_TARGETS[row.severity];
            return (
              <div key={row.severity}>
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold uppercase w-16" style={{ color }}>{row.severity}</span>
                    <span className="text-2xs text-text-muted">Target: {target?.label}</span>
                    <span className="text-2xs text-text-muted">·</span>
                    <span className="text-2xs text-text-muted">Avg: {fmtMinutes(row.avg_minutes)}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-2xs text-text-muted">{row.total_alerts - row.breached}/{row.total_alerts} within SLA</span>
                    <span className="text-sm font-bold font-mono" style={{ color: compColor }}>{row.compliance_pct.toFixed(1)}%</span>
                  </div>
                </div>
                <div className="h-2 bg-bg-elevated rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{ width: `${row.compliance_pct}%`, background: compColor }}
                  />
                </div>
                {row.compliance_pct < 90 && (
                  <p className="text-2xs text-severity-high mt-1 flex items-center gap-1">
                    <AlertTriangle size={9} />
                    {row.breached} breach{row.breached !== 1 ? "es" : ""} — below 90% target
                  </p>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Response Time Distribution ───────────────────────────────────────────────

function ResponseTimeChart({ data, loading }: { data: ResponseTimeBin[]; loading: boolean }) {
  return (
    <div className="bg-bg-card border border-border rounded-xl p-4">
      <div className="flex items-center gap-2 mb-3">
        <Clock size={13} className="text-accent" />
        <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted">Response Time Distribution</h3>
      </div>
      <div className="flex gap-3 text-2xs text-text-muted mb-3 flex-wrap">
        {[["critical","#EF4444"],["high","#F97316"],["medium","#F59E0B"],["low","#6B7280"]].map(([k,c])=>(
          <span key={k} className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm flex-shrink-0" style={{ background: c }} />{k}</span>
        ))}
      </div>
      {loading ? <Skel className="h-48" /> : (
        <ResponsiveContainer width="100%" height={190}>
          <BarChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -20 }} barCategoryGap="20%">
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
            <XAxis dataKey="label" tick={{ fill: "#5C6373", fontSize: 9 }} />
            <YAxis tick={{ fill: "#5C6373", fontSize: 9 }} />
            <Tooltip contentStyle={{ background: "#111", border: "1px solid #1F2937", fontSize: 11 }} />
            <Bar dataKey="critical" stackId="a" fill="#EF4444" opacity={0.85} />
            <Bar dataKey="high"     stackId="a" fill="#F97316" opacity={0.85} />
            <Bar dataKey="medium"   stackId="a" fill="#F59E0B" opacity={0.85} />
            <Bar dataKey="low"      stackId="a" fill="#6B7280" opacity={0.85} radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

// ─── SLA Breach Trend ─────────────────────────────────────────────────────────

function BreachTrendChart({ data, loading }: { data: SLABreachPoint[]; loading: boolean }) {
  const avg2h = data.length ? data.reduce((s, d) => s + d.warn_breach_pct, 0) / data.length : 0;
  const avg8h = data.length ? data.reduce((s, d) => s + d.crit_breach_pct, 0) / data.length : 0;

  return (
    <div className="bg-bg-card border border-border rounded-xl p-4">
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <TrendingDown size={13} className="text-severity-high" />
          <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted">SLA Breach Rate Trend</h3>
        </div>
        <div className="flex items-center gap-4 text-2xs text-text-muted">
          <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 bg-severity-medium inline-block" /> 2h SLA (avg {avg2h.toFixed(1)}%)</span>
          <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 bg-severity-critical inline-block" /> 8h SLA (avg {avg8h.toFixed(1)}%)</span>
        </div>
      </div>
      {loading ? <Skel className="h-52" /> : (
        <ResponsiveContainer width="100%" height={210}>
          <LineChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -15 }}>
            <defs>
              <linearGradient id="grad-warn" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="#F59E0B" stopOpacity={0.15} />
                <stop offset="95%" stopColor="#F59E0B" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
            <XAxis dataKey="date" tick={{ fill: "#5C6373", fontSize: 9 }} tickFormatter={(v: string) => v.slice(5)} />
            <YAxis tick={{ fill: "#5C6373", fontSize: 9 }} tickFormatter={(v: number) => `${v}%`} />
            <Tooltip
              contentStyle={{ background: "#111", border: "1px solid #1F2937", fontSize: 11 }}
              formatter={(v: number) => `${v.toFixed(1)}%`}
            />
            <ReferenceLine y={10} stroke="#F59E0B" strokeDasharray="4 4" strokeOpacity={0.5}
              label={{ value: "10% target", fill: "#F59E0B", fontSize: 9, position: "insideTopRight" }} />
            <Line type="monotone" dataKey="warn_breach_pct" name="2h SLA breach %" stroke="#F59E0B" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="crit_breach_pct" name="8h SLA breach %" stroke="#EF4444" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

// ─── Analyst SLA Table ────────────────────────────────────────────────────────

function AnalystSLATable({ data, loading }: { data: AnalystSLARow[]; loading: boolean }) {
  const sorted = useMemo(() => [...data].sort((a, b) => b.compliance_pct - a.compliance_pct), [data]);

  return (
    <div className="bg-bg-card border border-border rounded-xl overflow-hidden">
      <div className="px-4 py-3 border-b border-border flex items-center gap-2">
        <Users size={13} className="text-accent" />
        <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted">Analyst SLA Performance</h3>
      </div>
      {loading ? (
        <div className="p-4 space-y-3">{[1,2,3,4].map(i=><Skel key={i} className="h-10" />)}</div>
      ) : (
        <>
          {/* Header */}
          <div className="grid px-4 py-2.5 bg-bg-elevated border-b border-border text-2xs font-bold uppercase tracking-widest text-text-muted"
            style={{ gridTemplateColumns: "1fr 60px 90px 80px 80px 80px" }}>
            {["Analyst", "Handled", "Compliance", "Avg Respond", "Avg Resolve", "Open Breaches"].map(h=><span key={h}>{h}</span>)}
          </div>
          {sorted.map((row, i) => {
            const color = complianceColor(row.compliance_pct);
            return (
              <div key={row.user_id}
                className={cn("grid items-center px-4 py-3 text-xs border-b border-border/50 last:border-0 hover:bg-bg-elevated/50 transition-colors",
                  i === 0 && "bg-status-online/3")}
                style={{ gridTemplateColumns: "1fr 60px 90px 80px 80px 80px" }}>
                <div className="flex items-center gap-2.5">
                  <div className="w-6 h-6 rounded-full bg-accent/15 flex items-center justify-center text-2xs font-bold text-accent flex-shrink-0">
                    {row.name.charAt(0)}
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-text-primary">{row.name}</p>
                    <p className="text-2xs text-text-muted">{row.within_sla}/{row.handled} within SLA</p>
                  </div>
                </div>
                <span className="text-text-secondary font-mono tabular-nums">{row.handled}</span>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-1.5 bg-bg-elevated rounded-full overflow-hidden">
                    <div className="h-full rounded-full" style={{ width: `${row.compliance_pct}%`, background: color }} />
                  </div>
                  <span className="text-2xs font-bold font-mono tabular-nums w-10 text-right flex-shrink-0" style={{ color }}>{row.compliance_pct.toFixed(1)}%</span>
                </div>
                <span className="text-text-muted font-mono tabular-nums">{fmtMinutes(row.avg_response_minutes)}</span>
                <span className="text-text-muted font-mono tabular-nums">{fmtMinutes(row.avg_resolve_minutes)}</span>
                <span className={cn("font-mono tabular-nums font-semibold", row.open_breaches > 0 ? "text-severity-high" : "text-text-disabled")}>
                  {row.open_breaches > 0 ? row.open_breaches : "—"}
                </span>
              </div>
            );
          })}
        </>
      )}
    </div>
  );
}

// ─── Breach List ─────────────────────────────────────────────────────────────

const PAGE_SIZE = 6;

function BreachList({ data, loading }: { data: SLABreachAlert[]; loading: boolean }) {
  const [page, setPage] = useState(1);
  const total = data.length;
  const pages = Math.ceil(total / PAGE_SIZE);
  const slice = data.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  return (
    <div className="bg-bg-card border border-border rounded-xl overflow-hidden">
      <div className="px-4 py-3 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <AlertTriangle size={13} className="text-severity-high" />
          <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted">SLA Breaches</h3>
          {!loading && <span className="ml-1 text-2xs px-1.5 py-0.5 rounded bg-severity-high/15 text-severity-high font-bold">{total}</span>}
        </div>
        {pages > 1 && (
          <div className="flex items-center gap-1 text-xs text-text-muted">
            <button onClick={() => setPage(p => Math.max(1, p-1))} disabled={page === 1}
              className="p-1 rounded hover:bg-bg-elevated disabled:opacity-30 transition-colors">
              <ChevronLeft size={12} />
            </button>
            <span>{page} / {pages}</span>
            <button onClick={() => setPage(p => Math.min(pages, p+1))} disabled={page === pages}
              className="p-1 rounded hover:bg-bg-elevated disabled:opacity-30 transition-colors">
              <ChevronRight size={12} />
            </button>
          </div>
        )}
      </div>

      {loading ? (
        <div className="p-4 space-y-3">{[1,2,3,4].map(i=><Skel key={i} className="h-12" />)}</div>
      ) : total === 0 ? (
        <div className="flex flex-col items-center justify-center py-10 text-text-disabled">
          <CheckCircle size={28} className="mb-2 text-status-online/40" />
          <p className="text-xs">No SLA breaches in this period</p>
        </div>
      ) : (
        <>
          {/* Header */}
          <div className="grid px-4 py-2 bg-bg-elevated border-b border-border text-2xs font-bold uppercase tracking-widest text-text-muted"
            style={{ gridTemplateColumns: "1fr 70px 120px 100px 80px 90px" }}>
            {["Alert", "Severity", "Created", "Assigned To", "Elapsed", "Breach Type"].map(h=><span key={h}>{h}</span>)}
          </div>
          {slice.map((item) => {
            const color = SEV_COLOR[item.severity] ?? "#6B7280";
            const over  = item.elapsed_minutes - item.target_minutes;
            return (
              <div key={item.alert_id}
                className="grid items-center px-4 py-3 border-b border-border/50 last:border-0 hover:bg-bg-elevated/50 transition-colors text-xs"
                style={{ gridTemplateColumns: "1fr 70px 120px 100px 80px 90px" }}>
                <span className="text-text-secondary font-medium truncate pr-3">{item.title}</span>
                <span className="text-2xs font-bold uppercase px-1.5 py-0.5 rounded w-fit" style={{ background:`${color}15`, color, border:`1px solid ${color}30` }}>{item.severity}</span>
                <span className="text-text-muted font-mono text-2xs">{fmtTs(item.created_at)}</span>
                <span className="text-text-muted truncate">{item.assigned_to ?? <span className="text-text-disabled italic">unassigned</span>}</span>
                <span className="font-mono font-semibold text-severity-high">{fmtMinutes(item.elapsed_minutes)}</span>
                <div className="flex flex-col gap-0.5">
                  <span className="text-2xs font-semibold text-severity-high capitalize">{item.breach_type}</span>
                  <span className="text-2xs text-text-muted">+{fmtMinutes(over)} over</span>
                </div>
              </div>
            );
          })}
        </>
      )}
    </div>
  );
}

// ─── SLA Target Reference Panel ───────────────────────────────────────────────

function SLATargetReference() {
  const rows = [
    { sev: "Critical", color: "#EF4444", respond: "< 15 min", resolve: "< 2 hours",  note: "Immediate escalation required" },
    { sev: "High",     color: "#F97316", respond: "< 1 hour",  resolve: "< 4 hours",  note: "Analyst acknowledgement within 1h" },
    { sev: "Medium",   color: "#F59E0B", respond: "< 4 hours", resolve: "< 8 hours",  note: "Business hours response" },
    { sev: "Low",      color: "#6B7280", respond: "< 24 hours",resolve: "< 3 days",   note: "Next business day acceptable" },
  ];
  return (
    <div className="bg-bg-card border border-border rounded-xl overflow-hidden">
      <div className="px-4 py-3 border-b border-border">
        <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted">SLA Policy Reference</h3>
      </div>
      <div className="divide-y divide-border/50">
        {rows.map((r) => (
          <div key={r.sev} className="grid items-center px-4 py-2.5 text-xs" style={{ gridTemplateColumns: "70px 90px 90px 1fr" }}>
            <span className="font-bold text-2xs uppercase" style={{ color: r.color }}>{r.sev}</span>
            <span className="text-text-secondary font-mono">{r.respond}</span>
            <span className="text-text-secondary font-mono">{r.resolve}</span>
            <span className="text-text-muted">{r.note}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Export helper ────────────────────────────────────────────────────────────

function exportCsv(breaches: SLABreachAlert[]) {
  const headers = ["alert_id","title","severity","created_at","assigned_to","elapsed_minutes","target_minutes","breach_type"];
  const rows = breaches.map(b => headers.map(h => String((b as unknown as Record<string,unknown>)[h] ?? "")).join(","));
  const csv  = [headers.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a"); a.href = url; a.download = `sla-breaches-${Date.now()}.csv`; a.click();
  URL.revokeObjectURL(url);
}

// ─── SLADashboard ─────────────────────────────────────────────────────────────

export function SLADashboard() {
  useEffect(() => { document.title = "SLA Dashboard — NEURASHIELD"; }, []);

  const [timeRange, setTimeRange] = useState<TimeRange>("30d");

  const trendSample = timeRange === "7d" ? SAMPLE_TREND_7 : timeRange === "90d" ? SAMPLE_TREND_90 : SAMPLE_TREND_30;

  const { data: summary, isLoading: loadSummary } = useQuery({
    queryKey: ["metrics", "sla-summary", timeRange],
    queryFn: () => socMetricsApi.getSLASummary(timeRange).catch(() => SAMPLE_SUMMARY),
    staleTime: 120_000,
  });

  const { data: bySeverity, isLoading: loadBySev } = useQuery({
    queryKey: ["metrics", "sla-by-severity", timeRange],
    queryFn: () => socMetricsApi.getSLABySeverity(timeRange).catch(() => SAMPLE_BY_SEVERITY),
    staleTime: 120_000,
  });

  const { data: breachRate, isLoading: loadTrend } = useQuery({
    queryKey: ["metrics", "sla-breach-rate", timeRange],
    queryFn: () => socMetricsApi.getSLABreachRate(timeRange).catch(() => trendSample),
    staleTime: 120_000,
  });

  const { data: breachList, isLoading: loadBreaches } = useQuery({
    queryKey: ["metrics", "sla-breaches", timeRange],
    queryFn: () => socMetricsApi.getSLABreaches(timeRange).catch(() => ({ items: SAMPLE_BREACHES, total: SAMPLE_BREACHES.length, page: 1 })),
    staleTime: 120_000,
  });

  const { data: rtDist, isLoading: loadRt } = useQuery({
    queryKey: ["metrics", "response-time-distribution", timeRange],
    queryFn: () => socMetricsApi.getResponseTimeDistribution(timeRange).catch(() => SAMPLE_RT_DIST),
    staleTime: 120_000,
  });

  const { data: analystSLA, isLoading: loadAnalysts } = useQuery({
    queryKey: ["metrics", "analyst-sla", timeRange],
    queryFn: () => socMetricsApi.getAnalystSLA(timeRange).catch(() => SAMPLE_ANALYST_SLA),
    staleTime: 120_000,
  });

  const s = summary ?? SAMPLE_SUMMARY;
  const breaches = breachList?.items ?? SAMPLE_BREACHES;

  return (
    <div className="pb-8">
      {/* Page header */}
      <div className="flex items-start justify-between mb-5 flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-extrabold text-text-primary font-display">SLA Dashboard</h1>
          <p className="text-xs text-text-muted mt-0.5">
            Alert response &amp; resolution time compliance · SLA targets, breach trends, analyst performance
          </p>
        </div>
        <div className="flex items-center gap-2">
          {/* Time range selector */}
          <div className="flex bg-bg-elevated border border-border rounded-lg p-0.5">
            {(["7d","30d","90d"] as TimeRange[]).map((tr) => (
              <button key={tr} onClick={() => setTimeRange(tr)}
                className={cn("px-3 py-1 rounded text-xs font-semibold transition-all",
                  timeRange === tr ? "bg-accent/15 text-blue-300" : "text-text-muted hover:text-text-secondary")}>
                {tr}
              </button>
            ))}
          </div>
          <button
            onClick={() => exportCsv(breaches)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-border text-xs font-medium text-text-secondary hover:text-text-primary hover:border-border-hover transition-all"
          >
            <Download size={12} /> Export
          </button>
        </div>
      </div>

      {/* KPI strip */}
      <div className="grid grid-cols-5 gap-3 mb-4">
        <ComplianceRing pct={s.compliance_pct} loading={loadSummary} />
        <KpiCard
          label="Breaches"
          value={String(s.total_breaches)}
          delta={s.breach_delta}
          deltaLabel={`${Math.abs(s.breach_delta)} vs prior`}
          sublabel="alerts exceeded SLA"
          color="#EF4444"
          icon={AlertTriangle}
          loading={loadSummary}
        />
        <KpiCard
          label="Avg Response Time"
          value={fmtMinutes(s.avg_response_minutes)}
          sublabel="time to first analyst action"
          color="#F59E0B"
          icon={Clock}
          loading={loadSummary}
        />
        <KpiCard
          label="Avg Resolve Time"
          value={fmtMinutes(s.avg_resolve_minutes)}
          sublabel="time from open to closed"
          color="#3B82F6"
          icon={RefreshCw}
          loading={loadSummary}
        />
        <KpiCard
          label="Within SLA"
          value={`${s.within_sla}/${s.total}`}
          delta={s.compliance_delta}
          deltaLabel={`${s.compliance_delta > 0 ? "+" : ""}${s.compliance_delta}% vs prior`}
          sublabel="alerts resolved on time"
          color="#10B981"
          icon={CheckCircle}
          loading={loadSummary}
        />
      </div>

      {/* Row 2: trend + by-severity */}
      <div className="grid grid-cols-5 gap-3 mb-3">
        <div className="col-span-3">
          <WidgetErrorBoundary title="SLA Breach Trend">
            <BreachTrendChart data={breachRate ?? trendSample} loading={loadTrend} />
          </WidgetErrorBoundary>
        </div>
        <div className="col-span-2">
          <WidgetErrorBoundary title="SLA by Severity">
            <SLABySeveritySection data={bySeverity ?? SAMPLE_BY_SEVERITY} loading={loadBySev} />
          </WidgetErrorBoundary>
        </div>
      </div>

      {/* Row 3: response time distribution + SLA policy */}
      <div className="grid grid-cols-5 gap-3 mb-3">
        <div className="col-span-3">
          <WidgetErrorBoundary title="Response Time Distribution">
            <ResponseTimeChart data={rtDist ?? SAMPLE_RT_DIST} loading={loadRt} />
          </WidgetErrorBoundary>
        </div>
        <div className="col-span-2">
          <SLATargetReference />
        </div>
      </div>

      {/* Row 4: analyst SLA table */}
      <div className="mb-3">
        <WidgetErrorBoundary title="Analyst SLA Performance">
          <AnalystSLATable data={analystSLA ?? SAMPLE_ANALYST_SLA} loading={loadAnalysts} />
        </WidgetErrorBoundary>
      </div>

      {/* Row 5: breach list */}
      <WidgetErrorBoundary title="SLA Breaches">
        <BreachList data={breaches} loading={loadBreaches} />
      </WidgetErrorBoundary>
    </div>
  );
}
