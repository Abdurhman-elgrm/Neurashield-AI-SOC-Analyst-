import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AreaChart, Area, LineChart, Line,
  PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend, BarChart, Bar,
} from "recharts";
import { TrendingDown, TrendingUp, Shield, Clock, Users, Target, AlertTriangle, CheckCircle2, Activity, Download } from "lucide-react";
import { socMetricsApi } from "@/api/soc-metrics";
import { WidgetErrorBoundary } from "@/components/ui/WidgetErrorBoundary";
import { cn } from "@/lib/utils";

// ─── Skeleton ────────────────────────────────────────────────────────────────

function Skel({ className }: { className?: string }) {
  return <div className={cn("skel rounded-lg animate-pulse", className)} />;
}

// ─── MTTR Card ────────────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#6B7280",
};

function MTTRCard() {
  const { data, isLoading } = useQuery({
    queryKey: ["metrics", "mttr"],
    queryFn: () => socMetricsApi.getMTTR("30d"),
    staleTime: 300_000,
  });

  return (
    <div className="bg-bg-card border border-border rounded-xl p-4">
      <div className="flex items-center gap-2 mb-3">
        <Clock size={14} className="text-accent" />
        <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted">Mean Time to Resolve (30d)</h3>
      </div>
      {isLoading ? (
        <div className="space-y-2">{[1,2,3,4].map(i => <Skel key={i} className="h-8" />)}</div>
      ) : (
        <div className="space-y-2">
          {(data ?? []).map((row) => (
            <div key={row.severity} className="flex items-center gap-3">
              <span
                className="text-2xs font-bold uppercase w-16 flex-shrink-0"
                style={{ color: SEV_COLORS[row.severity] ?? "#8B95A7" }}
              >
                {row.severity}
              </span>
              <div className="flex-1 bg-bg-elevated rounded-full h-1.5">
                <div
                  className="h-1.5 rounded-full transition-all"
                  style={{
                    width: `${Math.min(100, (row.mean_minutes / 1440) * 100)}%`,
                    background: SEV_COLORS[row.severity] ?? "#8B95A7",
                  }}
                />
              </div>
              <span className="text-xs font-mono text-text-secondary w-16 text-right flex-shrink-0">
                {row.mean_minutes >= 60
                  ? `${(row.mean_minutes / 60).toFixed(1)}h`
                  : `${Math.round(row.mean_minutes)}m`}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Alert Volume Trend ───────────────────────────────────────────────────────

function AlertVolumeTrend() {
  const { data, isLoading } = useQuery({
    queryKey: ["metrics", "alert-volume"],
    queryFn: () => socMetricsApi.getAlertVolume("30d"),
    staleTime: 300_000,
  });

  return (
    <div className="bg-bg-card border border-border rounded-xl p-4">
      <div className="flex items-center gap-2 mb-3">
        <TrendingUp size={14} className="text-accent" />
        <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted">Alert Volume (30d)</h3>
      </div>
      {isLoading ? <Skel className="h-48" /> : (
        <ResponsiveContainer width="100%" height={180}>
          <AreaChart data={data ?? []} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
            <defs>
              {["critical","high","medium","low"].map((s) => (
                <linearGradient key={s} id={`grad-${s}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={SEV_COLORS[s]} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={SEV_COLORS[s]} stopOpacity={0} />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
            <XAxis dataKey="date" tick={{ fill: "#5C6373", fontSize: 9 }} tickFormatter={(v: string) => v.slice(5)} />
            <YAxis tick={{ fill: "#5C6373", fontSize: 9 }} />
            <Tooltip contentStyle={{ background: "#111", border: "1px solid #1F2937", fontSize: 11 }} />
            <Area type="monotone" dataKey="critical" stackId="1" stroke="#EF4444" fill="url(#grad-critical)" strokeWidth={1.5} />
            <Area type="monotone" dataKey="high"     stackId="1" stroke="#F97316" fill="url(#grad-high)"     strokeWidth={1.5} />
            <Area type="monotone" dataKey="medium"   stackId="1" stroke="#F59E0B" fill="url(#grad-medium)"   strokeWidth={1.5} />
            <Area type="monotone" dataKey="low"      stackId="1" stroke="#6B7280" fill="url(#grad-low)"      strokeWidth={1.5} />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

// ─── Analyst Leaderboard ─────────────────────────────────────────────────────

function AnalystLeaderboard() {
  const { data, isLoading } = useQuery({
    queryKey: ["metrics", "analyst-performance"],
    queryFn: socMetricsApi.getAnalystPerformance,
    staleTime: 60_000,
  });

  return (
    <div className="bg-bg-card border border-border rounded-xl p-4">
      <div className="flex items-center gap-2 mb-3">
        <Users size={14} className="text-accent" />
        <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted">Analyst Performance</h3>
      </div>
      {isLoading ? <Skel className="h-40" /> : (
        <div className="overflow-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left pb-2 text-text-muted font-semibold">Analyst</th>
                <th className="text-right pb-2 text-text-muted font-semibold">Triaged Today</th>
                <th className="text-right pb-2 text-text-muted font-semibold">Avg Resolve</th>
                <th className="text-right pb-2 text-text-muted font-semibold">Open</th>
              </tr>
            </thead>
            <tbody>
              {(data ?? []).map((a) => (
                <tr key={a.user_id} className="border-b border-border/50">
                  <td className="py-1.5 text-text-primary font-medium">{a.name}</td>
                  <td className="py-1.5 text-right text-accent font-mono">{a.alerts_triaged_today}</td>
                  <td className="py-1.5 text-right text-text-secondary font-mono">
                    {a.avg_resolution_minutes >= 60
                      ? `${(a.avg_resolution_minutes / 60).toFixed(1)}h`
                      : `${Math.round(a.avg_resolution_minutes)}m`}
                  </td>
                  <td className="py-1.5 text-right text-text-muted">{a.open_assignments}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── SLA Breach Rate ─────────────────────────────────────────────────────────

function SLABreachChart() {
  const { data, isLoading } = useQuery({
    queryKey: ["metrics", "sla-breach-rate"],
    queryFn: () => socMetricsApi.getSLABreachRate("30d"),
    staleTime: 300_000,
  });

  return (
    <div className="bg-bg-card border border-border rounded-xl p-4">
      <div className="flex items-center gap-2 mb-3">
        <TrendingDown size={14} className="text-severity-high" />
        <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted">SLA Breach Rate (30d)</h3>
      </div>
      {isLoading ? <Skel className="h-40" /> : (
        <ResponsiveContainer width="100%" height={160}>
          <LineChart data={data ?? []} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
            <XAxis dataKey="date" tick={{ fill: "#5C6373", fontSize: 9 }} tickFormatter={(v: string) => v.slice(5)} />
            <YAxis tick={{ fill: "#5C6373", fontSize: 9 }} tickFormatter={(v: number) => `${v}%`} />
            <Tooltip contentStyle={{ background: "#111", border: "1px solid #1F2937", fontSize: 11 }}
              formatter={(v: number) => `${v.toFixed(1)}%`} />
            <Legend wrapperStyle={{ fontSize: 10 }} />
            <Line type="monotone" dataKey="warn_breach_pct"  name="2h SLA" stroke="#F59E0B" strokeWidth={1.5} dot={false} />
            <Line type="monotone" dataKey="crit_breach_pct"  name="8h SLA" stroke="#EF4444" strokeWidth={1.5} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

// ─── Verdict Distribution ────────────────────────────────────────────────────

const VERDICT_COLORS = ["#10B981", "#EF4444", "#6B7280", "#3B82F6"];

function VerdictDonut() {
  const { data, isLoading } = useQuery({
    queryKey: ["metrics", "verdict-distribution"],
    queryFn: () => socMetricsApi.getVerdictDistribution("30d"),
    staleTime: 300_000,
  });

  const chartData = data ? [
    { name: "True Positive",  value: data.true_positive  },
    { name: "False Positive", value: data.false_positive },
    { name: "Benign",         value: data.benign         },
    { name: "Unknown",        value: data.unknown        },
  ] : [];

  return (
    <div className="bg-bg-card border border-border rounded-xl p-4">
      <div className="flex items-center gap-2 mb-3">
        <Target size={14} className="text-accent" />
        <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted">Verdict Distribution</h3>
      </div>
      {isLoading ? <Skel className="h-40" /> : (
        <div className="flex items-center gap-4">
          <ResponsiveContainer width={120} height={120}>
            <PieChart>
              <Pie data={chartData} cx="50%" cy="50%" innerRadius={35} outerRadius={55} dataKey="value">
                {chartData.map((_e, i) => <Cell key={i} fill={VERDICT_COLORS[i % VERDICT_COLORS.length]} />)}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="space-y-1.5">
            {chartData.map((d, i) => (
              <div key={d.name} className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: VERDICT_COLORS[i] }} />
                <span className="text-xs text-text-secondary">{d.name}</span>
                <span className="text-xs font-mono text-text-primary ml-auto pl-4">{d.value}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Coverage Score ───────────────────────────────────────────────────────────

function CoverageScore() {
  const { data, isLoading } = useQuery({
    queryKey: ["metrics", "coverage-score"],
    queryFn: socMetricsApi.getCoverageScore,
    staleTime: 300_000,
  });

  return (
    <div className="bg-bg-card border border-border rounded-xl p-4">
      <div className="flex items-center gap-2 mb-3">
        <Shield size={14} className="text-accent" />
        <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted">Detection Coverage</h3>
      </div>
      {isLoading ? <Skel className="h-20" /> : data ? (
        <div className="space-y-3">
          <div className="flex items-end gap-3">
            <span className="text-4xl font-extrabold font-display text-text-primary">{data.score_pct}%</span>
            <span className={cn(
              "text-sm font-semibold flex items-center gap-1 mb-1",
              data.trend_delta >= 0 ? "text-status-online" : "text-severity-high",
            )}>
              {data.trend_delta >= 0 ? <TrendingUp size={12} /> : <TrendingDown size={12} />}
              {data.trend_delta >= 0 ? "+" : ""}{data.trend_delta}%
            </span>
          </div>
          <div className="h-2 bg-bg-elevated rounded-full overflow-hidden">
            <div
              className="h-full rounded-full bg-accent transition-all"
              style={{ width: `${data.score_pct}%` }}
            />
          </div>
          <p className="text-xs text-text-muted">
            {data.covered_techniques} of {data.total_techniques} MITRE techniques covered
          </p>
        </div>
      ) : (
        <p className="text-xs text-text-muted">No data available</p>
      )}
    </div>
  );
}

// ─── SocMetricsPage ───────────────────────────────────────────────────────────

// ─── SLA Policy Card ──────────────────────────────────────────────────────────

function SLAPolicyCard() {
  const policies = [
    { sev: "Critical", limit: "1h",  color: "#EF4444", target: 95 },
    { sev: "High",     limit: "4h",  color: "#F97316", target: 90 },
    { sev: "Medium",   limit: "24h", color: "#F59E0B", target: 85 },
    { sev: "Low",      limit: "72h", color: "#6B7280", target: 80 },
  ];
  return (
    <div className="bg-bg-card border border-border rounded-xl p-4">
      <div className="flex items-center gap-2 mb-3">
        <AlertTriangle size={14} className="text-accent" />
        <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted">SLA Policy</h3>
        <span className="ml-auto text-2xs text-text-disabled border border-border rounded px-1.5 py-0.5">Edit Policy →</span>
      </div>
      <div className="space-y-3">
        {policies.map(({ sev, limit, color, target }) => (
          <div key={sev} className="flex items-center gap-3">
            <span className="text-xs font-bold w-14 flex-shrink-0" style={{ color }}>{sev}</span>
            <div className="flex-1 bg-bg-elevated rounded-full h-1.5">
              <div className="h-1.5 rounded-full" style={{ width: `${target}%`, background: color }} />
            </div>
            <span className="text-2xs font-mono text-text-muted w-8 text-right flex-shrink-0">{limit}</span>
            <span className="text-2xs text-text-disabled w-10 text-right flex-shrink-0">{target}% SLO</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Analyst Workload Distribution ───────────────────────────────────────────

function AnalystWorkloadChart() {
  const { data, isLoading } = useQuery({
    queryKey: ["metrics", "analyst-performance"],
    queryFn: socMetricsApi.getAnalystPerformance,
    staleTime: 60_000,
  });

  const chartData = (data ?? []).map((a) => ({
    name: a.name.split(" ")[0],
    open: a.open_assignments,
    triaged: a.alerts_triaged_today,
  }));

  return (
    <div className="bg-bg-card border border-border rounded-xl p-4">
      <div className="flex items-center gap-2 mb-3">
        <Activity size={14} className="text-accent" />
        <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted">Analyst Workload</h3>
      </div>
      {isLoading ? <Skel className="h-40" /> : chartData.length === 0 ? (
        <p className="text-xs text-text-muted py-8 text-center">No analyst data available</p>
      ) : (
        <ResponsiveContainer width="100%" height={160}>
          <BarChart data={chartData} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
            <XAxis dataKey="name" tick={{ fill: "#5C6373", fontSize: 9 }} />
            <YAxis tick={{ fill: "#5C6373", fontSize: 9 }} />
            <Tooltip contentStyle={{ background: "#111", border: "1px solid #1F2937", fontSize: 11 }} />
            <Legend wrapperStyle={{ fontSize: 10 }} />
            <Bar dataKey="open"    name="Open Cases"       fill="#3B82F6" radius={[2, 2, 0, 0]} />
            <Bar dataKey="triaged" name="Triaged Today"    fill="#10B981" radius={[2, 2, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

// ─── Top-level KPI summary ────────────────────────────────────────────────────

function SummaryKPIs() {
  const { data: mttr }     = useQuery({ queryKey: ["metrics", "mttr"], queryFn: () => socMetricsApi.getMTTR("30d"), staleTime: 300_000 });
  const { data: coverage } = useQuery({ queryKey: ["metrics", "coverage-score"], queryFn: socMetricsApi.getCoverageScore, staleTime: 300_000 });
  const { data: sla }      = useQuery({ queryKey: ["metrics", "sla-breach-rate"], queryFn: () => socMetricsApi.getSLABreachRate("30d"), staleTime: 300_000 });
  const { data: verdict }  = useQuery({ queryKey: ["metrics", "verdict-distribution"], queryFn: () => socMetricsApi.getVerdictDistribution("30d"), staleTime: 300_000 });

  const critMttr      = mttr?.find((r) => r.severity === "critical")?.mean_minutes ?? 0;
  const latestBreach  = sla?.[sla.length - 1]?.crit_breach_pct ?? 0;
  const totalVerdict  = verdict ? (verdict.true_positive + verdict.false_positive + verdict.benign + verdict.unknown) : 0;
  const tpRate        = totalVerdict > 0 ? Math.round((verdict!.true_positive / totalVerdict) * 100) : 0;

  const kpis = [
    { icon: Clock,         label: "Crit MTTR",    value: critMttr >= 60 ? `${(critMttr / 60).toFixed(1)}h` : `${Math.round(critMttr)}m`, sub: "target < 1h",    color: critMttr > 60 ? "#EF4444" : "#10B981"  },
    { icon: Shield,        label: "Coverage",     value: `${coverage?.score_pct ?? 0}%`,  sub: "MITRE ATT&CK",  color: "#3B82F6"  },
    { icon: AlertTriangle, label: "SLA Breach",   value: `${latestBreach.toFixed(1)}%`,   sub: "last 30 days",  color: latestBreach > 10 ? "#EF4444" : "#10B981" },
    { icon: CheckCircle2,  label: "TP Rate",      value: `${tpRate}%`,                    sub: "true positives", color: tpRate > 70 ? "#10B981" : "#F59E0B"        },
  ];

  return (
    <div className="grid grid-cols-4 gap-3 mb-4">
      {kpis.map(({ icon: Icon, label, value, sub, color }) => (
        <div key={label} className="bg-bg-card border border-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: `${color}18` }}>
              <Icon size={13} style={{ color }} />
            </div>
            <span className="text-2xs font-bold uppercase tracking-widest text-text-muted">{label}</span>
          </div>
          <div className="text-2xl font-extrabold font-mono" style={{ color }}>{value}</div>
          <div className="text-2xs text-text-disabled mt-1">{sub}</div>
        </div>
      ))}
    </div>
  );
}

// ─── SocMetricsPage ───────────────────────────────────────────────────────────

export function SocMetricsPage() {
  useEffect(() => { document.title = "SOC Metrics — NEURASHIELD"; }, []);

  return (
    <div className="pb-6">
      {/* Page header */}
      <div className="flex items-start justify-between mb-5">
        <div>
          <h1 className="text-xl font-extrabold text-text-primary font-display">SOC Metrics</h1>
          <p className="text-xs text-text-muted mt-0.5">Team performance, SLA compliance, and detection effectiveness — last 30 days</p>
        </div>
        <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border text-xs font-semibold text-text-muted hover:text-text-secondary transition-all">
          <Download size={12} /> Export PDF
        </button>
      </div>

      {/* Summary KPIs */}
      <WidgetErrorBoundary title="Summary KPIs"><SummaryKPIs /></WidgetErrorBoundary>

      {/* Row 1: MTTR + Coverage */}
      <div className="grid grid-cols-2 gap-3 mb-3">
        <WidgetErrorBoundary title="MTTR"><MTTRCard /></WidgetErrorBoundary>
        <WidgetErrorBoundary title="Coverage Score"><CoverageScore /></WidgetErrorBoundary>
      </div>

      {/* Row 2: Alert volume */}
      <div className="mb-3">
        <WidgetErrorBoundary title="Alert Volume"><AlertVolumeTrend /></WidgetErrorBoundary>
      </div>

      {/* Row 3: SLA breach + Verdict + Analyst leaderboard */}
      <div className="grid grid-cols-3 gap-3 mb-3">
        <WidgetErrorBoundary title="SLA Breach Rate"><SLABreachChart /></WidgetErrorBoundary>
        <WidgetErrorBoundary title="Verdict Distribution"><VerdictDonut /></WidgetErrorBoundary>
        <WidgetErrorBoundary title="Analyst Performance"><AnalystLeaderboard /></WidgetErrorBoundary>
      </div>

      {/* Row 4: Workload distribution + SLA policy */}
      <div className="grid grid-cols-2 gap-3">
        <WidgetErrorBoundary title="Analyst Workload"><AnalystWorkloadChart /></WidgetErrorBoundary>
        <WidgetErrorBoundary title="SLA Policy"><SLAPolicyCard /></WidgetErrorBoundary>
      </div>
    </div>
  );
}
