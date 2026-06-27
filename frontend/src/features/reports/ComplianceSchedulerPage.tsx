import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Calendar, CheckCircle, AlertTriangle, MinusCircle, ShieldOff } from "lucide-react";
import { apiGet } from "@/api/client";
import { cn } from "@/lib/utils";

// ─── Types ────────────────────────────────────────────────────────────────────

type ComplianceFramework = "soc2" | "iso27001" | "pci_dss";
type ControlStatus = "pass" | "partial" | "fail" | "not_applicable";

interface ComplianceFrameworkControl {
  control_id: string;
  control_name: string;
  status: ControlStatus;
  evidence: string;
  metric: string | null;
}

interface AlertSummary {
  total: number;
  open: number;
  acknowledged: number;
  closed: number;
  false_positive: number;
  by_severity: Record<string, number>;
  mean_time_to_acknowledge_hours: number | null;
  mean_time_to_close_hours: number | null;
}

interface InvestigationSummary {
  total: number;
  open: number;
  closed: number;
  high_confidence: number;
  avg_threat_score: number | null;
  behaviors_detected: string[];
}

interface AgentSummary {
  total_agents: number;
  online_agents: number;
  offline_agents: number;
  coverage_pct: number;
}

interface EventSummary {
  total_events: number;
  by_category: Record<string, number>;
}

interface ComplianceReport {
  framework: string;
  tenant_id: string;
  generated_at: string;
  period_start: string;
  period_end: string;
  alerts: AlertSummary;
  investigations: InvestigationSummary;
  agents: AgentSummary;
  events: EventSummary;
  controls: ComplianceFrameworkControl[];
}

// ─── Constants ────────────────────────────────────────────────────────────────

const FRAMEWORKS: { value: ComplianceFramework; label: string; desc: string }[] = [
  { value: "soc2",     label: "SOC 2 Type II", desc: "Trust Services Criteria" },
  { value: "iso27001", label: "ISO 27001",      desc: "Information Security" },
  { value: "pci_dss",  label: "PCI-DSS",        desc: "Payment Card Security" },
];

const DATE_RANGES = [
  { value: 30,  label: "Last 30 days"  },
  { value: 90,  label: "Last 90 days"  },
  { value: 365, label: "Last 365 days" },
];

const STATUS_META: Record<ControlStatus, { label: string; icon: typeof CheckCircle; color: string }> = {
  pass:           { label: "Pass",           icon: CheckCircle,  color: "text-status-online" },
  partial:        { label: "Partial",        icon: AlertTriangle, color: "text-severity-medium" },
  fail:           { label: "Fail",           icon: ShieldOff,     color: "text-severity-critical" },
  not_applicable: { label: "N/A",            icon: MinusCircle,  color: "text-text-muted" },
};

// ─── ControlRow ───────────────────────────────────────────────────────────────

function ControlRow({ ctrl }: { ctrl: ComplianceFrameworkControl }) {
  const meta = STATUS_META[ctrl.status];
  const Icon = meta.icon;
  return (
    <div className="flex items-start gap-3 py-3 border-b border-border last:border-0">
      <Icon size={15} className={cn("mt-0.5 flex-shrink-0", meta.color)} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-text-muted">{ctrl.control_id}</span>
          <span className="text-xs font-semibold text-text-primary">{ctrl.control_name}</span>
        </div>
        <p className="text-xs text-text-muted mt-0.5">{ctrl.evidence}</p>
        {ctrl.metric && <p className="text-xs text-accent mt-0.5">{ctrl.metric}</p>}
      </div>
      <span className={cn("text-xs font-semibold flex-shrink-0 mt-0.5", meta.color)}>{meta.label}</span>
    </div>
  );
}

// ─── SummaryCard ──────────────────────────────────────────────────────────────

function SummaryCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="rounded-xl border border-border bg-bg-elevated p-4">
      <p className="text-xs text-text-muted">{label}</p>
      <p className="text-lg font-bold text-text-primary mt-0.5">{value}</p>
      {sub && <p className="text-xs text-text-muted mt-0.5">{sub}</p>}
    </div>
  );
}

// ─── ComplianceSchedulerPage ──────────────────────────────────────────────────

export function ComplianceSchedulerPage() {
  const [framework, setFramework] = useState<ComplianceFramework>("soc2");
  const [fromDays, setFromDays] = useState(30);

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["compliance-report", framework, fromDays],
    queryFn: () =>
      apiGet<ComplianceReport>(`/reports/compliance?framework=${framework}&from_days=${fromDays}`),
    staleTime: 5 * 60_000,
  });

  const passCount    = data?.controls.filter((c) => c.status === "pass").length    ?? 0;
  const failCount    = data?.controls.filter((c) => c.status === "fail").length    ?? 0;
  const partialCount = data?.controls.filter((c) => c.status === "partial").length ?? 0;
  const total        = data?.controls.length ?? 0;
  const passRate     = total > 0 ? Math.round((passCount / total) * 100) : 0;

  return (
    <div className="page-in space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-text-primary">Compliance Reports</h1>
          <p className="text-sm text-text-muted mt-0.5">Security posture evidence by framework</p>
        </div>
        {data && (
          <div className="flex items-center gap-1.5 text-xs text-text-muted">
            <Calendar size={12} />
            Generated {new Date(data.generated_at).toLocaleString()}
          </div>
        )}
      </div>

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex gap-2">
          {FRAMEWORKS.map((f) => (
            <button
              key={f.value}
              onClick={() => setFramework(f.value)}
              className={cn(
                "px-3 py-1.5 rounded-lg text-xs font-semibold border transition-colors",
                framework === f.value
                  ? "bg-accent/15 border-accent/40 text-accent"
                  : "bg-bg-elevated border-border text-text-secondary hover:text-text-primary",
              )}
            >
              {f.label}
            </button>
          ))}
        </div>
        <select
          value={fromDays}
          onChange={(e) => setFromDays(Number(e.target.value))}
          className="px-2.5 py-1.5 rounded-lg text-xs border border-border bg-bg-elevated text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
        >
          {DATE_RANGES.map((r) => (
            <option key={r.value} value={r.value}>{r.label}</option>
          ))}
        </select>
        <button
          onClick={() => void refetch()}
          className="px-3 py-1.5 rounded-lg text-xs font-semibold border border-border bg-bg-elevated text-text-secondary hover:text-text-primary transition-colors"
        >
          Refresh
        </button>
      </div>

      {isLoading && (
        <div className="space-y-3">
          {[1,2,3,4].map((i) => <div key={i} className="skel h-14 rounded-xl animate-pulse" />)}
        </div>
      )}

      {isError && (
        <div className="rounded-xl border border-severity-critical/30 bg-severity-critical/5 p-6 text-center text-sm text-severity-critical">
          Failed to load compliance report.
        </div>
      )}

      {data && (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <SummaryCard label="Controls Passing" value={`${passRate}%`} sub={`${passCount} of ${total}`} />
            <SummaryCard label="Failing"    value={failCount}                                                  sub="need attention" />
            <SummaryCard label="Partial"    value={partialCount}                                               sub="in progress" />
            <SummaryCard label="Agent Coverage" value={`${Math.round(data.agents.coverage_pct)}%`} sub={`${data.agents.online_agents}/${data.agents.total_agents} online`} />
          </div>

          {/* Alert metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <SummaryCard label="Alerts (period)"  value={data.alerts.total.toLocaleString()}             />
            <SummaryCard label="Avg MTTA"         value={data.alerts.mean_time_to_acknowledge_hours != null ? `${data.alerts.mean_time_to_acknowledge_hours.toFixed(1)}h` : "—"} />
            <SummaryCard label="Avg MTTC"         value={data.alerts.mean_time_to_close_hours != null ? `${data.alerts.mean_time_to_close_hours.toFixed(1)}h` : "—"} />
            <SummaryCard label="Investigations"   value={data.investigations.total.toLocaleString()}     />
          </div>

          {/* Controls table */}
          <div className="rounded-xl border border-border bg-bg-card p-4">
            <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-3">
              {FRAMEWORKS.find((f) => f.value === framework)?.label} Controls
            </p>
            {data.controls.length === 0 ? (
              <p className="text-xs text-text-muted text-center py-6">No controls for this framework.</p>
            ) : (
              data.controls.map((ctrl) => <ControlRow key={ctrl.control_id} ctrl={ctrl} />)
            )}
          </div>
        </>
      )}
    </div>
  );
}
