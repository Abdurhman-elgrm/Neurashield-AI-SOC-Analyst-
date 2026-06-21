import { useDashboardStore } from "@/stores/dashboardStore";
import { useDashboardRealtime } from "./hooks/useDashboardRealtime";
import { KPIMetricsRow } from "./widgets/KPIMetricsRow";
import { LiveAlertsFeed } from "./widgets/LiveAlertsFeed";
import { IngestionRateChart } from "./widgets/IngestionRateChart";
import { DetectionHealthWidget } from "./widgets/DetectionHealthWidget";
import { MitreHeatmap } from "./widgets/MitreHeatmap";
import { CorrelationWidget } from "./widgets/CorrelationWidget";
import { AIInvestigationWidget } from "./widgets/AIInvestigationWidget";
import type { DashboardTimeRange } from "./types/dashboard";
import { TIME_RANGE_LABELS } from "./types/dashboard";

const TIME_RANGES: DashboardTimeRange[] = [
  "last_15m", "last_1h", "last_6h", "last_24h", "last_7d",
];

// ─── Time range picker ────────────────────────────────────────────────────────

function TimeRangePicker({
  value,
  onChange,
}: {
  value: DashboardTimeRange;
  onChange: (v: DashboardTimeRange) => void;
}) {
  return (
    <div className="flex gap-0.5 bg-bg-surface border border-border rounded-lg p-0.5">
      {TIME_RANGES.map((r) => (
        <button
          key={r}
          onClick={() => onChange(r)}
          className={
            r === value
              ? "px-3 py-1 rounded-md text-xs font-semibold bg-primary-600 text-white transition-all"
              : "px-3 py-1 rounded-md text-xs font-semibold text-text-muted hover:text-text-secondary transition-all"
          }
        >
          {TIME_RANGE_LABELS[r]}
        </button>
      ))}
    </div>
  );
}

// ─── Dashboard page ───────────────────────────────────────────────────────────

export function DashboardPage() {
  const timeRange    = useDashboardStore((s) => s.timeRange);
  const setTimeRange = useDashboardStore((s) => s.setTimeRange);

  useDashboardRealtime(timeRange);

  return (
    <div style={{ paddingBottom: 24 }}>

      {/* Page header */}
      <div className="flex items-start justify-between mb-5 flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-extrabold text-text-primary" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
            Security Overview
          </h1>
          <p className="text-xs text-text-muted mt-0.5">
            Real-time threat intelligence command center
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 text-xs text-status-online font-semibold">
            <span className="w-1.5 h-1.5 bg-status-online rounded-full animate-pulse" />
            Live
          </span>
          <TimeRangePicker value={timeRange} onChange={setTimeRange} />
        </div>
      </div>

      {/* Row 1: 8-card KPI strip */}
      <div className="mb-3">
        <KPIMetricsRow timeRange={timeRange} />
      </div>

      {/* Row 2: Live Alerts + Ingestion Rate + Detection Health */}
      <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr) 300px", gap: 12, marginBottom: 12 }}>
        <LiveAlertsFeed timeRange={timeRange} maxHeight={380} />
        <IngestionRateChart timeRange={timeRange} />
        <DetectionHealthWidget timeRange={timeRange} />
      </div>

      {/* Row 3: MITRE ATT&CK + Correlation Activity */}
      <div style={{ display: "grid", gridTemplateColumns: "3fr 2fr", gap: 12, marginBottom: 12 }}>
        <MitreHeatmap timeRange={timeRange} />
        <CorrelationWidget timeRange={timeRange} />
      </div>

      {/* Row 4: AI Operations */}
      <AIInvestigationWidget timeRange={timeRange} />
    </div>
  );
}
