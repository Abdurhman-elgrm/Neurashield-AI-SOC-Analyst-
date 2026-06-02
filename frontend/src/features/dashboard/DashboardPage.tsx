import { Clock } from "lucide-react";
import { cn } from "@/lib/utils";
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

// ─── Time range selector ──────────────────────────────────────────────────────

const TIME_RANGES: DashboardTimeRange[] = [
  "last_15m", "last_1h", "last_6h", "last_24h", "last_7d",
];

function TimeRangeSelector({
  value,
  onChange,
}: {
  value: DashboardTimeRange;
  onChange: (v: DashboardTimeRange) => void;
}) {
  return (
    <div className="flex items-center gap-1 rounded-lg border border-border bg-bg-surface p-0.5">
      {TIME_RANGES.map((range) => (
        <button
          key={range}
          onClick={() => onChange(range)}
          className={cn(
            "px-2.5 py-1 text-xs rounded-md transition-colors",
            value === range
              ? "bg-accent text-white font-medium"
              : "text-text-muted hover:text-text-primary hover:bg-bg-subtle"
          )}
        >
          {TIME_RANGE_LABELS[range]}
        </button>
      ))}
    </div>
  );
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

export function DashboardPage() {
  const timeRange = useDashboardStore((s) => s.timeRange);
  const setTimeRange = useDashboardStore((s) => s.setTimeRange);

  // Realtime updates — injects events into React Query cache
  useDashboardRealtime(timeRange);

  return (
    <div className="space-y-5 pb-6">
      {/* Page header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="page-title">Overview</h1>
          <p className="text-sm text-text-secondary mt-0.5">
            Security operations command center
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs text-text-muted">
            <Clock className="w-3.5 h-3.5" />
            <span>Time range:</span>
          </div>
          <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
        </div>
      </div>

      {/* Row 1: KPI metrics */}
      <KPIMetricsRow timeRange={timeRange} />

      {/* Row 2: Alerts + Ingestion + Detection */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4" style={{ minHeight: 420 }}>
        <div className="lg:col-span-2 flex flex-col">
          <LiveAlertsFeed timeRange={timeRange} maxHeight={380} />
        </div>
        <div className="lg:col-span-2 flex flex-col">
          <IngestionRateChart timeRange={timeRange} />
        </div>
        <div className="lg:col-span-1 flex flex-col">
          <DetectionHealthWidget timeRange={timeRange} />
        </div>
      </div>

      {/* Row 3: MITRE + Correlation */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4" style={{ minHeight: 380 }}>
        <div className="lg:col-span-3 flex flex-col">
          <MitreHeatmap timeRange={timeRange} />
        </div>
        <div className="lg:col-span-2 flex flex-col">
          <CorrelationWidget timeRange={timeRange} />
        </div>
      </div>

      {/* Row 4: AI operations (full width) */}
      <div style={{ minHeight: 280 }}>
        <AIInvestigationWidget timeRange={timeRange} />
      </div>
    </div>
  );
}
