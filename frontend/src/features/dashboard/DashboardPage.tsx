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
    <div
      className="flex items-center gap-0.5 rounded-lg p-0.5"
      style={{
        background: "rgba(10,10,10,0.8)",
        border: "1px solid rgba(59,130,246,0.15)",
      }}
    >
      {TIME_RANGES.map((range) => (
        <button
          key={range}
          onClick={() => onChange(range)}
          className={cn(
            "px-2.5 py-1 text-xs rounded-md transition-all duration-150 font-medium",
            value === range
              ? "text-white"
              : "text-text-muted hover:text-text-primary hover:bg-white/[0.04]"
          )}
          style={
            value === range
              ? {
                  background: "linear-gradient(135deg, #2563EB, #3B82F6)",
                  boxShadow: "0 0 12px rgba(59,130,246,0.4)",
                }
              : undefined
          }
        >
          {TIME_RANGE_LABELS[range]}
        </button>
      ))}
    </div>
  );
}

export function DashboardPage() {
  const timeRange = useDashboardStore((s) => s.timeRange);
  const setTimeRange = useDashboardStore((s) => s.setTimeRange);

  useDashboardRealtime(timeRange);

  return (
    <div className="space-y-5 pb-6">
      {/* Page header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="page-title">Security Overview</h1>
          <p className="text-sm text-text-muted mt-0.5">
            Real-time threat intelligence command center
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 text-xs text-status-online">
            <span className="w-1.5 h-1.5 bg-status-online rounded-full animate-pulse" />
            Live
          </span>
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

      {/* Row 4: AI operations */}
      <div style={{ minHeight: 280 }}>
        <AIInvestigationWidget timeRange={timeRange} />
      </div>
    </div>
  );
}
