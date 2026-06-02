import { useMemo } from "react";
import { format } from "date-fns";
import { Zap } from "lucide-react";
import { AreaChart } from "@/features/dashboard/charts";
import { CHART_COLORS } from "@/features/dashboard/charts/ChartTheme";
import { WidgetRefreshButton } from "./KPICard";
import { useIngestionRate } from "@/features/dashboard/hooks/useDashboardData";
import type { DashboardTimeRange, IngestionRatePoint } from "@/features/dashboard/types/dashboard";
import { cn } from "@/lib/utils";

interface IngestionRateChartProps {
  timeRange: DashboardTimeRange;
}

function formatEPS(v: number): string {
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`;
  if (v >= 1_000)     return `${(v / 1_000).toFixed(1)}K`;
  return String(Math.round(v));
}

function formatTimestamp(iso: string, timeRange: DashboardTimeRange): string {
  try {
    const d = new Date(iso);
    if (timeRange === "last_7d") return format(d, "MM/dd");
    if (timeRange === "last_24h" || timeRange === "last_6h") return format(d, "HH:mm");
    return format(d, "HH:mm");
  } catch {
    return "";
  }
}

export function IngestionRateChart({ timeRange }: IngestionRateChartProps) {
  const { data, isLoading, isRefetching, refetch } = useIngestionRate(timeRange);

  const chartData = useMemo(
    () =>
      (data?.points ?? []).map((p: IngestionRatePoint) => ({
        t: p.timestamp,
        label: formatTimestamp(p.timestamp, timeRange),
        eps: p.eps,
        alerts: p.alertsCreated,
      })),
    [data, timeRange]
  );

  const isFlat = chartData.every((d) => d.eps === 0);

  return (
    <div className="card flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <Zap className="w-3.5 h-3.5 text-accent" />
          <h3 className="text-sm font-semibold text-text-primary">Ingestion Rate</h3>
          {data && (
            <span className="text-xs text-text-muted">
              avg {formatEPS(data.averageEps)} EPS
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {data && data.peakEps > 0 && (
            <span className="text-2xs text-text-muted">
              peak <span className="text-text-secondary">{formatEPS(data.peakEps)}</span>
            </span>
          )}
          <WidgetRefreshButton onClick={() => void refetch()} isRefetching={isRefetching} />
        </div>
      </div>

      <div className={cn("flex-1 p-4", isFlat && "flex items-center justify-center")}>
        {isFlat && !isLoading ? (
          <div className="text-center">
            <Zap className="w-8 h-8 text-text-muted mx-auto mb-2" />
            <p className="text-sm text-text-muted">No ingestion data in this period</p>
          </div>
        ) : (
          <div className="space-y-2">
            <AreaChart
              data={chartData}
              series={[
                { key: "eps", label: "Events/sec", color: CHART_COLORS.accent },
                { key: "alerts", label: "Alerts created", color: CHART_COLORS.critical, fillOpacity: 0.6 },
              ]}
              xKey="label"
              yFormatter={formatEPS}
              height={160}
              isLoading={isLoading && chartData.length === 0}
              showLegend
            />
          </div>
        )}
      </div>
    </div>
  );
}
