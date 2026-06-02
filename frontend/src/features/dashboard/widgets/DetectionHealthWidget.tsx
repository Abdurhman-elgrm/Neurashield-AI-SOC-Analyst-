import { Activity, CheckCircle, AlertOctagon, VolumeX, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";
import { BarChart } from "@/features/dashboard/charts";
import { CHART_COLORS } from "@/features/dashboard/charts/ChartTheme";
import { WidgetRefreshButton } from "./KPICard";
import { SkeletonText } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/ui/EmptyState";
import { useDetectionHealth } from "@/features/dashboard/hooks/useDashboardData";
import type { DashboardTimeRange, DetectionRuleHealth } from "@/features/dashboard/types/dashboard";

// ─── Rule status mini-stat ────────────────────────────────────────────────────

function StatPill({
  icon,
  label,
  value,
  variant,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  variant: "success" | "warning" | "error" | "muted";
}) {
  const colors = {
    success: "text-severity-low",
    warning: "text-severity-medium",
    error:   "text-severity-critical",
    muted:   "text-text-muted",
  };

  return (
    <div className="flex flex-col items-center gap-0.5 min-w-0">
      <span className={cn("w-3.5 h-3.5", colors[variant])}>{icon}</span>
      <span className={cn("text-sm font-bold tabular-nums", colors[variant])}>
        {value.toLocaleString()}
      </span>
      <span className="text-2xs text-text-muted">{label}</span>
    </div>
  );
}

// ─── Rule row ─────────────────────────────────────────────────────────────────

function RuleRow({ rule }: { rule: DetectionRuleHealth }) {
  const statusColor: Record<DetectionRuleHealth["status"], string> = {
    active:   "text-severity-low",
    noisy:    "text-severity-medium",
    disabled: "text-text-muted",
    error:    "text-severity-critical",
  };

  return (
    <div className="flex items-center gap-2 py-1.5 border-b border-border last:border-0">
      <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0 mt-px", {
        "bg-severity-low": rule.status === "active",
        "bg-severity-medium": rule.status === "noisy",
        "bg-text-muted": rule.status === "disabled",
        "bg-severity-critical": rule.status === "error",
      })} />
      <span className="flex-1 text-xs text-text-secondary truncate">{rule.ruleName}</span>
      <span className={cn("text-xs font-medium tabular-nums", statusColor[rule.status])}>
        {rule.triggeredCount.toLocaleString()}
      </span>
    </div>
  );
}

// ─── DetectionHealthWidget ────────────────────────────────────────────────────

interface DetectionHealthWidgetProps {
  timeRange: DashboardTimeRange;
}

export function DetectionHealthWidget({ timeRange }: DetectionHealthWidgetProps) {
  const { data, isLoading, isRefetching, refetch } = useDetectionHealth(timeRange);

  // Build chart data from top rules
  const chartData =
    data?.topRules.slice(0, 8).map((r) => ({
      name: r.ruleName.length > 20 ? r.ruleName.slice(0, 18) + "…" : r.ruleName,
      count: r.triggeredCount,
    })) ?? [];

  return (
    <div className="card flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <Activity className="w-3.5 h-3.5 text-accent" />
          <h3 className="text-sm font-semibold text-text-primary">Detection Health</h3>
        </div>
        <WidgetRefreshButton onClick={() => void refetch()} isRefetching={isRefetching} />
      </div>

      <div className="flex-1 p-4 flex flex-col gap-4 min-h-0 overflow-y-auto">
        {/* Rule counts */}
        <div className="grid grid-cols-4 gap-2">
          <StatPill
            icon={<CheckCircle />}
            label="Active"
            value={data?.activeRules ?? 0}
            variant="success"
          />
          <StatPill
            icon={<VolumeX />}
            label="Noisy"
            value={data?.noisyRules ?? 0}
            variant="warning"
          />
          <StatPill
            icon={<AlertOctagon />}
            label="Error"
            value={data?.errorRules ?? 0}
            variant="error"
          />
          <StatPill
            icon={<RefreshCw />}
            label="Disabled"
            value={data?.disabledRules ?? 0}
            variant="muted"
          />
        </div>

        {/* Latency */}
        {data && data.avgLatencyMs > 0 && (
          <div className="flex items-center justify-between text-xs border-t border-border pt-3">
            <span className="text-text-muted">Avg detect latency</span>
            <span className="text-text-secondary font-medium">
              {data.avgLatencyMs >= 1000
                ? `${(data.avgLatencyMs / 1000).toFixed(1)}s`
                : `${data.avgLatencyMs}ms`}
            </span>
          </div>
        )}

        {/* Top triggered rules chart */}
        {isLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 4 }).map((_, i) => <SkeletonText key={i} lines={1} />)}
          </div>
        ) : chartData.length === 0 ? (
          <EmptyState
            icon={<Activity className="w-6 h-6" />}
            title="No rule activity"
            description="No detection rules have triggered in this period."
            className="py-6"
          />
        ) : (
          <div>
            <p className="text-2xs text-text-muted mb-2 font-medium uppercase tracking-wider">
              Top Triggered Rules
            </p>
            <BarChart
              data={chartData}
              xKey="name"
              yKey="count"
              layout="vertical"
              color={CHART_COLORS.accent}
              height={Math.max(120, chartData.length * 26)}
              showGrid={false}
              barSize={8}
            />
          </div>
        )}

        {/* Top rule list fallback for vertical mode */}
        {!isLoading && data && data.topRules.length > 0 && (
          <div className="border-t border-border pt-3">
            <p className="text-2xs text-text-muted mb-2 font-medium uppercase tracking-wider">
              Rule Details
            </p>
            {data.topRules.slice(0, 5).map((r) => (
              <RuleRow key={r.ruleId} rule={r} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
