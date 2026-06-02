import { Brain, CheckCircle, XCircle, Clock, TrendingUp } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { formatDistanceToNowStrict } from "date-fns";
import { cn } from "@/lib/utils";
import { DonutChart } from "@/features/dashboard/charts";
import { CHART_COLORS } from "@/features/dashboard/charts/ChartTheme";
import { EmptyState } from "@/components/ui/EmptyState";
import { SkeletonText } from "@/components/ui/Skeleton";
import { WidgetRefreshButton } from "./KPICard";
import { useAIOperations } from "@/features/dashboard/hooks/useDashboardData";
import type { DashboardTimeRange, AIVerdict } from "@/features/dashboard/types/dashboard";

// ─── Verdict row ──────────────────────────────────────────────────────────────

function VerdictRow({ v }: { v: AIVerdict }) {
  const statusIcon = {
    true_positive:  <CheckCircle className="w-3.5 h-3.5 text-severity-critical" />,
    false_positive: <XCircle className="w-3.5 h-3.5 text-severity-low" />,
    benign:         <CheckCircle className="w-3.5 h-3.5 text-text-muted" />,
    pending:        <Clock className="w-3.5 h-3.5 text-severity-medium" />,
  }[v.verdict];

  const relTime = v.analyzedAt
    ? formatDistanceToNowStrict(new Date(v.analyzedAt), { addSuffix: true })
    : "pending";

  return (
    <div className="flex items-start gap-2 py-2 border-b border-border last:border-0">
      <span className="flex-shrink-0 mt-0.5">{statusIcon}</span>
      <div className="flex-1 min-w-0">
        <p className="text-xs text-text-primary truncate">{v.title}</p>
        <div className="flex items-center gap-2 mt-0.5">
          <span className={cn("text-2xs capitalize font-medium", {
            "text-severity-critical": v.verdict === "true_positive",
            "text-severity-low":      v.verdict === "false_positive",
            "text-text-muted":        v.verdict === "benign",
            "text-severity-medium":   v.verdict === "pending",
          })}>
            {v.verdict.replace("_", " ")}
          </span>
          {v.confidence > 0 && (
            <span className="text-2xs text-text-muted">{v.confidence}% confidence</span>
          )}
        </div>
      </div>
      <span className="text-2xs text-text-muted flex-shrink-0">{relTime}</span>
    </div>
  );
}

// ─── AIInvestigationWidget ────────────────────────────────────────────────────

interface AIInvestigationWidgetProps {
  timeRange: DashboardTimeRange;
}

export function AIInvestigationWidget({ timeRange }: AIInvestigationWidgetProps) {
  const { data, isLoading, isRefetching, refetch } = useAIOperations(timeRange);
  const navigate = useNavigate();

  const donutData = [
    { name: "True Positive", value: data?.truePositiveCount ?? 0, color: CHART_COLORS.critical },
    { name: "False Positive", value: data?.falsePositiveCount ?? 0, color: CHART_COLORS.success },
    { name: "Pending",        value: data?.pendingCount ?? 0,       color: CHART_COLORS.warning },
  ];

  const hasData = donutData.some((d) => d.value > 0);

  return (
    <div className="card flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <Brain className="w-3.5 h-3.5 text-accent" />
          <h3 className="text-sm font-semibold text-text-primary">AI Operations</h3>
          {data && data.queueDepth > 0 && (
            <span className="px-1.5 py-0.5 text-2xs rounded-full bg-severity-medium/20 text-severity-medium border border-severity-medium/30">
              {data.queueDepth} queued
            </span>
          )}
        </div>
        <WidgetRefreshButton onClick={() => void refetch()} isRefetching={isRefetching} />
      </div>

      <div className="flex-1 overflow-y-auto">
        <div className="p-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
          {/* Donut chart + stats */}
          <div>
            <DonutChart
              data={donutData}
              height={160}
              innerRadius={48}
              outerRadius={70}
              isLoading={isLoading}
              showLegend={false}
              centerValue={hasData ? (data?.analyzedLast24h ?? 0) : undefined}
              centerLabel={hasData ? "analyzed" : undefined}
            />

            {/* Legend */}
            {hasData && (
              <div className="mt-2 space-y-1">
                {donutData.map((d) => (
                  <div key={d.name} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: d.color }} />
                      <span className="text-text-muted">{d.name}</span>
                    </div>
                    <span className="text-text-secondary font-medium tabular-nums">{d.value}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Confidence avg */}
            {data && data.avgConfidence > 0 && (
              <div className="mt-3 pt-3 border-t border-border flex items-center gap-2 text-xs">
                <TrendingUp className="w-3.5 h-3.5 text-accent" />
                <span className="text-text-muted">Avg confidence</span>
                <span className="text-text-primary font-medium ml-auto">{data.avgConfidence}%</span>
              </div>
            )}
          </div>

          {/* Recent verdicts */}
          <div>
            <p className="text-2xs text-text-muted font-medium uppercase tracking-wider mb-2">
              Recent Verdicts
            </p>

            {isLoading ? (
              <div className="space-y-2">
                {Array.from({ length: 4 }).map((_, i) => <SkeletonText key={i} lines={1} />)}
              </div>
            ) : (data?.recentVerdicts ?? []).length === 0 ? (
              <EmptyState
                icon={<Brain className="w-5 h-5" />}
                title="No verdicts yet"
                description="AI analysis results will appear here."
                className="py-6"
              />
            ) : (
              (data!.recentVerdicts).map((v) => (
                <VerdictRow key={v.investigationId} v={v} />
              ))
            )}
          </div>
        </div>
      </div>

      <div className="px-4 py-2 border-t border-border flex-shrink-0">
        <button
          onClick={() => navigate("/copilot")}
          className="text-xs text-accent hover:underline"
        >
          Open AI Copilot →
        </button>
      </div>
    </div>
  );
}
