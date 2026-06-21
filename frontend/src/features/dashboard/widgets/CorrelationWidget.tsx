import { GitMerge, Layers, ArrowRight } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { formatDistanceToNowStrict } from "date-fns";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { SkeletonText } from "@/components/ui/Skeleton";
import { WidgetRefreshButton } from "./KPICard";
import { useCorrelationActivity } from "@/features/dashboard/hooks/useDashboardData";
import type {
  DashboardTimeRange,
  CorrelationEvent,
  AlertSeverity,
} from "@/features/dashboard/types/dashboard";

const SEV_BADGE: Record<AlertSeverity, "critical" | "high" | "medium" | "low" | "info"> = {
  critical: "critical",
  high:     "high",
  medium:   "medium",
  low:      "low",
  info:     "info",
};

function CorrelationRow({
  event,
  onClick,
}: {
  event: CorrelationEvent;
  onClick: () => void;
}) {
  const relTime = (() => {
    try {
      return formatDistanceToNowStrict(new Date(event.correlatedAt), { addSuffix: true });
    } catch { return "—"; }
  })();

  return (
    <button
      onClick={onClick}
      className="w-full px-3 py-2.5 text-left hover:bg-bg-elevated/60 border-b border-border last:border-0 transition-colors group"
    >
      <div className="flex items-start gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 justify-between">
            <p className="text-xs font-medium text-text-primary truncate">
              {event.investigationTitle}
            </p>
            <ArrowRight className="w-3 h-3 text-text-muted flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity" />
          </div>
          <div className="flex items-center gap-2 mt-1 flex-wrap">
            <Badge variant={SEV_BADGE[event.severity]} className="text-2xs px-1.5 py-px">
              {event.severity}
            </Badge>
            <span className="text-2xs text-text-muted">
              {event.alertCount} alerts · {event.entityCount} entities
            </span>
          </div>
          {event.behaviorMatches.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-1">
              {event.behaviorMatches.slice(0, 3).map((b) => (
                <span
                  key={b}
                  className="text-2xs px-1.5 py-0.5 rounded bg-accent/10 text-accent border border-accent/20"
                >
                  {b}
                </span>
              ))}
            </div>
          )}
        </div>
        <span className="text-2xs text-text-muted flex-shrink-0">{relTime}</span>
      </div>
    </button>
  );
}

interface CorrelationWidgetProps {
  timeRange: DashboardTimeRange;
}

export function CorrelationWidget({ timeRange }: CorrelationWidgetProps) {
  const { data, isLoading, isRefetching, isError, refetch } = useCorrelationActivity(timeRange);
  const navigate = useNavigate();

  return (
    <div className="card flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <GitMerge className="w-3.5 h-3.5 text-accent" />
          <h3 className="text-sm font-semibold text-text-primary">Correlation Activity</h3>
        </div>
        <WidgetRefreshButton onClick={() => void refetch()} isRefetching={isRefetching} isError={isError} />
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-3 divide-x divide-border border-b border-border flex-shrink-0">
        {[
          { label: "Active Invs.", value: data?.activeInvestigations ?? 0 },
          { label: "Grouped Alerts", value: data?.totalGroupedAlerts ?? 0 },
          { label: "Entities", value: data?.totalEntities ?? 0 },
        ].map(({ label, value }) => (
          <div key={label} className="flex flex-col items-center py-2.5">
            <span className={cn(
              "text-lg font-bold tabular-nums",
              isLoading ? "text-text-muted animate-pulse" : "text-text-primary"
            )}>
              {isLoading ? "—" : value.toLocaleString()}
            </span>
            <span className="text-2xs text-text-muted">{label}</span>
          </div>
        ))}
      </div>

      {/* Recent correlations list */}
      <div className="flex-1 overflow-y-auto">
        {isLoading ? (
          <div className="p-3 space-y-3">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="space-y-1.5 px-1">
                <SkeletonText lines={1} />
                <SkeletonText lines={1} className="w-2/3" />
              </div>
            ))}
          </div>
        ) : (data?.recentCorrelations ?? []).length === 0 ? (
          <EmptyState
            icon={<Layers className="w-6 h-6" />}
            title="No correlations"
            description="Alert correlations will appear here as they are detected."
            className="py-10"
          />
        ) : (
          (data?.recentCorrelations ?? []).map((ev) => (
            <CorrelationRow
              key={ev.id}
              event={ev}
              onClick={() => navigate(`/investigations?id=${ev.investigationId}`)}
            />
          ))
        )}
      </div>

      {(data?.recentCorrelations ?? []).length > 0 && (
        <div className="px-4 py-2 border-t border-border flex-shrink-0">
          <button
            onClick={() => navigate("/investigations")}
            className="text-xs text-accent hover:underline"
          >
            View all investigations →
          </button>
        </div>
      )}
    </div>
  );
}
