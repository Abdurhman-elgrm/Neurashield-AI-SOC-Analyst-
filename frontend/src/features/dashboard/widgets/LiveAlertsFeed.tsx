import { useRef, memo } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useNavigate } from "react-router-dom";
import { formatDistanceToNowStrict } from "date-fns";
import { ArrowRight, Radio } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { SkeletonText } from "@/components/ui/Skeleton";
import { WidgetRefreshButton } from "./KPICard";
import { useAlertsFeed } from "@/features/dashboard/hooks/useDashboardData";
import type { DashboardTimeRange, LiveAlert, AlertSeverity } from "@/features/dashboard/types/dashboard";

// ─── Severity dot ─────────────────────────────────────────────────────────────

const SEV_DOT: Record<AlertSeverity, string> = {
  critical: "bg-severity-critical",
  high:     "bg-severity-high",
  medium:   "bg-severity-medium",
  low:      "bg-severity-low",
  info:     "bg-accent",
};

const SEV_BADGE_VARIANT: Record<AlertSeverity, "critical" | "high" | "medium" | "low" | "info"> = {
  critical: "critical",
  high:     "high",
  medium:   "medium",
  low:      "low",
  info:     "info",
};

// ─── AlertRow ─────────────────────────────────────────────────────────────────

const AlertRow = memo(function AlertRow({
  alert,
  onClick,
}: {
  alert: LiveAlert;
  onClick: () => void;
}) {
  const relTime = (() => {
    try {
      return formatDistanceToNowStrict(new Date(alert.createdAt), { addSuffix: true });
    } catch {
      return "—";
    }
  })();

  return (
    <button
      onClick={onClick}
      className="w-full px-3 py-2.5 text-left hover:bg-bg-elevated/60 border-b border-border last:border-0 transition-colors group"
    >
      <div className="flex items-start gap-2.5">
        <span className={cn("w-2 h-2 rounded-full mt-1.5 flex-shrink-0", SEV_DOT[alert.severity])} />

        <div className="flex-1 min-w-0">
          <div className="flex items-start gap-2 justify-between">
            <p className="text-xs font-medium text-text-primary truncate leading-tight">{alert.title}</p>
            <ArrowRight className="w-3 h-3 text-text-muted flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity mt-0.5" />
          </div>

          <div className="flex items-center gap-2 mt-1 flex-wrap">
            <Badge variant={SEV_BADGE_VARIANT[alert.severity]} className="text-2xs px-1.5 py-px">
              {alert.severity}
            </Badge>
            <span className="text-2xs text-text-muted truncate">{alert.hostname}</span>
            {alert.correlationScore > 0 && (
              <span className="text-2xs text-accent">
                {alert.correlationScore}% match
              </span>
            )}
          </div>
        </div>

        <span className="text-2xs text-text-muted flex-shrink-0 mt-0.5">{relTime}</span>
      </div>
    </button>
  );
});

// ─── LiveAlertsFeed ───────────────────────────────────────────────────────────

interface LiveAlertsFeedProps {
  timeRange: DashboardTimeRange;
  maxHeight?: number;
}

export function LiveAlertsFeed({ timeRange, maxHeight = 400 }: LiveAlertsFeedProps) {
  const { data: alerts = [], isLoading, isRefetching, isError, refetch } = useAlertsFeed(timeRange);
  const navigate = useNavigate();
  const parentRef = useRef<HTMLDivElement>(null);

  const virtualizer = useVirtualizer({
    count: alerts.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 64,
    overscan: 5,
  });

  return (
    <div className="card flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <Radio className="w-3.5 h-3.5 text-accent" />
          <h3 className="text-sm font-semibold text-text-primary">Live Alerts</h3>
          {alerts.length > 0 && (
            <span className="text-xs text-text-muted">({alerts.length})</span>
          )}
        </div>
        <div className="flex items-center gap-1">
          <span className="flex items-center gap-1 text-2xs text-status-online">
            <span className="w-1.5 h-1.5 bg-status-online rounded-full animate-pulse" />
            Live
          </span>
          <WidgetRefreshButton onClick={() => void refetch()} isRefetching={isRefetching} isError={isError} />
        </div>
      </div>

      {/* Body */}
      <div
        ref={parentRef}
        className="flex-1 overflow-y-auto"
        style={{ maxHeight }}
      >
        {isLoading && alerts.length === 0 ? (
          <div className="p-3 space-y-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="flex gap-2.5 px-1 py-1">
                <div className="w-2 h-2 rounded-full bg-bg-subtle mt-1.5 flex-shrink-0" />
                <div className="flex-1 space-y-1.5">
                  <SkeletonText lines={1} />
                  <SkeletonText lines={1} className="w-2/3" />
                </div>
              </div>
            ))}
          </div>
        ) : alerts.length === 0 ? (
          <EmptyState
            icon={<Radio className="w-6 h-6" />}
            title="No alerts"
            description="No alerts in the selected time range."
            className="py-10"
          />
        ) : (
          <div
            style={{
              height: virtualizer.getTotalSize(),
              width: "100%",
              position: "relative",
            }}
          >
            {virtualizer.getVirtualItems().map((vi) => {
              const alert = alerts[vi.index];
              return (
                <div
                  key={vi.key}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    height: vi.size,
                    transform: `translateY(${vi.start}px)`,
                  }}
                >
                  <AlertRow
                    alert={alert}
                    onClick={() =>
                      alert.investigationId
                        ? navigate(`/investigations/${alert.investigationId}`)
                        : navigate(`/alerts?id=${alert.id}`)
                    }
                  />
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Footer */}
      {alerts.length > 0 && (
        <div className="px-4 py-2 border-t border-border flex-shrink-0">
          <button
            onClick={() => navigate("/alerts")}
            className="text-xs text-accent hover:underline"
          >
            View all alerts →
          </button>
        </div>
      )}
    </div>
  );
}
