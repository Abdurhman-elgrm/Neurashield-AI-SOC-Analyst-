import { memo } from "react";
import { useNavigate } from "react-router-dom";
import { formatDistanceToNowStrict } from "date-fns";
import { Bell, ExternalLink } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { SeverityBadge } from "@/components/ui/Badge";
import { SkeletonText } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/ui/EmptyState";
import { getRelatedAlerts, PLACEHOLDER_RELATED_ALERTS } from "../api/investigationsApi";
import { investigationKeys } from "../hooks/useInvestigation";
import type { Alert } from "@/features/alerts/types";

const AlertRow = memo(function AlertRow({
  alert,
  onOpen,
}: {
  alert: Alert;
  onOpen: (id: string) => void;
}) {
  return (
    <div className="flex items-center gap-2 py-2 border-b border-border last:border-0">
      <SeverityBadge severity={alert.severity} />
      <div className="flex-1 min-w-0">
        <p className="text-xs text-text-primary truncate">{alert.title}</p>
        <p className="text-2xs text-text-muted">
          {formatDistanceToNowStrict(new Date(alert.createdAt), { addSuffix: true })}
          {alert.hostname && ` · ${alert.hostname}`}
        </p>
      </div>
      <button
        onClick={() => onOpen(alert.id)}
        className="flex-shrink-0 p-1 text-text-muted hover:text-accent transition-colors rounded"
      >
        <ExternalLink className="w-3 h-3" />
      </button>
    </div>
  );
});

interface RelatedAlertsProps {
  investigationId: string;
}

export function RelatedAlerts({ investigationId }: RelatedAlertsProps) {
  const navigate = useNavigate();

  const { data: alerts, isLoading } = useQuery({
    queryKey: investigationKeys.relatedAlerts(investigationId),
    queryFn: () => getRelatedAlerts(investigationId),
    placeholderData: PLACEHOLDER_RELATED_ALERTS,
    staleTime: 30_000,
    enabled: !!investigationId,
  });

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <p className="text-2xs text-text-muted uppercase tracking-wider font-medium flex items-center gap-1">
          <Bell className="w-3 h-3" />
          Related Alerts ({alerts?.length ?? 0})
        </p>
        <button
          onClick={() => navigate(`/alerts?correlationId=${investigationId}`)}
          className="text-2xs text-accent hover:underline"
        >
          View all
        </button>
      </div>

      {isLoading ? (
        <SkeletonText lines={4} />
      ) : !alerts?.length ? (
        <EmptyState
          icon={<Bell className="w-4 h-4" />}
          title="No related alerts"
          className="py-4"
        />
      ) : (
        <div>
          {alerts.slice(0, 8).map((a) => (
            <AlertRow key={a.id} alert={a} onOpen={(id) => navigate(`/alerts?open=${id}`)} />
          ))}
        </div>
      )}
    </div>
  );
}
