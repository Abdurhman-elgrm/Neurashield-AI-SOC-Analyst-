import { memo } from "react";
import { useNavigate } from "react-router-dom";
import { formatDistanceToNowStrict } from "date-fns";
import { Bell, ExternalLink, Archive } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { SeverityBadge } from "@/components/ui/Badge";
import { SkeletonText } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/ui/EmptyState";
import { getRelatedAlerts, PLACEHOLDER_RELATED_ALERTS } from "../api/investigationsApi";
import { investigationKeys } from "../hooks/useInvestigation";
import type { Alert } from "@/features/alerts/types";

type RelatedAlert = Alert & { archived?: boolean }

const AlertRow = memo(function AlertRow({
  alert,
  onOpen,
}: {
  alert: RelatedAlert;
  onOpen: (id: string) => void;
}) {
  return (
    <div
      className="flex items-center gap-2 py-2 border-b border-border last:border-0"
      style={{ opacity: alert.archived ? 0.65 : 1 }}
    >
      <SeverityBadge severity={alert.severity} />
      <div className="flex-1 min-w-0">
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <p className="text-xs text-text-primary truncate">{alert.title}</p>
          {alert.archived && (
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: 2, flexShrink: 0,
              padding: '1px 5px', borderRadius: 3, fontSize: 8, fontWeight: 700,
              fontFamily: "'JetBrains Mono', monospace",
              background: 'rgba(156,163,175,0.08)', color: '#6B7280',
              border: '1px solid rgba(156,163,175,0.18)',
              textTransform: 'uppercase', letterSpacing: '0.4px',
            }}>
              <Archive size={7} style={{ display: 'inline' }} /> Archived
            </span>
          )}
        </div>
        <p className="text-2xs text-text-muted">
          {formatDistanceToNowStrict(new Date(alert.createdAt), { addSuffix: true })}
          {alert.hostname && ` · ${alert.hostname}`}
          {alert.archived && (
            <span style={{ color: '#4B5563' }}> · not visible in Alerts page</span>
          )}
        </p>
      </div>
      {!alert.archived && (
        <button
          onClick={() => onOpen(alert.id)}
          className="flex-shrink-0 p-1 text-text-muted hover:text-accent transition-colors rounded"
          title="Open in Alerts page"
        >
          <ExternalLink className="w-3 h-3" />
        </button>
      )}
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

  const archivedCount = (alerts ?? []).filter(a => a.archived).length

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <p className="text-2xs text-text-muted uppercase tracking-wider font-medium flex items-center gap-1">
          <Bell className="w-3 h-3" />
          Related Alerts ({alerts?.length ?? 0})
          {archivedCount > 0 && (
            <span style={{
              fontSize: 8, padding: '1px 4px', borderRadius: 3,
              background: 'rgba(107,114,128,0.12)', color: '#6B7280',
              fontWeight: 700, letterSpacing: '0.3px',
            }}>
              {archivedCount} archived
            </span>
          )}
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
