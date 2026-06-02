import { memo } from "react";
import { formatDistanceToNowStrict } from "date-fns";
import { Activity } from "lucide-react";
import { SkeletonText } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/ui/EmptyState";
import { useInvestigationActivity } from "../../hooks/useInvestigation";
import type { AnalystActivity } from "../../types/investigation";

const ActivityRow = memo(function ActivityRow({ item }: { item: AnalystActivity }) {
  return (
    <div className="flex items-start gap-2 py-2 border-b border-border last:border-0">
      <div className="w-5 h-5 rounded-full bg-accent/20 flex items-center justify-center flex-shrink-0 mt-0.5">
        <span className="text-2xs font-semibold text-accent">
          {item.analystName.charAt(0).toUpperCase()}
        </span>
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs text-text-secondary">
          <span className="font-medium text-text-primary">{item.analystName}</span>{" "}
          {item.action}
        </p>
        <p className="text-2xs text-text-muted">
          {formatDistanceToNowStrict(new Date(item.timestamp), { addSuffix: true })}
        </p>
      </div>
    </div>
  );
});

interface ActivityFeedProps {
  investigationId: string;
}

export function ActivityFeed({ investigationId }: ActivityFeedProps) {
  const { data: activities, isLoading } = useInvestigationActivity(investigationId);

  return (
    <div>
      <div className="flex items-center gap-1.5 mb-2">
        <Activity className="w-3.5 h-3.5 text-accent" />
        <p className="text-2xs text-text-muted uppercase tracking-wider font-medium">
          Recent Activity
        </p>
      </div>

      {isLoading ? (
        <SkeletonText lines={4} />
      ) : !activities?.length ? (
        <EmptyState
          icon={<Activity className="w-4 h-4" />}
          title="No activity yet"
          className="py-4"
        />
      ) : (
        <div>
          {activities.slice(0, 10).map((a) => (
            <ActivityRow key={a.id} item={a} />
          ))}
        </div>
      )}
    </div>
  );
}
