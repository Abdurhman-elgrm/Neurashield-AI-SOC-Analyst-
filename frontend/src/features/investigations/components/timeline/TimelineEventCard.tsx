import { useState, memo } from "react";
import { format } from "date-fns";
import {
  AlertTriangle, Shield, User, Brain, FileText,
  ChevronDown, ChevronRight, Bell, Tag, GitBranch,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { TimelineEvent, TimelineEventType, TimelineActorType } from "../../types/timeline";

// ─── Icon map ─────────────────────────────────────────────────────────────────

const TYPE_ICON: Record<TimelineEventType, React.ReactNode> = {
  alert_triggered:       <AlertTriangle className="w-3 h-3" />,
  investigation_created: <GitBranch className="w-3 h-3" />,
  status_changed:        <Tag className="w-3 h-3" />,
  assigned:              <User className="w-3 h-3" />,
  note_added:            <FileText className="w-3 h-3" />,
  evidence_added:        <FileText className="w-3 h-3" />,
  ai_analyzed:           <Brain className="w-3 h-3" />,
  verdict_updated:       <Shield className="w-3 h-3" />,
  alert_added:           <Bell className="w-3 h-3" />,
  entity_tagged:         <Tag className="w-3 h-3" />,
  mitre_mapped:          <Shield className="w-3 h-3" />,
  analyst_action:        <User className="w-3 h-3" />,
};

const ACTOR_COLOR: Record<TimelineActorType, string> = {
  system:  "bg-bg-elevated text-text-muted",
  analyst: "bg-accent/20 text-accent",
  ai:      "bg-severity-medium/20 text-severity-medium",
};

const SEV_DOT: Record<string, string> = {
  critical: "bg-severity-critical",
  high:     "bg-severity-high",
  medium:   "bg-severity-medium",
  low:      "bg-severity-low",
  info:     "bg-text-muted",
};

// ─── TimelineEventCard ────────────────────────────────────────────────────────

interface TimelineEventCardProps {
  event: TimelineEvent;
  isLast: boolean;
}

export const TimelineEventCard = memo(function TimelineEventCard({
  event,
  isLast,
}: TimelineEventCardProps) {
  const [expanded, setExpanded] = useState(false);
  const hasPayload = event.rawPayload && Object.keys(event.rawPayload).length > 0;

  return (
    <div className="flex gap-2">
      {/* Spine */}
      <div className="flex flex-col items-center flex-shrink-0">
        <div
          className={cn(
            "w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0",
            ACTOR_COLOR[event.actorType]
          )}
        >
          {TYPE_ICON[event.type]}
        </div>
        {!isLast && <div className="w-px flex-1 bg-border mt-1 min-h-[12px]" />}
      </div>

      {/* Content */}
      <div className="flex-1 pb-4 min-w-0">
        <div className="flex items-start justify-between gap-2">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-1.5 flex-wrap">
              {event.severity && (
                <span
                  className={cn(
                    "w-2 h-2 rounded-full flex-shrink-0",
                    SEV_DOT[event.severity] ?? "bg-text-muted"
                  )}
                />
              )}
              <p className="text-xs font-medium text-text-primary">{event.title}</p>
              {event.mitreTechniqueId && (
                <span className="text-2xs font-mono bg-accent/10 text-accent px-1 rounded">
                  {event.mitreTechniqueId}
                </span>
              )}
            </div>

            <p className="text-2xs text-text-muted mt-0.5">{event.description}</p>

            {event.actorName && (
              <p className="text-2xs text-text-muted mt-0.5">
                by <span className="text-text-secondary">{event.actorName}</span>
              </p>
            )}

            {/* Note content */}
            {event.type === "note_added" && typeof event.metadata.content === "string" && (
              <div className="mt-1.5 px-2 py-1.5 bg-bg-subtle rounded border border-border text-xs text-text-secondary">
                {event.metadata.content}
              </div>
            )}

            {/* Raw payload toggle */}
            {hasPayload && (
              <button
                onClick={() => setExpanded((v) => !v)}
                className="mt-1 flex items-center gap-0.5 text-2xs text-accent hover:underline"
              >
                {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                {expanded ? "Hide" : "Show"} raw event
              </button>
            )}

            {expanded && hasPayload && (
              <pre className="mt-1.5 p-2 bg-bg-elevated rounded text-2xs text-text-muted overflow-x-auto max-h-40 border border-border">
                {JSON.stringify(event.rawPayload, null, 2)}
              </pre>
            )}
          </div>

          <span className="text-2xs text-text-muted flex-shrink-0 tabular-nums">
            {format(new Date(event.timestamp), "HH:mm:ss")}
          </span>
        </div>
      </div>
    </div>
  );
});
