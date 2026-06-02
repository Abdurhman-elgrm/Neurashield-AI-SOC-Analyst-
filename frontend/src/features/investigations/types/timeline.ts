export type TimelineEventType =
  | "alert_triggered"
  | "investigation_created"
  | "status_changed"
  | "assigned"
  | "note_added"
  | "evidence_added"
  | "ai_analyzed"
  | "verdict_updated"
  | "alert_added"
  | "entity_tagged"
  | "mitre_mapped"
  | "analyst_action";

export type TimelineActorType = "system" | "analyst" | "ai";

export interface TimelineEvent {
  id: string;
  investigationId: string;
  type: TimelineEventType;
  severity?: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  actorId?: string;
  actorName?: string;
  actorType: TimelineActorType;
  metadata: Record<string, unknown>;
  mitreTechniqueId?: string;
  alertId?: string;
  rawPayload?: Record<string, unknown>;
  timestamp: string;
}

export interface TimelineFilterState {
  types: TimelineEventType[];
  actorType: "all" | TimelineActorType;
  search: string;
  severity: string[];
}

export const DEFAULT_TIMELINE_FILTER: TimelineFilterState = {
  types: [],
  actorType: "all",
  search: "",
  severity: [],
};
