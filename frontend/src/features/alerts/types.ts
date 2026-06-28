// ─── Severity / Status ───────────────────────────────────────────────────────

export type AlertSeverity = "critical" | "high" | "medium" | "low" | "info";
export type AlertStatus = "open" | "acknowledged" | "closed" | "false_positive";
export type AIVerdictType = "true_positive" | "false_positive" | "benign" | "pending";
export type BulkAlertAction =
  | "close"
  | "reopen"
  | "assign"
  | "mark_true_positive"
  | "mark_false_positive"
  | "add_tag"
  | "remove_tag"
  | "update_severity";

// ─── Risk context (populated by detection engine severity escalation) ─────────

export interface AlertRiskContext {
  ruleSeverity: string;
  finalSeverity: string;
  severityEscalated: boolean;
  escalationReasons: string[];
  uebaScore: number;
  uebaFlags: string[];
  isThreatIp: boolean;
  abuseConfidence: number;
  threatIntelFlags: string[];
}

// ─── Core alert entity ────────────────────────────────────────────────────────

export interface MitreAttack {
  techniqueId: string;  // e.g. "T1059"
  techniqueName: string;
  tacticId: string;     // e.g. "TA0002"
  tacticName: string;
}

export interface AIAlertVerdict {
  verdict: AIVerdictType;
  confidence: number;   // 0-100
  reasoning?: string;
  analyzedAt?: string;
}

export interface Alert {
  id: string;
  tenantId: string;
  ruleId: string;
  ruleName: string;
  title: string;
  description: string;
  severity: AlertSeverity;
  status: AlertStatus;
  hostname: string;
  sourceIp?: string;
  username?: string;
  processName?: string;
  mitre?: MitreAttack;
  correlationId?: string;     // investigation ID if grouped
  correlationScore?: number;  // 0-100
  assignedTo?: string;        // user ID
  assignedToName?: string;    // display name
  aiVerdict?: AIAlertVerdict;
  tags: string[];
  rawEventCount: number;
  firstSeenAt: string;
  lastSeenAt: string;
  createdAt: string;
  updatedAt: string;
  acknowledgedAt?: string;
  closedAt?: string;
  notes?: string;
  riskContext?: AlertRiskContext;
}

// ─── Alert list / pagination ──────────────────────────────────────────────────

export interface AlertListParams {
  page?: number;
  pageSize?: number;
  sort?: string;             // e.g. "-created_at"
  severity?: AlertSeverity[];
  status?: AlertStatus[];
  hostname?: string;
  username?: string;
  sourceIp?: string;
  mitreTechnique?: string;
  aiVerdict?: AIVerdictType[];
  assignedTo?: string;
  tags?: string[];
  search?: string;
  timeRange?: string;
  fromTs?: string;           // ISO-8601 start (sent as from_ts to backend)
  toTs?: string;             // ISO-8601 end   (sent as to_ts  to backend)
  correlationId?: string;
  cursor?: string;
}

export interface AlertListResponse {
  items: Alert[];
  total: number;
  page: number;
  pageSize: number;
  pageCount: number;
}

// ─── Alert detail enrichment ──────────────────────────────────────────────────

export interface AlertContext {
  alertId: string;
  relatedAlerts: Alert[];
  investigation?: {
    id: string;
    title: string;
    status: string;
    createdAt: string;
    alertCount: number;
  };
  entityGraph?: {
    nodes: Array<{ id: string; label: string; type: string }>;
    edges: Array<{ source: string; target: string; label: string }>;
  };
}

export type TimelineEventType =
  | "alert_created"
  | "status_changed"
  | "assigned"
  | "note_added"
  | "ai_analyzed"
  | "investigation_linked"
  | "tag_added"
  | "tag_removed"
  | "severity_changed";

export interface AlertTimelineEvent {
  id: string;
  alertId: string;
  eventType: TimelineEventType;
  actorId?: string;
  actorName?: string;
  details: Record<string, unknown>;
  createdAt: string;
}

export interface AlertNote {
  id: string;
  alertId: string;
  authorId: string;
  authorName: string;
  content: string;
  createdAt: string;
  updatedAt: string;
}

// ─── Bulk operations ──────────────────────────────────────────────────────────

export interface BulkActionPayload {
  alertIds: string[];
  action: BulkAlertAction;
  assignTo?: string;
  tag?: string;
  severity?: AlertSeverity;
}

export interface BulkActionResult {
  succeeded: string[];
  failed: Array<{ id: string; reason: string }>;
}

