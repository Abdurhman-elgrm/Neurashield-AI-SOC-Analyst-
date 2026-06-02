// ─── Severity + Status enums ──────────────────────────────────────────────────

export type AlertSeverity = "critical" | "high" | "medium" | "low" | "info";
export type AlertStatus = "open" | "acknowledged" | "resolved" | "suppressed";

// ─── Alert ────────────────────────────────────────────────────────────────────

export interface Alert {
  id: string;
  tenant_id: string;
  rule_id: string | null;
  title: string;
  description: string;
  severity: AlertSeverity;
  status: AlertStatus;
  source_host: string | null;
  source_ip: string | null;
  category: string;
  tags: string[];
  event_count: number;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  resolved_at: string | null;
  investigation_id: string | null;
}

export interface AlertSummary
  extends Pick<Alert, "id" | "title" | "severity" | "status" | "source_host" | "created_at" | "last_seen" | "category"> {}

// ─── Alert list query params ──────────────────────────────────────────────────

export interface AlertFilters {
  severity?: AlertSeverity[];
  status?: AlertStatus[];
  category?: string;
  source_host?: string;
  since?: string;
  from?: string;
  to?: string;
  search?: string;
  rule_id?: string;
}

export interface AlertListParams extends AlertFilters {
  cursor?: string;
  limit?: number;
  sort_by?: "created_at" | "severity" | "last_seen";
  sort_dir?: "asc" | "desc";
}

// ─── Alert mutations ──────────────────────────────────────────────────────────

export interface AcknowledgeAlertRequest {
  note?: string;
}

export interface ResolveAlertRequest {
  resolution_note?: string;
}

export interface BulkAlertAction {
  alert_ids: string[];
  action: "acknowledge" | "resolve" | "suppress";
  note?: string;
}

// ─── Severity helpers ─────────────────────────────────────────────────────────

export const SEVERITY_ORDER: Record<AlertSeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export const SEVERITY_LABELS: Record<AlertSeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export const STATUS_LABELS: Record<AlertStatus, string> = {
  open: "Open",
  acknowledged: "Acknowledged",
  resolved: "Resolved",
  suppressed: "Suppressed",
};
