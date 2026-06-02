import type { AlertSeverity } from "./alerts";

// ─── Investigation status + verdict ──────────────────────────────────────────

export type InvestigationStatus =
  | "open"
  | "in_progress"
  | "reviewing"
  | "closed"
  | "archived";

export type Verdict =
  | "true_positive"
  | "false_positive"
  | "benign"
  | "unknown"
  | "needs_review";

// ─── Investigation ────────────────────────────────────────────────────────────

export interface Investigation {
  id: string;
  tenant_id: string;
  title: string;
  description: string | null;
  status: InvestigationStatus;
  verdict: Verdict | null;
  threat_score: number;
  confidence: "low" | "medium" | "high" | "critical";
  severity: AlertSeverity;
  assigned_to: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
  alert_count: number;
  event_count: number;
  tags: string[];
}

export interface InvestigationSummary
  extends Pick<
    Investigation,
    | "id"
    | "title"
    | "status"
    | "verdict"
    | "threat_score"
    | "severity"
    | "assigned_to"
    | "created_at"
    | "alert_count"
  > {}

// ─── Notes ────────────────────────────────────────────────────────────────────

export interface InvestigationNote {
  id: string;
  investigation_id: string;
  author_id: string;
  author_name: string;
  content: string;
  pinned: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateNoteRequest {
  content: string;
  pinned?: boolean;
}

// ─── Evidence ─────────────────────────────────────────────────────────────────

export type EvidenceType =
  | "file"
  | "process"
  | "network"
  | "registry"
  | "log"
  | "screenshot"
  | "other";

export interface InvestigationEvidence {
  id: string;
  investigation_id: string;
  added_by: string;
  title: string;
  description: string | null;
  evidence_type: EvidenceType;
  file_path: string | null;
  hash_sha256: string | null;
  source_host: string | null;
  collected_at: string | null;
  extra_data: Record<string, unknown>;
  created_at: string;
}

// ─── Assignments ──────────────────────────────────────────────────────────────

export interface InvestigationAssignment {
  id: string;
  investigation_id: string;
  assigned_by: string;
  assigned_to: string;
  assigned_to_name: string | null;
  escalated: boolean;
  escalation_reason: string | null;
  assigned_at: string;
  is_active: boolean;
}

// ─── Query params ─────────────────────────────────────────────────────────────

export interface InvestigationFilters {
  status?: InvestigationStatus[];
  verdict?: Verdict[];
  assigned_to?: string;
  severity?: AlertSeverity[];
  search?: string;
  since?: string;
  from?: string;
  to?: string;
}

export interface InvestigationListParams extends InvestigationFilters {
  cursor?: string;
  limit?: number;
  sort_by?: "created_at" | "threat_score" | "updated_at";
  sort_dir?: "asc" | "desc";
}

// ─── Labels ───────────────────────────────────────────────────────────────────

export const STATUS_LABELS: Record<InvestigationStatus, string> = {
  open: "Open",
  in_progress: "In Progress",
  reviewing: "Reviewing",
  closed: "Closed",
  archived: "Archived",
};

export const VERDICT_LABELS: Record<Verdict, string> = {
  true_positive: "True Positive",
  false_positive: "False Positive",
  benign: "Benign",
  unknown: "Unknown",
  needs_review: "Needs Review",
};
