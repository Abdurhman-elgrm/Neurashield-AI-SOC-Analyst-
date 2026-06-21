import { apiClient } from "@/api/client";
import type { APIResponse } from "@/types/api";
import type {
  Investigation,
  InvestigationNote,
  InvestigationStatus,
  InvestigationVerdict,
  AnalystActivity,
} from "../types/investigation";
import type { TimelineEvent } from "../types/timeline";
import type { EvidenceItem } from "../types/evidence";
import type { InvestigationGraph } from "../types/graph";
import type { Alert } from "@/features/alerts/types";

// ─── Investigation detail ─────────────────────────────────────────────────────

export async function getInvestigation(id: string): Promise<Investigation> {
  const { data } = await apiClient.get<APIResponse<Investigation>>(
    `/investigations/${id}`
  );
  return data.data!;
}

// ─── Timeline ─────────────────────────────────────────────────────────────────

export async function getInvestigationTimeline(id: string): Promise<TimelineEvent[]> {
  const { data } = await apiClient.get<APIResponse<TimelineEvent[]>>(
    `/investigations/${id}/timeline`
  );
  return data.data!;
}

// ─── Entity/Behavior graph ────────────────────────────────────────────────────

export async function getInvestigationGraph(id: string): Promise<InvestigationGraph> {
  const { data } = await apiClient.get<APIResponse<InvestigationGraph>>(
    `/investigations/${id}/graph`
  );
  return data.data!;
}

// ─── Evidence ─────────────────────────────────────────────────────────────────

export async function getInvestigationEvidence(id: string): Promise<EvidenceItem[]> {
  const { data } = await apiClient.get<APIResponse<EvidenceItem[]>>(
    `/investigations/${id}/evidence`
  );
  return data.data!;
}

export async function uploadEvidence(
  id: string,
  file: File,
  meta: { title: string; type: string; description?: string; tags?: string[] },
  onProgress?: (pct: number) => void
): Promise<EvidenceItem> {
  const form = new FormData();
  form.append("file", file);
  form.append("title", meta.title);
  form.append("type", meta.type);
  if (meta.description) form.append("description", meta.description);
  if (meta.tags) form.append("tags", meta.tags.join(","));

  const { data } = await apiClient.post<APIResponse<EvidenceItem>>(
    `/investigations/${id}/evidence`,
    form,
    {
      headers: { "Content-Type": "multipart/form-data" },
      onUploadProgress: (e) => {
        if (e.total) onProgress?.(Math.round((e.loaded / e.total) * 100));
      },
    }
  );
  return data.data!;
}

// ─── Notes ────────────────────────────────────────────────────────────────────

export async function addInvestigationNote(
  id: string,
  content: string
): Promise<InvestigationNote> {
  const { data } = await apiClient.post<APIResponse<InvestigationNote>>(
    `/investigations/${id}/notes`,
    { content }
  );
  return data.data!;
}

// ─── Assignment ───────────────────────────────────────────────────────────────

export async function assignInvestigation(
  id: string,
  userId: string,
): Promise<Investigation> {
  const { data } = await apiClient.patch<APIResponse<Investigation>>(
    `/investigations/${id}/assign`,
    { assigned_to: userId }
  );
  return data.data!;
}

// ─── Status / Verdict ─────────────────────────────────────────────────────────

export async function updateInvestigationStatus(
  id: string,
  status: InvestigationStatus
): Promise<Investigation> {
  const { data } = await apiClient.patch<APIResponse<Investigation>>(
    `/investigations/${id}/status`,
    { status }
  );
  return data.data!;
}

export async function updateInvestigationVerdict(
  id: string,
  verdict: InvestigationVerdict,
  reasoning?: string
): Promise<Investigation> {
  const { data } = await apiClient.patch<APIResponse<Investigation>>(
    `/investigations/${id}/verdict`,
    { verdict, reasoning }
  );
  return data.data!;
}

// ─── Related alerts ───────────────────────────────────────────────────────────

// The backend returns snake_case; adapt to camelCase Alert + archived flag
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function _adaptRelatedAlert(raw: Record<string, any>): Alert & { archived?: boolean } {
  return {
    id:             String(raw.id ?? ''),
    tenantId:       String(raw.tenant_id ?? ''),
    ruleId:         String(raw.rule_id ?? ''),
    ruleName:       String(raw.rule_name ?? ''),
    title:          String(raw.title ?? ''),
    description:    String(raw.description ?? ''),
    severity:       raw.severity ?? 'low',
    status:         raw.status ?? 'open',
    hostname:       String(raw.source_host ?? raw.hostname ?? ''),
    sourceIp:       raw.source_ip ? String(raw.source_ip) : undefined,
    username:       raw.username ? String(raw.username) : undefined,
    processName:    raw.process_name ? String(raw.process_name) : undefined,
    tags:           Array.isArray(raw.tags) ? raw.tags : [],
    rawEventCount:  Number(raw.raw_event_count ?? 0),
    firstSeenAt:    String(raw.first_seen_at ?? raw.created_at ?? ''),
    lastSeenAt:     String(raw.last_seen_at ?? raw.updated_at ?? ''),
    createdAt:      String(raw.created_at ?? ''),
    updatedAt:      String(raw.updated_at ?? ''),
    archived:       Boolean(raw.archived),
  } as Alert & { archived?: boolean }
}

export async function getRelatedAlerts(id: string): Promise<(Alert & { archived?: boolean })[]> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data } = await apiClient.get<APIResponse<any[]>>(
    `/investigations/${id}/related-alerts`
  );
  return (data.data ?? []).map(_adaptRelatedAlert)
}

// ─── Activity ─────────────────────────────────────────────────────────────────

export async function getInvestigationActivity(id: string): Promise<AnalystActivity[]> {
  const { data } = await apiClient.get<APIResponse<AnalystActivity[]>>(
    `/investigations/${id}/activity`
  );
  return data.data!;
}

// ─── Investigation list ───────────────────────────────────────────────────────

export interface InvestigationListItem {
  investigation_id: string
  tenant_id: string
  investigation_group_id: string
  threat_score: number
  confidence: string
  tp_probability: number
  fp_probability: number
  status: string
  verdict: string | null
  assigned_to: string | null
  assigned_to_name: string | null
  executive_summary: string
  title: string | null
  source: string | null
  created_at: string
  updated_at: string
  ai_analysis_json?: Record<string, unknown> | null
}

export interface InvestigationListResponse {
  data: InvestigationListItem[]
  next_cursor: string | null
  has_more: boolean
  total: number
}

export interface ListInvestigationsParams {
  status?: string
  title_search?: string
  min_score?: number
  assigned_to_me?: boolean
  from_ts?: string
  limit?: number
  cursor?: string
}

export async function listInvestigations(params?: ListInvestigationsParams): Promise<InvestigationListResponse> {
  const { data } = await apiClient.get<InvestigationListResponse>("/investigations", { params })
  return data
}

// ─── Manual create ────────────────────────────────────────────────────────────

export interface InvestigationCreate {
  title: string
  description?: string
  severity: "critical" | "high" | "medium" | "low"
  assigned_to?: string
  alert_ids?: string[]
}

export async function createInvestigation(
  payload: InvestigationCreate
): Promise<InvestigationListItem> {
  const { data } = await apiClient.post<APIResponse<InvestigationListItem>>(
    "/investigations",
    payload
  )
  return data.data!
}

// ─── Promote alert ────────────────────────────────────────────────────────────

export async function promoteAlert(
  alertId: string
): Promise<{ investigation_id: string }> {
  const { data } = await apiClient.post<APIResponse<{ investigation_id: string }>>(
    `/alerts/${alertId}/promote`
  )
  return data.data!
}

// ─── Placeholder data ─────────────────────────────────────────────────────────

export const PLACEHOLDER_TIMELINE: TimelineEvent[] = [];
export const PLACEHOLDER_EVIDENCE: EvidenceItem[] = [];
export const PLACEHOLDER_RELATED_ALERTS: Alert[] = [];
export const PLACEHOLDER_ACTIVITY: AnalystActivity[] = [];
