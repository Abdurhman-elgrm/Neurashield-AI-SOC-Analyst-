import { apiClient } from "@/api/client";
import type { APIResponse } from "@/types/api";
import type {
  Alert,
  AlertListParams,
  AlertListResponse,
  AlertContext,
  AlertTimelineEvent,
  AlertNote,
  BulkActionPayload,
  BulkActionResult,
} from "@/features/alerts/types";

// ─── List alerts (paginated, filterable) ──────────────────────────────────────

export async function getAlerts(params: AlertListParams): Promise<AlertListResponse> {
  const { data } = await apiClient.get<APIResponse<AlertListResponse>>("/alerts", {
    params: {
      page: params.page ?? 1,
      page_size: params.pageSize ?? 50,
      sort: params.sort ?? "-created_at",
      ...(params.severity?.length && { severity: params.severity.join(",") }),
      ...(params.status?.length && { status: params.status.join(",") }),
      ...(params.hostname && { hostname: params.hostname }),
      ...(params.username && { username: params.username }),
      ...(params.sourceIp && { source_ip: params.sourceIp }),
      ...(params.mitreTechnique && { mitre_technique: params.mitreTechnique }),
      ...(params.aiVerdict?.length && { ai_verdict: params.aiVerdict.join(",") }),
      ...(params.assignedTo && { assigned_to: params.assignedTo }),
      ...(params.tags?.length && { tags: params.tags.join(",") }),
      ...(params.search && { search: params.search }),
      ...(params.timeRange && { time_range: params.timeRange }),
      ...(params.correlationId && { correlation_id: params.correlationId }),
    },
  });
  return data.data!;
}

// ─── Single alert detail ──────────────────────────────────────────────────────

export async function getAlertDetail(alertId: string): Promise<Alert> {
  const { data } = await apiClient.get<APIResponse<Alert>>(`/alerts/${alertId}`);
  return data.data!;
}

// ─── Alert investigation context (related alerts, entity graph) ───────────────

export async function getAlertContext(alertId: string): Promise<AlertContext> {
  const { data } = await apiClient.get<APIResponse<AlertContext>>(
    `/alerts/${alertId}/context`
  );
  return data.data!;
}

// ─── Alert timeline ───────────────────────────────────────────────────────────

export async function getAlertTimeline(alertId: string): Promise<AlertTimelineEvent[]> {
  const { data } = await apiClient.get<APIResponse<AlertTimelineEvent[]>>(
    `/alerts/${alertId}/timeline`
  );
  return data.data!;
}

// ─── Add analyst note ─────────────────────────────────────────────────────────

export async function addAlertNote(
  alertId: string,
  content: string
): Promise<AlertNote> {
  const { data } = await apiClient.post<APIResponse<AlertNote>>(
    `/alerts/${alertId}/notes`,
    { content }
  );
  return data.data!;
}

// ─── Bulk operations ──────────────────────────────────────────────────────────

export async function bulkUpdateAlerts(
  payload: BulkActionPayload
): Promise<BulkActionResult> {
  const { data } = await apiClient.post<APIResponse<BulkActionResult>>(
    "/alerts/bulk",
    {
      alert_ids: payload.alertIds,
      action: payload.action,
      ...(payload.assignTo && { assign_to: payload.assignTo }),
      ...(payload.tag && { tag: payload.tag }),
      ...(payload.severity && { severity: payload.severity }),
    }
  );
  return data.data!;
}

// ─── Placeholder data ─────────────────────────────────────────────────────────

export const PLACEHOLDER_ALERT_LIST: AlertListResponse = {
  items: [],
  total: 0,
  page: 1,
  pageSize: 50,
  pageCount: 0,
};
