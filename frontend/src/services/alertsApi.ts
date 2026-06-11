import { apiClient } from "@/api/client";
import type { APIResponse } from "@/types/api";
import type {
  Alert,
  AlertSeverity,
  AlertStatus,
  AlertListParams,
  AlertListResponse,
  BulkActionPayload,
  BulkActionResult,
} from "@/features/alerts/types";

// ─── Backend → Frontend adapter ───────────────────────────────────────────────
// Backend returns snake_case PaginatedResponse; frontend needs camelCase Alert

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function adaptAlert(raw: Record<string, any>): Alert {
  return {
    id:               String(raw.id ?? ""),
    tenantId:         String(raw.tenant_id ?? ""),
    ruleId:           String(raw.rule_id ?? ""),
    ruleName:         String(raw.rule_name ?? ""),
    title:            String(raw.title ?? ""),
    description:      String(raw.description ?? ""),
    severity:         (raw.severity as AlertSeverity) ?? "low",
    status:           (raw.status as AlertStatus) ?? "open",
    hostname:         String(raw.source_host ?? raw.hostname ?? ""),
    sourceIp:         raw.source_ip ? String(raw.source_ip) : undefined,
    username:         raw.username ? String(raw.username) : undefined,
    processName:      raw.process_name ? String(raw.process_name) : undefined,
    mitre:            undefined,
    correlationId:    raw.correlation_id ? String(raw.correlation_id) : undefined,
    correlationScore: raw.correlation_score != null ? Number(raw.correlation_score) : undefined,
    assignedTo:       raw.assignee_id ? String(raw.assignee_id) : undefined,
    assignedToName:   raw.assignee_name ? String(raw.assignee_name) : undefined,
    aiVerdict:        undefined,
    tags:             Array.isArray(raw.tags) ? (raw.tags as string[]) : [],
    rawEventCount:    Number(raw.raw_event_count ?? 0),
    firstSeenAt:      String(raw.first_seen_at ?? raw.created_at ?? ""),
    lastSeenAt:       String(raw.last_seen_at ?? raw.updated_at ?? ""),
    createdAt:        String(raw.created_at ?? ""),
    updatedAt:        String(raw.updated_at ?? ""),
    acknowledgedAt:   raw.acknowledged_at ? String(raw.acknowledged_at) : undefined,
    closedAt:         raw.closed_at ? String(raw.closed_at) : undefined,
    notes:            raw.notes ? String(raw.notes) : undefined,
  };
}

// ─── List alerts (paginated, filterable) ──────────────────────────────────────

export async function getAlerts(params: AlertListParams): Promise<AlertListResponse> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data } = await apiClient.get<any>("/alerts", {
    params: {
      limit: params.pageSize ?? 50,
      ...(params.status?.length && { status: params.status.join(",") }),
      ...(params.severity?.length && { severity: params.severity.join(",") }),
      ...(params.hostname && { source_host: params.hostname }),
      ...(params.search && { search: params.search }),
      ...(params.cursor && { cursor: params.cursor }),
    },
  });

  // Backend returns PaginatedResponse: { data: [...items], pagination: { next_cursor, has_more, limit }, meta: {...} }
  const items: Alert[] = (data.data ?? []).map(adaptAlert);
  const pagination = data.pagination ?? {};

  return {
    items,
    total:     items.length,
    page:      1,
    pageSize:  params.pageSize ?? 50,
    pageCount: pagination.has_more ? 2 : 1,
    nextCursor: pagination.next_cursor ?? undefined,
  } as AlertListResponse & { nextCursor?: string };
}

// ─── Single alert detail ──────────────────────────────────────────────────────

export async function getAlertDetail(alertId: string): Promise<Alert> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data } = await apiClient.get<APIResponse<any>>(`/alerts/${alertId}`);
  return adaptAlert(data.data!);
}

// ─── Update alert status / notes / assignee ───────────────────────────────────

export async function updateAlert(
  alertId: string,
  payload: { status?: string; notes?: string; assigneeId?: string }
): Promise<Alert> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data } = await apiClient.patch<APIResponse<any>>(`/alerts/${alertId}`, {
    ...(payload.status !== undefined && { status: payload.status }),
    ...(payload.notes !== undefined && { notes: payload.notes }),
    ...(payload.assigneeId !== undefined && { assignee_id: payload.assigneeId }),
  });
  return adaptAlert(data.data!);
}

// ─── Alert investigation context (stubs — backend endpoints not yet implemented) ─

export async function getAlertContext(_alertId: string): Promise<import("@/features/alerts/types").AlertContext> {
  return { alertId: _alertId, relatedAlerts: [] };
}

export async function getAlertTimeline(_alertId: string): Promise<import("@/features/alerts/types").AlertTimelineEvent[]> {
  return [];
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
