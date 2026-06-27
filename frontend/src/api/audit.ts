import { apiClient, apiGet } from "./client";

export interface AuditEvent {
  id: string;
  timestamp: string;
  actor_name: string;
  actor_id: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  resource_title: string | null;
  old_value: unknown;
  new_value: unknown;
  ip_address: string | null;
}

export interface AuditListResponse {
  events: AuditEvent[];
  total: number;
  page: number;
  page_size: number;
}

export const auditApi = {
  list: (params: { page?: number; pageSize?: number; actor?: string; action?: string; resourceType?: string }) =>
    apiGet<AuditListResponse>("/audit/events", {
      page:          params.page ?? 1,
      page_size:     params.pageSize ?? 50,
      actor:         params.actor,
      action:        params.action,
      resource_type: params.resourceType,
    }),

  exportCsv: (params: { actor?: string; action?: string; resourceType?: string }) =>
    apiClient.get<Blob>("/audit/events/export", { params, responseType: "blob" }).then((r) => r.data),
};
