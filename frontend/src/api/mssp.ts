import { apiGet, apiPost } from "./client";

export interface TenantHealthCard {
  tenant_id:                  string;
  tenant_name:                string;
  open_critical_alerts:       number;
  unresolved_investigations:  number;
  agents_online:              number;
  last_event_at:              string | null;
  breach_status:              "green" | "amber" | "red";
  oldest_critical_alert_age_ms: number;
}

export interface CrossTenantAlertPoint {
  date:    string;
  tenants: Record<string, number>;
}

export interface MSSPOverviewResponse {
  tenants:     TenantHealthCard[];
  alert_trend: CrossTenantAlertPoint[];
}

export const msspApi = {
  getOverview: () =>
    apiGet<MSSPOverviewResponse>("/mssp/overview"),

  createTenant: (name: string) =>
    apiPost<{ tenant_id: string; name: string }>("/mssp/tenants", { name }),
};
