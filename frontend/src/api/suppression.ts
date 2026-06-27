import { apiGet, apiPost, apiPatch, apiDelete } from "./client";

export type SuppressionDuration = "1h" | "4h" | "24h" | "7d" | "30d" | "indefinite";
export type SuppressionReason = "testing" | "known_good" | "noisy_rule" | "maintenance_window" | "other";

export interface SuppressionCondition {
  field: "hostname_glob" | "username_glob" | "rule_name_contains" | "source_ip_cidr" | "mitre_technique";
  value: string;
}

export interface SuppressionRule {
  id: string;
  name: string;
  conditions: SuppressionCondition[];
  duration: SuppressionDuration;
  reason: SuppressionReason;
  notes: string;
  created_by: string;
  created_at: string;
  expires_at: string | null;
  alert_count: number;
  status: "active" | "expired";
}

export interface CreateSuppressionPayload {
  name: string;
  conditions: SuppressionCondition[];
  duration: SuppressionDuration;
  reason: SuppressionReason;
  notes?: string;
}

export const suppressionApi = {
  list: () =>
    apiGet<SuppressionRule[]>("/suppression-rules"),

  create: (payload: CreateSuppressionPayload) =>
    apiPost<SuppressionRule>("/suppression-rules", payload),

  update: (id: string, payload: Partial<CreateSuppressionPayload>) =>
    apiPatch<SuppressionRule>(`/suppression-rules/${id}`, payload),

  delete: (id: string) =>
    apiDelete(`/suppression-rules/${id}`),
};
