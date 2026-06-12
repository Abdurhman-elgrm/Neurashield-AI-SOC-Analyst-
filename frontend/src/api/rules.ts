import { apiClient } from './client'

export type RuleType     = 'pattern' | 'threshold'
export type RuleSeverity = 'low' | 'medium' | 'high' | 'critical'
export type PatternOp    = 'eq' | 'contains' | 'regex' | 'in' | 'ne'

export interface PatternCondition {
  field: string
  op:    PatternOp
  value: string | string[]
}

export interface ThresholdCondition {
  field:       string
  group_by:    string
  threshold:   number
  window_secs: number
  filters?:    PatternCondition[]
}

export interface DetectionRule {
  id:                     string
  tenant_id:              string
  name:                   string
  description:            string | null
  rule_type:              RuleType
  severity:               RuleSeverity
  enabled:                boolean
  conditions:             PatternCondition[] | ThresholdCondition
  mitre_tactics:          string[]
  mitre_techniques:       string[]
  suppression_window_secs: number
  created_by_id:          string | null
  created_at:             string
  updated_at:             string
}

export interface RulesPaginatedResponse {
  data:       DetectionRule[]
  pagination: { page: number; limit: number; total: number; pages: number }
}

export interface RuleCreateRequest {
  name:                   string
  description?:           string
  rule_type:              RuleType
  severity:               RuleSeverity
  conditions:             PatternCondition[] | ThresholdCondition
  mitre_tactics?:         string[]
  mitre_techniques?:      string[]
  suppression_window_secs?: number
}

export interface RuleUpdateRequest {
  name?:                  string
  description?:           string
  severity?:              RuleSeverity
  enabled?:               boolean
  conditions?:            PatternCondition[] | ThresholdCondition
  mitre_tactics?:         string[]
  mitre_techniques?:      string[]
  suppression_window_secs?: number
}

export const rulesApi = {
  list: (params?: { page?: number; limit?: number; enabled_only?: boolean }) =>
    apiClient.get<RulesPaginatedResponse>('/rules', { params }),

  get: (id: string) =>
    apiClient.get<{ data: DetectionRule }>(`/rules/${id}`),

  create: (data: RuleCreateRequest) =>
    apiClient.post<{ data: DetectionRule }>('/rules', data),

  update: (id: string, data: RuleUpdateRequest) =>
    apiClient.patch<{ data: DetectionRule }>(`/rules/${id}`, data),

  delete: (id: string) =>
    apiClient.delete(`/rules/${id}`),

  toggle: (id: string, enabled: boolean) =>
    apiClient.patch<{ data: DetectionRule }>(`/rules/${id}`, { enabled }),
}
