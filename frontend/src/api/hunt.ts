import { apiGet, apiPost } from './client'

// ─── Shared ───────────────────────────────────────────────────────────────────

export type FilterOperator = 'eq' | 'contains' | 'startswith' | 'endswith' | 'gt' | 'lt' | 'gte' | 'lte'
export type FilterLogic    = 'and' | 'or'

export interface SavedHunt {
  hunt_id:      string
  name:         string
  description?: string | null
  query_params: Record<string, unknown>
  run_count:    number
  created_at:   string
}

export interface SavedHuntCreate {
  name:         string
  description?: string
  query_params: Record<string, unknown>
}

// ─── Investigation Hunt ───────────────────────────────────────────────────────

export interface HuntFilter {
  field:    string
  operator: FilterOperator
  value:    string
}

export interface HuntQuery {
  filters:       HuntFilter[]
  logic:         FilterLogic
  from_ts?:      string | null
  to_ts?:        string | null
  mitre_tactics?: string[]
  limit?:        number
  cursor?:       string | null
}

export interface HuntResultEntry {
  investigation_id: string
  tenant_id:        string
  threat_score:     number
  confidence:       string
  status:           string
  verdict:          string | null
  assigned_to:      string | null
  executive_summary: string
  created_at:       string
  match_reasons:    string[]
}

export interface HuntResult {
  entries:     HuntResultEntry[]
  total:       number
  next_cursor: string | null
  has_more:    boolean
}

// ─── Event Hunt ───────────────────────────────────────────────────────────────

export interface EventHuntFilter {
  field:    string
  operator: FilterOperator
  value:    string
}

export interface EventHuntQuery {
  filters:       EventHuntFilter[]
  logic:         FilterLogic
  from_ts?:      string | null
  to_ts?:        string | null
  // Quick filters
  category?:     string[]
  min_severity?: number | null
  is_anomaly?:   boolean | null
  is_threat_ip?: boolean | null
  ueba_flags?:   string[]
  tags?:         string[]
  cursor?:       string | null
  limit?:        number
  sort?:         'asc' | 'desc'
}

export interface EventHuntResultEntry {
  event_id:       string
  timestamp:      string
  host_name:      string | null
  username:       string | null
  source_ip:      string | null
  dest_ip:        string | null
  process_name:   string | null
  category:       string
  severity:       number
  is_anomaly:     boolean
  is_threat_ip:   boolean
  anomaly_score:  number
  ueba_flags:     string[]
  tags:           string[]
  match_reasons:  string[]
  correlation_id: string | null
  geo_country:    string | null
}

export interface EventHuntSummary {
  unique_hosts:     number
  unique_users:     number
  unique_ips:       number
  total_anomalies:  number
  total_threat_ips: number
}

export interface EventHuntResult {
  entries:     EventHuntResultEntry[]
  total:       number
  next_cursor: string | null
  has_more:    boolean
  summary:     EventHuntSummary
}

// ─── API ──────────────────────────────────────────────────────────────────────

export const huntApi = {
  // Investigation-level hunt
  run: (query: HuntQuery) =>
    apiPost<HuntResult>('/investigations/hunt', query),

  // Raw event-level hunt (true threat hunting)
  runEventHunt: (query: EventHuntQuery) =>
    apiPost<EventHuntResult>('/investigations/hunt/events', query),

  saveHunt: (data: SavedHuntCreate) =>
    apiPost<SavedHunt>('/investigations/hunt/saved', data),

  listSaved: () =>
    apiGet<SavedHunt[]>('/investigations/hunt/saved'),
}
