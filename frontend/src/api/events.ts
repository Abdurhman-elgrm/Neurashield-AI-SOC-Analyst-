import { apiClient } from './client'

// ─── Severity: backend sends integer 1-4 ─────────────────────────────────────

export type EventSeverityInt = 1 | 2 | 3 | 4

export function severityLabel(s: number): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  if (s >= 4) return 'critical'
  if (s >= 3) return 'high'
  if (s >= 2) return 'medium'
  if (s >= 1) return 'low'
  return 'info'
}

export function severityToInt(s: string): number {
  switch (s) {
    case 'critical': return 4
    case 'high':     return 3
    case 'medium':   return 2
    case 'low':      return 1
    default:         return 0
  }
}

// ─── Event shape (mirrors backend EventResponse) ──────────────────────────────

export interface EventResponse {
  id: string
  tenant_id: string
  agent_id: string | null
  stream_id: string | null
  raw_id: string | null
  category: string
  severity: number
  event_timestamp: string
  ingested_at: string | null
  host_name: string | null
  source_ip: string | null
  dest_ip: string | null
  process_name: string | null
  username: string | null
  process: Record<string, unknown> | null
  user: Record<string, unknown> | null
  network: Record<string, unknown> | null
  file: Record<string, unknown> | null
  registry: Record<string, unknown> | null
  tags: string[]
  correlation_id: string | null
  session_id: string | null
  process_tree_id: string | null
  event_chain_id: string | null
  raw?: Record<string, unknown> | null
  // GeoIP enrichment (Phase 1)
  geo_country: string | null
  geo_country_code: string | null
  geo_city: string | null
  geo_latitude: number | null
  geo_longitude: number | null
  geo_isp: string | null
  // Threat Intel enrichment (Phase 1)
  abuse_confidence: number
  is_threat_ip: boolean
  threat_intel_flags: string[]
}

// ─── Search request (mirrors backend EventSearchRequest) ─────────────────────

export interface EventSearchRequest {
  query?: string
  categories?: string[]
  severity_min?: number
  severity_max?: number
  host_names?: string[]
  usernames?: string[]
  source_ips?: string[]
  dest_ips?: string[]
  process_names?: string[]
  agent_ids?: string[]
  tags?: string[]
  from_ts?: string
  to_ts?: string
  sort_by?: 'event_timestamp' | 'ingested_at' | 'severity' | 'host_name'
  sort_dir?: 'asc' | 'desc'
  cursor?: string | null
  limit?: number
}

// ─── Search response ──────────────────────────────────────────────────────────

export interface EventSearchResponse {
  items: EventResponse[]
  next_cursor: string | null
  prev_cursor: string | null
  has_more: boolean
  total_estimate: number | null
}

// ─── Cursor-paginated list response (from GET /events) ───────────────────────

export interface EventsListResponse {
  data: EventResponse[]
  pagination: {
    next_cursor: string | null
    prev_cursor: string | null
    has_more: boolean
    limit: number
  }
}

// ─── Export request ───────────────────────────────────────────────────────────

export interface EventExportRequest {
  format: 'csv' | 'json' | 'ndjson'
  query?: string
  categories?: string[]
  severity_min?: number
  host_names?: string[]
  agent_ids?: string[]
  from_ts?: string
  to_ts?: string
  max_rows?: number
}

// ─── API ──────────────────────────────────────────────────────────────────────

export const eventsApi = {
  search: (req: EventSearchRequest) =>
    apiClient.post<EventSearchResponse>('/events/search', req),

  list: (params?: {
    category?: string
    severity_min?: number
    host_name?: string
    agent_id?: string
    cursor?: string
    limit?: number
  }) => apiClient.get<EventsListResponse>('/events', { params }),

  get: (id: string) =>
    apiClient.get<{ data: EventResponse; error: null }>(`/events/${id}`),

  export: (req: EventExportRequest) =>
    apiClient.post('/events/export', req, { responseType: 'blob' }),
}
