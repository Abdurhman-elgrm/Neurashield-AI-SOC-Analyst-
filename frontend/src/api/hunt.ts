import { apiGet, apiPost } from './client'

export type FilterOperator = 'eq' | 'contains' | 'startswith' | 'endswith' | 'gt' | 'lt' | 'gte' | 'lte'
export type FilterLogic = 'and' | 'or'

export interface HuntFilter {
  field: string
  operator: FilterOperator
  value: string
}

export interface HuntQuery {
  filters: HuntFilter[]
  logic: FilterLogic
  from_ts?: string | null
  to_ts?: string | null
  mitre_tactics?: string[]
  limit?: number
  cursor?: string | null
}

export interface HuntResultEntry {
  investigation_id: string
  tenant_id: string
  threat_score: number
  confidence: string
  status: string
  verdict: string | null
  assigned_to: string | null
  executive_summary: string
  created_at: string
  match_reasons: string[]
}

export interface HuntResult {
  entries: HuntResultEntry[]
  total: number
  next_cursor: string | null
  has_more: boolean
}

export interface SavedHunt {
  hunt_id: string
  name: string
  description?: string | null
  query_params: Record<string, unknown>
  run_count: number
  created_at: string
}

export interface SavedHuntCreate {
  name: string
  description?: string
  query_params: Record<string, unknown>
}

export const huntApi = {
  run: (query: HuntQuery) =>
    apiPost<HuntResult>('/investigations/hunt', query),

  saveHunt: (data: SavedHuntCreate) =>
    apiPost<SavedHunt>('/investigations/hunt/saved', data),

  listSaved: () =>
    apiGet<SavedHunt[]>('/investigations/hunt/saved'),
}
