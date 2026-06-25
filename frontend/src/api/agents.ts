import { apiPost, apiGet, apiPatch, apiDelete, apiClient } from './client'

export interface Agent {
  id: string
  name: string
  hostname: string
  os_type: string
  status: string
  ip_address: string | null
  agent_version: string | null
  last_seen_at: string | null
  tags: string[]
  created_at: string
  updated_at: string
  tenant_id: string
  config: Record<string, unknown>
  containment_state?: string
  containment_reason?: string | null
  contained_at?: string | null
}

export interface ContainmentStatus {
  agent_id: string
  hostname: string
  containment_state: string
  containment_reason: string | null
  contained_at: string | null
  contained_by_id: string | null
}

export interface ResponseAction {
  id: string
  action_type: string
  target_type: string
  target_name: string | null
  status: string
  result: string | null
  created_at: string
}

interface OffsetPagination {
  page: number
  limit: number
  total: number
  pages: number
}

export interface AgentsListResponse {
  data: Agent[]
  pagination: OffsetPagination
}

export const agentsApi = {
  list: async (params?: {
    status?: string
    limit?: number
    page?: number
    search?: string
  }): Promise<AgentsListResponse> => {
    const resp = await apiClient.get<AgentsListResponse>('/agents', { params: params as Record<string, unknown> })
    return resp.data
  },

  get: (id: string): Promise<Agent> =>
    apiGet<Agent>(`/agents/${id}`),

  update: (id: string, data: { tags?: string[]; name?: string }): Promise<Agent> =>
    apiPatch<Agent>(`/agents/${id}`, data),

  delete: (id: string): Promise<void> =>
    apiDelete(`/agents/${id}`),

  getContainment: (id: string): Promise<ContainmentStatus> =>
    apiGet<ContainmentStatus>(`/agents/${id}/containment`),

  quarantine: (id: string, reason: string): Promise<ContainmentStatus> =>
    apiPost<ContainmentStatus>(`/agents/${id}/quarantine`, { reason }),

  isolate: (id: string, reason: string): Promise<ContainmentStatus> =>
    apiPost<ContainmentStatus>(`/agents/${id}/isolate`, { reason }),

  release: (id: string, reason?: string): Promise<ContainmentStatus> =>
    apiPost<ContainmentStatus>(`/agents/${id}/release`, { reason: reason ?? '' }),

  getResponseActions: (id: string): Promise<ResponseAction[]> =>
    apiGet<ResponseAction[]>(`/agents/${id}/response-actions`),
}
