import { apiClient } from './client'

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
  list: (params?: {
    status?: string
    limit?: number
    page?: number
    search?: string
  }) => apiClient.get<AgentsListResponse>('/agents', { params }),

  get: (id: string) =>
    apiClient.get<{ data: Agent; error: null }>(`/agents/${id}`),

  update: (id: string, data: { tags?: string[]; name?: string }) =>
    apiClient.patch<{ data: Agent; error: null }>(`/agents/${id}`, data),

  delete: (id: string) =>
    apiClient.delete(`/agents/${id}`),
}
