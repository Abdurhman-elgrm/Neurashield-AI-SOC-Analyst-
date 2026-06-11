import { apiClient } from './client'

// ─── User Profile ─────────────────────────────────────────────────────────────

export interface UserProfile {
  id: string
  email: string
  full_name: string
  is_active: boolean
  created_at: string
  timezone?: string
}

export interface UpdateProfilePayload {
  full_name?: string
  timezone?: string
}

// ─── Tenant ───────────────────────────────────────────────────────────────────

export interface TenantInfo {
  id: string
  name: string
  slug: string
  is_active: boolean
  created_at: string
}

// ─── Member ───────────────────────────────────────────────────────────────────

export interface Member {
  id: string
  tenant_id: string
  user_id: string
  role: string
  joined_at: string | null
  created_at: string
  email: string | null
  full_name: string | null
}

// ─── API Keys ─────────────────────────────────────────────────────────────────

export interface ApiKey {
  id: string
  name: string
  key_prefix: string
  created_at: string
  last_used_at: string | null
  expires_at: string | null
  revoked_at: string | null
}

export interface ApiKeyCreateResponse extends ApiKey {
  raw_key: string
}

// ─── API ──────────────────────────────────────────────────────────────────────

export const settingsApi = {
  // Profile  — GET /api/v1/users/me  (no X-Tenant-ID required)
  getProfile: async (): Promise<UserProfile> => {
    const resp = await apiClient.get<{ data: UserProfile }>('/users/me')
    return resp.data.data
  },

  updateProfile: async (payload: UpdateProfilePayload): Promise<UserProfile> => {
    const resp = await apiClient.patch<{ data: UserProfile }>('/users/me', payload)
    return resp.data.data
  },

  // Tenant  — GET /api/v1/tenants/{id}
  getTenant: async (id: string): Promise<TenantInfo> => {
    const resp = await apiClient.get<{ data: TenantInfo }>(`/tenants/${id}`)
    return resp.data.data
  },

  updateTenant: async (id: string, payload: { name: string }): Promise<TenantInfo> => {
    const resp = await apiClient.patch<{ data: TenantInfo }>(`/tenants/${id}`, payload)
    return resp.data.data
  },

  // Members  — GET /api/v1/tenants/{tenant_id}/members  (needs X-Tenant-ID)
  getMembers: async (tenantId: string): Promise<Member[]> => {
    const resp = await apiClient.get<{ data: Member[] }>(`/tenants/${tenantId}/members`)
    return resp.data.data ?? []
  },

  updateMemberRole: async (tenantId: string, userId: string, role: string) =>
    apiClient.patch(`/tenants/${tenantId}/members/${userId}/role`, { role }),

  removeMember: async (tenantId: string, userId: string) =>
    apiClient.delete(`/tenants/${tenantId}/members/${userId}`),

  // API Keys  — GET/POST/DELETE /api/v1/api-keys
  listApiKeys: async (): Promise<ApiKey[]> => {
    const resp = await apiClient.get<{ data: ApiKey[] }>('/api-keys')
    return resp.data.data ?? []
  },

  createApiKey: async (name: string, expires_in_days?: number): Promise<ApiKeyCreateResponse> => {
    const resp = await apiClient.post<{ data: ApiKeyCreateResponse }>('/api-keys', {
      name,
      expires_in_days: expires_in_days ?? null,
    })
    return resp.data.data
  },

  revokeApiKey: async (id: string): Promise<void> => {
    await apiClient.delete(`/api-keys/${id}`)
  },
}
