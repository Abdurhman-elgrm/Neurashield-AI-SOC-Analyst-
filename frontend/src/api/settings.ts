import { apiClient } from './client'

// ─── User Profile ─────────────────────────────────────────────────────────────

export interface UserProfile {
  id: string
  email: string
  full_name: string
  is_active: boolean
  created_at: string
  timezone?: string
  email_verified?: boolean
  avatar_url?: string | null
  job_title?: string | null
  bio?: string | null
  gravatar_url?: string | null
}

export interface UpdateProfilePayload {
  full_name?: string
  timezone?: string
  avatar_url?: string | null
  job_title?: string | null
  bio?: string | null
}

// ─── Tenant ───────────────────────────────────────────────────────────────────

export interface TenantInfo {
  id: string
  name: string
  slug: string
  is_active: boolean
  created_at: string
  timezone: string
  logo_url: string | null
  event_retention_days: number
  alert_retention_days: number
}

export interface TenantUpdatePayload {
  name?: string
  timezone?: string
  logo_url?: string | null
  event_retention_days?: number
  alert_retention_days?: number
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
  custom_permissions?: { grant: string[]; revoke: string[] }
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

// ─── Notification Preferences ─────────────────────────────────────────────────

export interface NotificationPreferences {
  email_high_critical_alerts: boolean
  email_agent_offline: boolean
  email_new_investigation: boolean
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

  updateTenant: async (id: string, payload: TenantUpdatePayload): Promise<TenantInfo> => {
    const resp = await apiClient.patch<{ data: TenantInfo }>(`/tenants/${id}`, payload)
    return resp.data.data
  },

  deleteTenant: async (id: string): Promise<void> => {
    await apiClient.delete(`/tenants/${id}`)
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

  updateMemberPermissions: (tenantId: string, userId: string, grant: string[], revoke: string[]) =>
    apiClient.patch(`/tenants/${tenantId}/members/${userId}/permissions`, { grant, revoke }),

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

  // Notification preferences  — GET/PATCH /api/v1/notifications
  getNotificationPrefs: async (): Promise<NotificationPreferences> => {
    const resp = await apiClient.get<{ data: NotificationPreferences }>('/notifications')
    return resp.data.data!
  },

  updateNotificationPrefs: async (prefs: Partial<NotificationPreferences>): Promise<NotificationPreferences> => {
    const resp = await apiClient.patch<{ data: NotificationPreferences }>('/notifications', prefs)
    return resp.data.data!
  },
}
