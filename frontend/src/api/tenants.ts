import { apiClient } from './client'
import type { Tenant } from '@/types/tenant'

interface TenantsResponse {
  data: Tenant[]
  error: null
}

interface TenantResponse {
  data: Tenant
  error: null
}

// GET /api/v1/tenants — requires only Bearer token, no X-Tenant-ID
export async function fetchMyTenants(): Promise<Tenant[]> {
  const resp = await apiClient.get<TenantsResponse>('/tenants')
  return resp.data.data ?? []
}

// POST /api/v1/tenants — create a new workspace (Bearer token only, no X-Tenant-ID)
export async function createTenant(name: string): Promise<Tenant> {
  const resp = await apiClient.post<TenantResponse>('/tenants', { name })
  return resp.data.data
}
