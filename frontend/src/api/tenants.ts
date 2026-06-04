import { apiClient } from './client'
import type { Tenant } from '@/types/tenant'

interface TenantsResponse {
  data: Tenant[]
  error: null
}

// GET /api/v1/tenants — requires only Bearer token, no X-Tenant-ID
export async function fetchMyTenants(): Promise<Tenant[]> {
  const resp = await apiClient.get<TenantsResponse>('/tenants')
  return resp.data.data ?? []
}
