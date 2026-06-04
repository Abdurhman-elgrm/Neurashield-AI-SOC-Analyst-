import { useEffect, useRef } from 'react'
import { useAuthStore } from '@/stores/authStore'
import { useTenantStore } from '@/stores/tenantStore'
import { fetchMyTenants } from '@/api/tenants'
import type { MemberRole } from '@/types/tenant'

/**
 * Initialises the active tenant on every app mount (including page refreshes).
 *
 * tenantStore is NOT persisted, so activeTenant is always null after a refresh
 * even though authStore still holds the activeTenantId.
 *
 * Two scenarios handled:
 *  1. activeTenant is null  →  fetch tenants and select the first one
 *  2. activeTenant is set   →  no-op (already initialised for this session)
 */
export function useTenantInit() {
  const accessToken    = useAuthStore((s) => s.accessToken)
  const activeTenant   = useTenantStore((s) => s.activeTenant)
  const setAuthTenant  = useAuthStore((s) => s.setActiveTenant)
  const setStoreTenant = useTenantStore((s) => s.setActiveTenant)
  const initialised    = useRef(false)

  useEffect(() => {
    if (!accessToken)    return   // not logged in
    if (activeTenant)    return   // already set for this session
    if (initialised.current) return
    initialised.current = true

    fetchMyTenants()
      .then((tenants) => {
        if (tenants.length === 0) return
        const tenant = tenants[0]
        // Default to 'analyst' — good enough for most permissions.
        // The real role is resolved per-request by the backend RBAC layer.
        const role: MemberRole = 'analyst'
        setStoreTenant(tenant, role)
        setAuthTenant(tenant.id)
      })
      .catch((err) => {
        console.warn('[useTenantInit] failed to fetch tenants:', err)
        initialised.current = false   // allow retry next render
      })
  }, [accessToken, activeTenant, setAuthTenant, setStoreTenant])
}
