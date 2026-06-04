import { useEffect, useRef, useState } from 'react'
import { useAuthStore } from '@/stores/authStore'
import { useTenantStore } from '@/stores/tenantStore'
import { fetchMyTenants } from '@/api/tenants'
import type { MemberRole } from '@/types/tenant'

export function useTenantInit() {
  const accessToken    = useAuthStore((s) => s.accessToken)
  const activeTenant   = useTenantStore((s) => s.activeTenant)
  const setAuthTenant  = useAuthStore((s) => s.setActiveTenant)
  const setStoreTenant = useTenantStore((s) => s.setActiveTenant)
  const running        = useRef(false)
  // retryKey increments on error to re-trigger the effect
  const [retryKey, setRetryKey] = useState(0)

  useEffect(() => {
    if (!accessToken) return
    if (activeTenant) return
    if (running.current) return
    running.current = true

    fetchMyTenants()
      .then((tenants) => {
        running.current = false
        if (tenants.length === 0) return   // no tenants — TenantSelector handles creation
        const tenant = tenants[0]
        const role: MemberRole = 'analyst'
        setStoreTenant(tenant, role)
        setAuthTenant(tenant.id)
      })
      .catch((err) => {
        console.warn('[useTenantInit] fetch failed, will retry:', err)
        running.current = false
        // Increment key after a short delay to re-trigger the effect
        setTimeout(() => setRetryKey((k) => k + 1), 3000)
      })
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accessToken, activeTenant, retryKey])
}
