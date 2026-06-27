import { useEffect, useRef, useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { useAuthStore } from '@/stores/authStore'
import { useTenantStore } from '@/stores/tenantStore'
import { fetchMyTenants } from '@/api/tenants'
import type { MemberRole } from '@/types/tenant'

export function useTenantInit() {
  const navigate       = useNavigate()
  const location       = useLocation()
  const accessToken    = useAuthStore((s) => s.accessToken)
  const activeTenant   = useTenantStore((s) => s.activeTenant)
  const setAuthTenant  = useAuthStore((s) => s.setActiveTenant)
  const setStoreTenant = useTenantStore((s) => s.setActiveTenant)
  const running        = useRef(false)
  const [retryKey, setRetryKey] = useState(0)

  useEffect(() => {
    if (!accessToken) return
    if (activeTenant) return
    if (location.pathname === '/setup') return   // already on setup page
    if (running.current) return
    running.current = true

    const storedTenantId = useAuthStore.getState().activeTenantId

    fetchMyTenants()
      .then((tenants) => {
        running.current = false
        if (tenants.length === 0) {
          navigate('/setup', { replace: true })
          return
        }
        // Verify stored tenantId is still valid; fall back to first available
        const match = storedTenantId
          ? tenants.find((t) => t.id === storedTenantId)
          : null
        const tenant = match ?? tenants[0]
        const role: MemberRole = tenant.member_role ?? 'viewer'
        setStoreTenant(tenant, role)
        setAuthTenant(tenant.id)
      })
      .catch((err) => {
        console.warn('[useTenantInit] fetch failed, will retry:', err)
        running.current = false
        setTimeout(() => setRetryKey((k) => k + 1), 3000)
      })
   
  }, [accessToken, activeTenant, retryKey, location.pathname])
}
