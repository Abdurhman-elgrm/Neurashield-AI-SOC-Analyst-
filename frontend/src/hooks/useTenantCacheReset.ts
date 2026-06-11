import { useEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useTenantStore } from '@/stores/tenantStore'

/**
 * Clears all React Query cache when the active tenant changes.
 * Prevents data from Tenant A leaking into Tenant B's UI.
 */
export function useTenantCacheReset() {
  const queryClient = useQueryClient()
  const activeTenant = useTenantStore((s) => s.activeTenant)
  const prevTenantId = useRef<string | null>(null)

  useEffect(() => {
    const newId = activeTenant?.id ?? null
    if (prevTenantId.current !== null && prevTenantId.current !== newId) {
      queryClient.clear()
    }
    prevTenantId.current = newId
  }, [activeTenant?.id, queryClient])
}
