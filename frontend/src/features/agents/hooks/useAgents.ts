import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { agentsApi } from '@/api/agents'

export function useAgents(params?: { status?: string; search?: string }) {
  return useQuery({
    queryKey: ['agents', params],
    queryFn: async () => {
      const resp = await agentsApi.list(params)
      return {
        items: resp.data.data,
        total: resp.data.pagination.total,
      }
    },
    refetchInterval: 30_000,
  })
}

export function useAgent(id: string) {
  return useQuery({
    queryKey: ['agents', id],
    queryFn: async () => {
      const resp = await agentsApi.get(id)
      return resp.data.data
    },
    enabled: !!id,
  })
}

export function useDeleteAgent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => agentsApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })
}
