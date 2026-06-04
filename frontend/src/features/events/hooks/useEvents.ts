import { useQuery } from '@tanstack/react-query'
import { eventsApi, type EventSearchRequest } from '@/api/events'
import { severityToInt } from '@/api/events'

export interface UseEventsParams {
  query?: string
  category?: string
  severity?: string
  host_name?: string
  agent_id?: string
  cursor?: string | null
  limit?: number
}

export function useEvents(params?: UseEventsParams) {
  return useQuery({
    queryKey: ['events', params],
    queryFn: async () => {
      const body: EventSearchRequest = {
        query: params?.query || undefined,
        categories: params?.category ? [params.category] : undefined,
        severity_min: params?.severity ? severityToInt(params.severity) : undefined,
        host_names: params?.host_name ? [params.host_name] : undefined,
        agent_ids: params?.agent_id ? [params.agent_id] : undefined,
        cursor: params?.cursor ?? null,
        limit: params?.limit ?? 50,
        sort_dir: 'desc',
        sort_by: 'event_timestamp',
      }
      const resp = await eventsApi.search(body)
      return resp.data
    },
    staleTime: 10_000,
  })
}

export function useEvent(id: string) {
  return useQuery({
    queryKey: ['event', id],
    queryFn: async () => {
      const resp = await eventsApi.get(id)
      return resp.data.data
    },
    enabled: !!id,
  })
}
