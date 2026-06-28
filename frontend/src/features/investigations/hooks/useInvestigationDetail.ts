import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/api/client'
import { toastError } from '@/lib/toast'
import { extractApiError } from '@/lib/utils'

// ─── Backend types ────────────────────────────────────────────────────────────

export interface AIAnalysis {
  executive_summary: string
  attack_narrative: string
  kill_chain_stage: string
  kill_chain_index: number
  threat_actor_attribution: string
  threat_actor_details: {
    name: string
    confidence: number
    matching_ttps: string[]
  }
  evidence_strength: {
    strong: string[]
    circumstantial: string[]
    noise: string[]
  }
  recommended_actions: string[]
  verdict_suggestion: 'true_positive' | 'false_positive' | 'needs_investigation'
  verdict_confidence: number
  rag_sources_used: string[]
  analyst_feedback?: {
    verdict: string
    timestamp: string
    agreed_with_ai: boolean | null
  }
}

export interface InvestigationDetail {
  investigation_id: string
  tenant_id: string
  investigation_group_id: string
  threat_score: number
  confidence: string
  tp_probability: number
  fp_probability: number
  status: string
  verdict: string | null
  assigned_to: string | null
  executive_summary: string
  title: string | null
  source: string | null
  created_at: string
  updated_at: string
  resolved_at?: string | null
  closed_at?: string | null
  triaged_at?: string | null
  investigating_at?: string | null
  contained_at?: string | null
  technical_summary: string
  attack_progression: string[]
  recommended_actions: string[]
  note_count: number
  evidence_count: number
  ai_analysis_json?: AIAnalysis | null
}

export interface TimelineEntryOut {
  event_id: string
  timestamp: number
  hostname: string
  username: string | null
  process: string | null
  action: string
  outcome: string
  rule_match: string[]
  severity: number
  category: string
  entity_keys: string[]
}

export interface TimelineResponse {
  investigation_id: string
  entries: TimelineEntryOut[]
  total_events: number
  filtered_count: number
  first_seen: number
  last_seen: number
  next_cursor: string | null
  has_more: boolean
}

export interface GraphNodeOut {
  node_id: string
  node_type: string
  label: string
  attributes: Record<string, unknown>
  first_seen: number
  last_seen: number
  event_count: number
}

export interface GraphEdgeOut {
  source: string
  target: string
  edge_type: string
  weight: number
  first_seen: number
  last_seen: number
}

export interface GraphResponse {
  investigation_id: string
  nodes: GraphNodeOut[]
  edges: GraphEdgeOut[]
  attack_paths: string[][]
  node_count: number
  edge_count: number
  max_depth: number
}

export interface EvidenceOut {
  evidence_id: string
  investigation_id: string
  tenant_id: string
  analyst_id: string
  evidence_type: string
  reference_id: string | null
  title: string
  description: string | null
  extra_data: Record<string, unknown>
  created_at: string
}

export interface NoteOut {
  note_id: string
  investigation_id: string
  tenant_id: string
  analyst_id: string
  analyst_name: string | null
  content: string
  pinned: boolean
  created_at: string
  updated_at: string
}

// ─── Hooks ────────────────────────────────────────────────────────────────────

export function useInvDetail(id: string) {
  return useQuery({
    queryKey: ['inv-detail', id],
    queryFn: async () => {
      const resp = await apiClient.get<{ data: InvestigationDetail }>(
        `/investigations/${id}`
      )
      return resp.data.data!
    },
    enabled: !!id,
    staleTime: 15_000,
    refetchInterval: 30_000,
  })
}

export function useInvTimeline(id: string, options?: { enabled?: boolean; refetchInterval?: number | false }) {
  return useQuery({
    queryKey: ['inv-detail', id, 'timeline'],
    queryFn: async () => {
      const resp = await apiClient.get<{ data: TimelineResponse }>(
        `/investigations/${id}/timeline`
      )
      return resp.data.data!
    },
    enabled: (options?.enabled ?? true) && !!id,
    staleTime: 20_000,
    refetchInterval: options?.refetchInterval,
  })
}

export function useInvGraph(id: string, options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ['inv-detail', id, 'graph'],
    queryFn: async () => {
      const resp = await apiClient.get<{ data: GraphResponse }>(
        `/investigations/${id}/graph`
      )
      return resp.data.data!
    },
    enabled: (options?.enabled ?? true) && !!id,
    staleTime: 30_000,
  })
}

export function useInvEvidence(id: string, options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ['inv-detail', id, 'evidence'],
    queryFn: async () => {
      const resp = await apiClient.get<{ data: EvidenceOut[] }>(
        `/investigations/${id}/evidence`
      )
      return resp.data.data ?? []
    },
    enabled: (options?.enabled ?? true) && !!id,
    staleTime: 30_000,
  })
}

export function useInvNotes(id: string, options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ['inv-detail', id, 'notes'],
    queryFn: async () => {
      const resp = await apiClient.get<{ data: NoteOut[]; pagination: unknown }>(
        `/investigations/${id}/notes`
      )
      return resp.data.data ?? []
    },
    enabled: (options?.enabled ?? true) && !!id,
    staleTime: 10_000,
  })
}

export function useInvUpdateStatus(id: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (status: string) =>
      apiClient.patch(`/investigations/${id}/status`, { status }),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ['inv-detail', id] }),
  })
}

export function useInvCreateNote(id: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (content: string) =>
      apiClient.post(`/investigations/${id}/notes`, { content }),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ['inv-detail', id, 'notes'] }),
  })
}

export function useRunAIAnalysis(id: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () =>
      apiClient.post<{ data: InvestigationDetail }>(`/investigations/${id}/analyze`),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ['inv-detail', id] }),
  })
}

export function useInvSetVerdict(id: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (verdict: string) =>
      apiClient.patch(`/investigations/${id}/verdict`, { verdict }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['inv-detail', id] })
    },
    onError: (err) => {
      toastError(extractApiError(err), 'Failed to set verdict')
    },
  })
}
