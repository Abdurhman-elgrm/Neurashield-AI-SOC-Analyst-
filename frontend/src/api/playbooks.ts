import { apiGet, apiPost, apiPatch, apiDelete } from './client'

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PlaybookTemplate {
  id: string
  name: string
  tactic: string | null
  technique: string | null
  category: string
  is_system: boolean
  version: number
  enabled: boolean
  created_at: string
}

export interface PlaybookStep {
  id: string
  playbook_id: string
  step_order: number
  category: string
  title: string
  description: string
  status: 'pending' | 'in_progress' | 'completed' | 'skipped' | 'failed'
  action_type: string | null
  completed_at: string | null
  notes: string | null
  result: string | null
}

export interface Playbook {
  id: string
  tenant_id: string
  template_id: string | null
  alert_id: string | null
  investigation_id: string | null
  title: string
  severity: string
  source_host: string | null
  status: 'draft' | 'in_progress' | 'completed' | 'failed' | 'cancelled'
  generated_by: 'llm' | 'template' | 'manual' | 'fallback'
  created_by_id: string | null
  variables: Record<string, string>
  created_at: string
  updated_at: string
  steps?: PlaybookStep[]
}

export interface PlaybookRun {
  id: string
  playbook_id: string
  mode: string
  status: string
  steps_completed: number
  steps_total: number
  started_at: string
  completed_at: string | null
}

// ─── API ──────────────────────────────────────────────────────────────────────

export const playbooksApi = {
  listTemplates: (): Promise<PlaybookTemplate[]> =>
    apiGet<PlaybookTemplate[]>('/playbooks/templates'),

  list: (params?: { status?: string; severity?: string; investigation_id?: string }): Promise<Playbook[]> => {
    const qs = params
      ? '?' + new URLSearchParams(Object.entries(params).filter(([, v]) => v != null) as [string, string][]).toString()
      : ''
    return apiGet<Playbook[]>(`/playbooks${qs}`)
  },

  get: (id: string): Promise<Playbook> =>
    apiGet<Playbook>(`/playbooks/${id}`),

  generate: (payload: {
    alert_id?: string
    investigation_id?: string
    incident_id?: string
    tactic?: string
    technique?: string
    severity?: string
    source_host?: string
    variables?: Record<string, string>
  }): Promise<Playbook> =>
    apiPost<Playbook>('/playbooks/generate', payload),

  execute: (id: string, mode?: 'auto' | 'manual'): Promise<PlaybookRun> =>
    apiPost<PlaybookRun>(`/playbooks/${id}/execute`, { mode: mode ?? 'manual' }),

  completeStep: (
    playbookId: string,
    stepId: string,
    payload: { notes?: string; result?: string }
  ): Promise<PlaybookStep> =>
    apiPatch<PlaybookStep>(`/playbooks/${playbookId}/steps/${stepId}`, payload),

  delete: (id: string): Promise<void> =>
    apiDelete(`/playbooks/${id}`),
}
