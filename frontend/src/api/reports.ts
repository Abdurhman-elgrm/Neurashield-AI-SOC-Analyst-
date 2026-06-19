import { apiGet } from './client'

// ─── Types ────────────────────────────────────────────────────────────────────

export type ComplianceFramework = 'soc2' | 'iso27001' | 'pci_dss'

export interface AlertSummary {
  total: number
  open: number
  acknowledged: number
  closed: number
  false_positive: number
  by_severity: Record<string, number>
  mean_time_to_acknowledge_hours: number | null
  mean_time_to_close_hours: number | null
}

export interface InvestigationSummary {
  total: number
  open: number
  closed: number
  high_confidence: number
  avg_threat_score: number | null
  behaviors_detected: string[]
}

export interface AgentSummary {
  total_agents: number
  online_agents: number
  offline_agents: number
  coverage_pct: number
}

export interface EventSummary {
  total_events: number
  by_category?: Record<string, number>
}

export interface ComplianceControl {
  control_id: string
  control_name: string
  status: 'pass' | 'partial' | 'fail' | 'not_applicable'
  evidence: string
  metric: string | null
}

export interface ComplianceReport {
  framework: string
  generated_at: string
  period_start: string
  period_end: string
  tenant_id: string
  alerts: AlertSummary
  investigations: InvestigationSummary
  agents: AgentSummary
  events: EventSummary
  controls: ComplianceControl[]
}

// ─── API ──────────────────────────────────────────────────────────────────────

export const reportsApi = {
  getCompliance: (framework: ComplianceFramework, from_days = 30): Promise<ComplianceReport> =>
    apiGet<ComplianceReport>(`/reports/compliance?framework=${framework}&from_days=${from_days}`),
}
