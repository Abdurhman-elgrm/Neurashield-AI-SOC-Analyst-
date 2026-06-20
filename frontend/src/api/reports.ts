import { apiGet, apiPost } from './client'

// ─── Compliance types ─────────────────────────────────────────────────────────

export type ComplianceFramework = 'soc2' | 'iso27001' | 'pci_dss'
export type ReportType = 'executive_summary' | 'threat_report' | 'compliance_summary'

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

// ─── Generated report types ───────────────────────────────────────────────────

export interface ReportSection {
  title: string
  content: string
}

export interface ReportMetrics {
  alerts: {
    total: number
    open: number
    closed: number
    false_positive: number
    by_severity: Record<string, number>
    mtta_hours: number | null
    mttc_hours: number | null
  }
  investigations: { total: number; open: number; high_confidence: number; avg_threat_score: number | null }
  agents: { total: number; online: number; coverage_pct: number }
  top_techniques: { technique: string; count: number }[]
  top_hosts: { host: string; count: number }[]
}

export interface GeneratedReportSummary {
  id: string
  report_type: ReportType
  title: string
  status: 'generating' | 'completed' | 'failed'
  period_days: number
  period_start: string
  period_end: string
  created_at: string
}

export interface GeneratedReportDetail extends GeneratedReportSummary {
  sections: ReportSection[] | null
  metrics: ReportMetrics | null
  error_message: string | null
}

// ─── Auto config types ────────────────────────────────────────────────────────

export interface AutoPlaybookConfig {
  enabled: boolean
  min_severity: 'critical' | 'high' | 'medium' | 'low'
}

// ─── API ──────────────────────────────────────────────────────────────────────

export const reportsApi = {
  getCompliance: (framework: ComplianceFramework, from_days = 30): Promise<ComplianceReport> =>
    apiGet<ComplianceReport>(`/reports/compliance?framework=${framework}&from_days=${from_days}`),

  generate: (payload: { report_type: ReportType; period_days: number }): Promise<GeneratedReportSummary> =>
    apiPost<GeneratedReportSummary>('/reports/generate', payload),

  listGenerated: (page = 1): Promise<GeneratedReportSummary[]> =>
    apiGet<GeneratedReportSummary[]>(`/reports/generated?page=${page}&limit=20`),

  getGenerated: (id: string): Promise<GeneratedReportDetail> =>
    apiGet<GeneratedReportDetail>(`/reports/generated/${id}`),
}

export const playbookAutoApi = {
  getConfig: (): Promise<AutoPlaybookConfig> =>
    apiGet<AutoPlaybookConfig>('/playbooks/auto-config'),

  updateConfig: (payload: AutoPlaybookConfig): Promise<AutoPlaybookConfig> =>
    apiPost<AutoPlaybookConfig>('/playbooks/auto-config', payload),
}
