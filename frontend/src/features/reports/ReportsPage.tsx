import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Shield, Download, AlertTriangle, Activity, Monitor, FileText,
  CheckCircle, XCircle, MinusCircle, Plus, Loader2, RefreshCw,
  FileBarChart2, Brain, ChevronRight, Clock,
} from 'lucide-react'
import { reportsApi, type ComplianceFramework, type ComplianceControl, type GeneratedReportSummary, type ReportType } from '@/api/reports'
import { Button } from '@/components/ui/Button'
import { formatDateTime } from '@/lib/timezone'
import { extractApiError } from '@/lib/utils'

// ─── Constants ────────────────────────────────────────────────────────────────

const FRAMEWORKS: { id: ComplianceFramework; label: string; description: string; color: string }[] = [
  { id: 'soc2',     label: 'SOC 2 Type II', description: 'Trust Services Criteria', color: '#3B82F6' },
  { id: 'iso27001', label: 'ISO 27001',      description: 'Information Security',   color: '#8B5CF6' },
  { id: 'pci_dss',  label: 'PCI-DSS',        description: 'Payment Card Security',  color: '#F59E0B' },
]

const REPORT_TYPES: { id: ReportType; label: string; desc: string; icon: React.ElementType; color: string }[] = [
  { id: 'executive_summary',  label: 'Executive Summary',    desc: 'C-suite security posture overview',    icon: FileBarChart2, color: '#3B82F6' },
  { id: 'threat_report',      label: 'Threat Intelligence',  desc: 'Attack patterns & affected assets',    icon: Brain,         color: '#EF4444' },
  { id: 'compliance_summary', label: 'Compliance Summary',   desc: 'Audit evidence & control status',      icon: Shield,        color: '#10B981' },
]

const STATUS_CFG = {
  generating: { label: 'Generating…', color: '#F59E0B', icon: Loader2, spin: true },
  completed:  { label: 'Completed',   color: '#10B981', icon: CheckCircle, spin: false },
  failed:     { label: 'Failed',      color: '#EF4444', icon: XCircle, spin: false },
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function MetricCard({ label, value, sub, color, icon: Icon }: {
  label: string; value: string | number; sub?: string; color: string; icon: React.ElementType
}) {
  return (
    <div style={{ background: '#0D0D0D', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, padding: '14px 16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <div style={{ width: 28, height: 28, borderRadius: 6, background: `${color}1A`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Icon size={14} style={{ color }} />
        </div>
        <span style={{ fontSize: 10, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '1px' }}>{label}</span>
      </div>
      <div style={{ fontSize: 26, fontWeight: 800, color, fontFamily: "'Space Grotesk', sans-serif" }}>{value}</div>
      {sub && <div style={{ fontSize: 10, color: '#8B95A7', marginTop: 4 }}>{sub}</div>}
    </div>
  )
}

function ProgressBar({ label, value, max, color }: { label: string; value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
        <span style={{ fontSize: 11, color: '#B8C0CC' }}>{label}</span>
        <span style={{ fontSize: 11, color, fontWeight: 700 }}>{value} <span style={{ color: '#5C6373', fontWeight: 400 }}>/ {max}</span></span>
      </div>
      <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2 }}>
        <div style={{ height: '100%', borderRadius: 2, width: `${pct}%`, background: color, transition: 'width 400ms ease' }} />
      </div>
    </div>
  )
}

// ─── Generate Modal ───────────────────────────────────────────────────────────

function GenerateModal({ onClose, onGenerated }: { onClose: () => void; onGenerated: () => void }) {
  const [reportType, setReportType] = useState<ReportType>('executive_summary')
  const [periodDays, setPeriodDays] = useState(30)
  const [error, setError] = useState<string | null>(null)
  const qc = useQueryClient()

  const generate = useMutation({
    mutationFn: () => reportsApi.generate({ report_type: reportType, period_days: periodDays }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['generated-reports'] })
      onGenerated()
    },
    onError: (err) => setError(extractApiError(err)),
  })

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 100, background: 'rgba(0,0,0,0.75)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ width: 480, background: '#111', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: 24 }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: '#F5F7FA', marginBottom: 4, fontFamily: "'Space Grotesk', sans-serif" }}>Generate AI Report</div>
        <div style={{ fontSize: 12, color: '#5C6373', marginBottom: 20 }}>Select a report type and time period</div>

        {/* Report type selector */}
        <div style={{ display: 'grid', gap: 8, marginBottom: 16 }}>
          {REPORT_TYPES.map(rt => (
            <button
              key={rt.id}
              onClick={() => setReportType(rt.id)}
              style={{
                display: 'flex', alignItems: 'center', gap: 12, padding: '12px 14px',
                borderRadius: 8, cursor: 'pointer', textAlign: 'left',
                background: reportType === rt.id ? `${rt.color}12` : 'rgba(255,255,255,0.03)',
                border: `1px solid ${reportType === rt.id ? rt.color + '40' : 'rgba(255,255,255,0.06)'}`,
                transition: 'all 120ms',
              }}
            >
              <div style={{ width: 32, height: 32, borderRadius: 8, background: `${rt.color}1A`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                <rt.icon size={15} style={{ color: rt.color }} />
              </div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: reportType === rt.id ? '#F5F7FA' : '#8B95A7' }}>{rt.label}</div>
                <div style={{ fontSize: 11, color: '#5C6373', marginTop: 1 }}>{rt.desc}</div>
              </div>
              {reportType === rt.id && <CheckCircle size={14} style={{ color: rt.color, marginLeft: 'auto' }} />}
            </button>
          ))}
        </div>

        {/* Period */}
        <div style={{ marginBottom: 16 }}>
          <label style={{ fontSize: 11, color: '#8B95A7', display: 'block', marginBottom: 6 }}>Time Period</label>
          <select className="inp" value={periodDays} onChange={e => setPeriodDays(Number(e.target.value))}>
            <option value={7}>Last 7 days</option>
            <option value={14}>Last 14 days</option>
            <option value={30}>Last 30 days</option>
            <option value={60}>Last 60 days</option>
            <option value={90}>Last 90 days</option>
          </select>
        </div>

        {error && (
          <div style={{ padding: '8px 12px', borderRadius: 6, fontSize: 12, background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)', color: '#F87171', marginBottom: 12 }}>
            {error}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
          <Button variant="primary" size="sm" loading={generate.isPending} onClick={() => generate.mutate()}>
            <Brain size={13} /> Generate
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── Report Viewer ────────────────────────────────────────────────────────────

function ReportViewer({ reportId, onBack }: { reportId: string; onBack: () => void }) {
  const { data: report, isLoading, refetch } = useQuery({
    queryKey: ['generated-report', reportId],
    queryFn: () => reportsApi.getGenerated(reportId),
    refetchInterval: (q) => q.state.data?.status === 'generating' ? 3000 : false,
  })

  const typeInfo = REPORT_TYPES.find(t => t.id === report?.report_type) ?? REPORT_TYPES[0]

  function handleExport() {
    if (!report?.sections) return
    const content = report.sections.map(s => `## ${s.title}\n\n${s.content}`).join('\n\n---\n\n')
    const header = `# ${report.title}\nGenerated: ${formatDateTime(report.created_at)}\nPeriod: ${report.period_days} days\n\n---\n\n`
    const blob = new Blob([header + content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${report.report_type}_${new Date().toISOString().split('T')[0]}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Viewer header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, paddingBottom: 12, borderBottom: '1px solid rgba(255,255,255,0.06)', flexShrink: 0 }}>
        <button
          onClick={onBack}
          style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: '#5C6373', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
        >
          ← Reports
        </button>
        <span style={{ color: 'rgba(255,255,255,0.15)' }}>|</span>
        <div style={{ width: 28, height: 28, borderRadius: 6, background: `${typeInfo.color}1A`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <typeInfo.icon size={14} style={{ color: typeInfo.color }} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: '#F5F7FA', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {isLoading ? 'Loading…' : report?.title}
          </div>
          {report && (
            <div style={{ fontSize: 10, color: '#5C6373' }}>
              {report.period_days}-day period · Generated {formatDateTime(report.created_at)}
            </div>
          )}
        </div>
        {report?.status === 'completed' && (
          <Button variant="secondary" size="sm" onClick={handleExport}>
            <Download size={13} /> Export
          </Button>
        )}
        {report?.status === 'generating' && (
          <Button variant="ghost" size="sm" onClick={() => void refetch()}>
            <RefreshCw size={13} /> Refresh
          </Button>
        )}
      </div>

      <div style={{ flex: 1, overflowY: 'auto', paddingTop: 16 }}>
        {isLoading && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 200, gap: 10, color: '#5C6373' }}>
            <Loader2 size={20} className="animate-spin" />
            <span style={{ fontSize: 13 }}>Loading report…</span>
          </div>
        )}

        {report?.status === 'generating' && (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 200, gap: 12 }}>
            <div style={{ width: 44, height: 44, borderRadius: 12, background: 'rgba(245,158,11,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Brain size={22} style={{ color: '#F59E0B' }} className="animate-pulse" />
            </div>
            <div style={{ fontSize: 14, fontWeight: 600, color: '#F5F7FA' }}>AI is generating your report…</div>
            <div style={{ fontSize: 12, color: '#5C6373' }}>This usually takes 10–30 seconds. The page will refresh automatically.</div>
          </div>
        )}

        {report?.status === 'failed' && (
          <div style={{ padding: '12px 16px', borderRadius: 8, background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', color: '#F87171', fontSize: 12 }}>
            Report generation failed: {report.error_message || 'Unknown error'}
          </div>
        )}

        {report?.status === 'completed' && report.sections && (
          <div style={{ display: 'grid', gap: 16 }}>
            {/* Key metrics strip */}
            {report.metrics && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 10 }}>
                <MetricCard label="Total Alerts" value={report.metrics.alerts.total} sub={`${report.metrics.alerts.open} open`} color="#F97316" icon={AlertTriangle} />
                <MetricCard label="Investigations" value={report.metrics.investigations.total} sub={`${report.metrics.investigations.open} open`} color="#8B5CF6" icon={FileText} />
                <MetricCard label="Agent Coverage" value={`${report.metrics.agents.coverage_pct.toFixed(0)}%`} sub={`${report.metrics.agents.online}/${report.metrics.agents.total} online`} color="#10B981" icon={Monitor} />
                <MetricCard label="Critical Alerts" value={report.metrics.alerts.by_severity.critical ?? 0} color="#EF4444" icon={AlertTriangle} />
              </div>
            )}

            {/* Narrative sections */}
            {report.sections.map((section, i) => (
              <div key={i} style={{ background: '#0D0D0D', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10, padding: '18px 20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                  <div style={{ width: 24, height: 24, borderRadius: 6, background: `${typeInfo.color}1A`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                    <typeInfo.icon size={12} style={{ color: typeInfo.color }} />
                  </div>
                  <span style={{ fontSize: 12, fontWeight: 700, color: '#F5F7FA', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                    {section.title}
                  </span>
                </div>
                <p style={{ fontSize: 13, color: '#B8C0CC', lineHeight: 1.75, margin: 0 }}>
                  {section.content}
                </p>
              </div>
            ))}

            {/* Top techniques / hosts */}
            {report.metrics && (report.metrics.top_techniques.length > 0 || report.metrics.top_hosts.length > 0) && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                {report.metrics.top_techniques.length > 0 && (
                  <div style={{ background: '#0D0D0D', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10, padding: '16px 18px' }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '1.5px', marginBottom: 12 }}>Top MITRE Techniques</div>
                    {report.metrics.top_techniques.map(t => (
                      <div key={t.technique} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                        <span style={{ fontSize: 11, color: '#93C5FD', fontFamily: "'JetBrains Mono', monospace" }}>{t.technique}</span>
                        <span style={{ fontSize: 11, fontWeight: 700, color: '#F5F7FA', fontFamily: "'JetBrains Mono', monospace" }}>{t.count}</span>
                      </div>
                    ))}
                  </div>
                )}
                {report.metrics.top_hosts.length > 0 && (
                  <div style={{ background: '#0D0D0D', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10, padding: '16px 18px' }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '1.5px', marginBottom: 12 }}>Most Targeted Assets</div>
                    {report.metrics.top_hosts.map(h => (
                      <div key={h.host} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                        <span style={{ fontSize: 11, color: '#8B95A7', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{h.host}</span>
                        <span style={{ fontSize: 11, fontWeight: 700, color: '#F5F7FA', fontFamily: "'JetBrains Mono', monospace', marginLeft: 8" }}>{h.count}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Report list row ──────────────────────────────────────────────────────────

function ReportRow({ report, onClick }: { report: GeneratedReportSummary; onClick: () => void }) {
  const [hovered, setHovered] = useState(false)
  const status = STATUS_CFG[report.status] ?? STATUS_CFG.generating
  const typeInfo = REPORT_TYPES.find(t => t.id === report.report_type) ?? REPORT_TYPES[0]
  const StatusIcon = status.icon

  return (
    <tr
      onClick={report.status === 'completed' ? onClick : undefined}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        borderBottom: '1px solid rgba(255,255,255,0.04)',
        background: hovered && report.status === 'completed' ? 'rgba(255,255,255,0.025)' : 'transparent',
        cursor: report.status === 'completed' ? 'pointer' : 'default',
        transition: 'background 120ms',
      }}
    >
      <td style={{ padding: '10px 12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 28, height: 28, borderRadius: 6, background: `${typeInfo.color}1A`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <typeInfo.icon size={13} style={{ color: typeInfo.color }} />
          </div>
          <div>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#F5F7FA' }}>{report.title}</div>
            <div style={{ fontSize: 10, color: '#5C6373', marginTop: 1 }}>{typeInfo.label} · {report.period_days}-day window</div>
          </div>
        </div>
      </td>
      <td style={{ padding: '10px 12px' }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10, fontWeight: 700, color: status.color, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          <StatusIcon size={10} style={{ animation: status.spin ? 'spin 1s linear infinite' : 'none' }} />
          {status.label}
        </span>
      </td>
      <td style={{ padding: '10px 12px' }}>
        <span style={{ fontSize: 11, color: '#5C6373', display: 'flex', alignItems: 'center', gap: 4 }}>
          <Clock size={10} />
          {formatDateTime(report.created_at)}
        </span>
      </td>
      <td style={{ padding: '10px 12px', opacity: hovered && report.status === 'completed' ? 1 : 0, transition: 'opacity 120ms' }}>
        <ChevronRight size={14} style={{ color: '#5C6373' }} />
      </td>
    </tr>
  )
}

// ─── Compliance tab (existing) ────────────────────────────────────────────────

function ComplianceTab() {
  const [framework, setFramework] = useState<ComplianceFramework>('soc2')
  const [fromDays, setFromDays] = useState(30)
  const { data: report, isLoading, error } = useQuery({
    queryKey: ['compliance-report', framework, fromDays],
    queryFn: () => reportsApi.getCompliance(framework, fromDays),
    staleTime: 5 * 60 * 1000,
  })
  const activeFramework = FRAMEWORKS.find(f => f.id === framework)!
  const severityColors: Record<string, string> = { critical: '#EF4444', high: '#F97316', medium: '#F59E0B', low: '#3B82F6' }

  function handleExport() {
    if (!report) return
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `neurashield_${framework}_${new Date().toISOString().split('T')[0]}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <>
      <div style={{ display: 'flex', gap: 10, padding: '10px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', flexShrink: 0 }}>
        {FRAMEWORKS.map(fw => (
          <button key={fw.id} onClick={() => setFramework(fw.id)} style={{
            padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: 'pointer',
            background: framework === fw.id ? `${fw.color}1A` : 'rgba(255,255,255,0.04)',
            border: `1px solid ${framework === fw.id ? fw.color + '4D' : 'rgba(255,255,255,0.06)'}`,
            color: framework === fw.id ? fw.color : '#8B95A7', transition: 'all 120ms',
          }}>{fw.label}</button>
        ))}
        <div style={{ flex: 1 }} />
        <select className="inp" style={{ width: 120 }} value={fromDays} onChange={e => setFromDays(Number(e.target.value))}>
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
          <option value={60}>Last 60 days</option>
          <option value={90}>Last 90 days</option>
        </select>
        <Button variant="secondary" size="sm" onClick={handleExport} disabled={!report}>
          <Download size={13} /> Export JSON
        </Button>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', paddingTop: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
          <div style={{ width: 32, height: 32, borderRadius: 8, background: `${activeFramework.color}1A`, border: `1px solid ${activeFramework.color}33`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Shield size={16} style={{ color: activeFramework.color }} />
          </div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#F5F7FA' }}>{activeFramework.label}</div>
            <div style={{ fontSize: 11, color: '#5C6373' }}>
              {activeFramework.description} · {fromDays}-day evidence window
              {report?.generated_at && ` · Generated ${formatDateTime(report.generated_at)}`}
            </div>
          </div>
        </div>
        {isLoading && <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 10 }}>{Array.from({length: 8}).map((_,i) => <div key={i} className="skel" style={{ height: 90, borderRadius: 8 }} />)}</div>}
        {error && <div style={{ padding: '12px 16px', borderRadius: 8, background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)', color: '#F87171', fontSize: 12 }}>Failed to load compliance report.</div>}
        {report && (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 10, marginBottom: 16 }}>
              <MetricCard label="Total Alerts"    value={report.alerts.total}         sub={`${report.alerts.open} open`}                      color="#F97316" icon={AlertTriangle} />
              <MetricCard label="Investigations"  value={report.investigations.total} sub={`${report.investigations.open} open`}               color="#8B5CF6" icon={FileText} />
              <MetricCard label="Agent Coverage"  value={`${report.agents.coverage_pct.toFixed(0)}%`} sub={`${report.agents.online_agents}/${report.agents.total_agents} online`} color="#10B981" icon={Monitor} />
              <MetricCard label="Events Collected" value={report.events.total_events.toLocaleString()} color="#3B82F6" icon={Activity} />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 16 }}>
              <div style={{ background: '#0D0D0D', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, padding: '16px 18px' }}>
                <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 14 }}>Alert Status Breakdown</div>
                <ProgressBar label="Open"           value={report.alerts.open}           max={report.alerts.total} color="#EF4444" />
                <ProgressBar label="Acknowledged"   value={report.alerts.acknowledged}   max={report.alerts.total} color="#F59E0B" />
                <ProgressBar label="Closed"         value={report.alerts.closed}         max={report.alerts.total} color="#10B981" />
                <ProgressBar label="False Positive" value={report.alerts.false_positive} max={report.alerts.total} color="#5C6373" />
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <div style={{ background: '#0D0D0D', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, padding: '16px 18px', flex: 1 }}>
                  <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 14 }}>Alerts by Severity</div>
                  {Object.entries(report.alerts.by_severity ?? {}).map(([sev, count]) => (
                    <ProgressBar key={sev} label={sev.charAt(0).toUpperCase() + sev.slice(1)} value={count} max={report.alerts.total} color={severityColors[sev] ?? '#8B95A7'} />
                  ))}
                </div>
              </div>
            </div>
            {report.controls?.length > 0 && (
              <div style={{ background: '#0D0D0D', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, padding: '16px 18px', marginBottom: 16 }}>
                <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 14 }}>
                  Framework Controls ({report.controls.filter((c: ComplianceControl) => c.status === 'pass').length}/{report.controls.length} passing)
                </div>
                <div style={{ display: 'grid', gap: 8 }}>
                  {report.controls.map((ctrl: ComplianceControl) => {
                    const sc = ctrl.status === 'pass' ? { icon: CheckCircle, color: '#10B981' } : ctrl.status === 'fail' ? { icon: XCircle, color: '#EF4444' } : { icon: MinusCircle, color: '#F59E0B' }
                    const Icon = sc.icon
                    return (
                      <div key={ctrl.control_id} style={{ display: 'flex', alignItems: 'flex-start', gap: 12, padding: '10px 12px', borderRadius: 6, background: 'rgba(255,255,255,0.02)', border: `1px solid ${sc.color}22` }}>
                        <Icon size={14} style={{ color: sc.color, flexShrink: 0, marginTop: 1 }} />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                            <span style={{ fontSize: 10, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", color: '#8B95A7' }}>{ctrl.control_id}</span>
                            <span style={{ fontSize: 12, fontWeight: 600, color: '#F5F7FA' }}>{ctrl.control_name}</span>
                            {ctrl.metric && <span style={{ marginLeft: 'auto', fontSize: 11, fontWeight: 700, color: sc.color, fontFamily: "'JetBrains Mono', monospace" }}>{ctrl.metric}</span>}
                          </div>
                          <div style={{ fontSize: 11, color: '#8B95A7', lineHeight: 1.5 }}>{ctrl.evidence}</div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export function ReportsPage() {
  const [tab, setTab] = useState<'generated' | 'compliance'>('generated')
  const [showGenerate, setShowGenerate] = useState(false)
  const [viewingId, setViewingId] = useState<string | null>(null)

  const { data: reportsData, isLoading } = useQuery({
    queryKey: ['generated-reports'],
    queryFn: () => reportsApi.listGenerated(),
    refetchInterval: 15_000,
    enabled: tab === 'generated' && !viewingId,
  })
  const reports = reportsData ?? []

  const tabStyle = (active: boolean, color = '#3B82F6') => ({
    padding: '7px 16px', borderRadius: 6, fontSize: 12, fontWeight: 600,
    cursor: 'pointer', border: 'none', transition: 'all 120ms',
    background: active ? `${color}18` : 'transparent',
    color: active ? color : '#5C6373',
    borderBottom: active ? `2px solid ${color}` : '2px solid transparent',
  })

  if (viewingId) {
    return (
      <div className="page-in" style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 50px - 40px)', overflow: 'hidden' }}>
        <ReportViewer reportId={viewingId} onBack={() => setViewingId(null)} />
      </div>
    )
  }

  return (
    <div className="page-in" style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 50px - 40px)', overflow: 'hidden' }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', paddingBottom: 12, borderBottom: '1px solid rgba(255,255,255,0.06)', flexShrink: 0 }}>
        <div>
          <h1 style={{ fontSize: 17, fontWeight: 800, color: '#F5F7FA', fontFamily: "'Space Grotesk', sans-serif" }}>Reports</h1>
          <p style={{ fontSize: 12, color: '#5C6373', marginTop: 3 }}>AI-generated security reports & compliance evidence</p>
        </div>
        {tab === 'generated' && (
          <Button variant="primary" size="sm" onClick={() => setShowGenerate(true)}>
            <Plus size={13} /> Generate Report
          </Button>
        )}
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 2, padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', flexShrink: 0 }}>
        <button style={tabStyle(tab === 'generated')} onClick={() => setTab('generated')}>
          <Brain size={12} style={{ display: 'inline', marginRight: 5 }} />
          AI Reports
          {reports.filter(r => r.status === 'generating').length > 0 && (
            <span style={{ marginLeft: 6, padding: '1px 5px', borderRadius: 10, fontSize: 9, background: 'rgba(245,158,11,0.2)', color: '#F59E0B', fontWeight: 700 }}>
              {reports.filter(r => r.status === 'generating').length}
            </span>
          )}
        </button>
        <button style={tabStyle(tab === 'compliance', '#8B5CF6')} onClick={() => setTab('compliance')}>
          <Shield size={12} style={{ display: 'inline', marginRight: 5 }} />
          Compliance Live
        </button>
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflowY: tab === 'compliance' ? 'hidden' : 'auto', display: 'flex', flexDirection: 'column', paddingTop: tab === 'generated' ? 12 : 0 }}>
        {tab === 'generated' && (
          <>
            {isLoading && (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 200, gap: 8, color: '#5C6373' }}>
                <Loader2 size={18} className="animate-spin" />
                <span style={{ fontSize: 13 }}>Loading reports…</span>
              </div>
            )}

            {!isLoading && reports.length === 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 240, gap: 12 }}>
                <div style={{ width: 52, height: 52, borderRadius: 14, background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <Brain size={24} style={{ color: '#3B82F6' }} />
                </div>
                <div style={{ fontSize: 14, fontWeight: 600, color: '#5C6373' }}>No reports generated yet</div>
                <div style={{ fontSize: 12, color: '#3A4150', textAlign: 'center', maxWidth: 320 }}>
                  Generate AI-powered security reports with narrative analysis, key findings, and actionable recommendations.
                </div>
                <Button variant="primary" size="sm" onClick={() => setShowGenerate(true)}>
                  <Plus size={13} /> Generate First Report
                </Button>
              </div>
            )}

            {!isLoading && reports.length > 0 && (
              <table className="data-table">
                <thead style={{ position: 'sticky', top: 0, background: '#050505', zIndex: 10 }}>
                  <tr>
                    <th>REPORT</th>
                    <th style={{ width: 120 }}>STATUS</th>
                    <th style={{ width: 160 }}>GENERATED</th>
                    <th style={{ width: 40 }}></th>
                  </tr>
                </thead>
                <tbody>
                  {reports.map(r => (
                    <ReportRow key={r.id} report={r} onClick={() => setViewingId(r.id)} />
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}

        {tab === 'compliance' && <ComplianceTab />}
      </div>

      {showGenerate && (
        <GenerateModal
          onClose={() => setShowGenerate(false)}
          onGenerated={() => {
            setShowGenerate(false)
            setTab('generated')
          }}
        />
      )}
    </div>
  )
}
