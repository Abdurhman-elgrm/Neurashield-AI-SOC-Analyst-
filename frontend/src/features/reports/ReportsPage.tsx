import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Shield, Download, AlertTriangle, Activity, Monitor, FileText, CheckCircle, XCircle, MinusCircle } from 'lucide-react'
import { reportsApi, type ComplianceFramework, type ComplianceControl } from '@/api/reports'
import { Button } from '@/components/ui/Button'
import { formatDateTime } from '@/lib/timezone'

// ─── Framework info ───────────────────────────────────────────────────────────

const FRAMEWORKS: { id: ComplianceFramework; label: string; description: string; color: string }[] = [
  { id: 'soc2',     label: 'SOC 2 Type II', description: 'Trust Services Criteria', color: '#3B82F6' },
  { id: 'iso27001', label: 'ISO 27001',      description: 'Information Security',   color: '#8B5CF6' },
  { id: 'pci_dss',  label: 'PCI-DSS',        description: 'Payment Card Security',  color: '#F59E0B' },
]

// ─── Metric card ──────────────────────────────────────────────────────────────

function MetricCard({ label, value, sub, color, icon: Icon }: {
  label: string
  value: string | number
  sub?: string
  color: string
  icon: React.ElementType
}) {
  return (
    <div style={{
      background: '#0D0D0D', border: '1px solid rgba(255,255,255,0.06)',
      borderRadius: 8, padding: '14px 16px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <div style={{
          width: 28, height: 28, borderRadius: 6,
          background: `${color}1A`, display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Icon size={14} style={{ color }} />
        </div>
        <span style={{ fontSize: 10, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '1px' }}>
          {label}
        </span>
      </div>
      <div style={{ fontSize: 26, fontWeight: 800, color, fontFamily: "'Space Grotesk', sans-serif" }}>
        {value}
      </div>
      {sub && <div style={{ fontSize: 10, color: '#8B95A7', marginTop: 4 }}>{sub}</div>}
    </div>
  )
}

// ─── Progress bar ─────────────────────────────────────────────────────────────

function ProgressBar({ label, value, max, color }: { label: string; value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
        <span style={{ fontSize: 11, color: '#B8C0CC' }}>{label}</span>
        <span style={{ fontSize: 11, color, fontWeight: 700 }}>
          {value} <span style={{ color: '#5C6373', fontWeight: 400 }}>/ {max}</span>
        </span>
      </div>
      <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2 }}>
        <div style={{
          height: '100%', borderRadius: 2,
          width: `${pct}%`, background: color,
          transition: 'width 400ms ease',
        }} />
      </div>
    </div>
  )
}

// ─── ReportsPage ──────────────────────────────────────────────────────────────

export function ReportsPage() {
  const [framework, setFramework] = useState<ComplianceFramework>('soc2')
  const [fromDays, setFromDays] = useState(30)

  const { data: report, isLoading, error } = useQuery({
    queryKey: ['compliance-report', framework, fromDays],
    queryFn: () => reportsApi.getCompliance(framework, fromDays),
    staleTime: 5 * 60 * 1000,
  })

  const activeFramework = FRAMEWORKS.find(f => f.id === framework)!

  function handleExport() {
    if (!report) return
    const json = JSON.stringify(report, null, 2)
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `neurashield_${framework}_${new Date().toISOString().split('T')[0]}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const severityColors: Record<string, string> = {
    critical: '#EF4444',
    high:     '#F97316',
    medium:   '#F59E0B',
    low:      '#3B82F6',
    info:     '#8B95A7',
  }

  return (
    <div className="page-in" style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 50px - 40px)', overflow: 'hidden' }}>

      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'flex-start',
        justifyContent: 'space-between', paddingBottom: 12,
        borderBottom: '1px solid rgba(255,255,255,0.06)', flexShrink: 0,
      }}>
        <div>
          <h1 style={{ fontSize: 17, fontWeight: 800, color: '#F5F7FA', fontFamily: "'Space Grotesk', sans-serif" }}>
            Compliance Reports
          </h1>
          <p style={{ fontSize: 12, color: '#5C6373', marginTop: 3 }}>
            Security posture evidence for compliance frameworks
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <Button variant="secondary" size="sm" onClick={handleExport} disabled={!report}>
            <Download size={13} /> Export JSON
          </Button>
        </div>
      </div>

      {/* Framework selector + time range */}
      <div style={{
        display: 'flex', gap: 10, padding: '10px 0',
        borderBottom: '1px solid rgba(255,255,255,0.04)', flexShrink: 0,
      }}>
        {FRAMEWORKS.map(fw => (
          <button
            key={fw.id}
            onClick={() => setFramework(fw.id)}
            style={{
              padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600,
              background: framework === fw.id ? `${fw.color}1A` : 'rgba(255,255,255,0.04)',
              border: `1px solid ${framework === fw.id ? fw.color + '4D' : 'rgba(255,255,255,0.06)'}`,
              color: framework === fw.id ? fw.color : '#8B95A7',
              cursor: 'pointer', transition: 'all 120ms',
            }}
          >
            {fw.label}
          </button>
        ))}

        <div style={{ flex: 1 }} />

        <select
          className="inp"
          style={{ width: 120 }}
          value={fromDays}
          onChange={e => setFromDays(Number(e.target.value))}
        >
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
          <option value={60}>Last 60 days</option>
          <option value={90}>Last 90 days</option>
        </select>
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflowY: 'auto', paddingTop: 14 }}>

        {/* Framework label */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14,
        }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8,
            background: `${activeFramework.color}1A`,
            border: `1px solid ${activeFramework.color}33`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Shield size={16} style={{ color: activeFramework.color }} />
          </div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#F5F7FA' }}>
              {activeFramework.label}
            </div>
            <div style={{ fontSize: 11, color: '#5C6373' }}>
              {activeFramework.description} · {fromDays}-day evidence window
              {report?.generated_at && ` · Generated ${formatDateTime(report.generated_at)}`}
            </div>
          </div>
        </div>

        {isLoading && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 16 }}>
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="skel" style={{ height: 90, borderRadius: 8, display: 'block' }} />
            ))}
          </div>
        )}

        {error && (
          <div style={{
            padding: '12px 16px', borderRadius: 8, marginBottom: 16,
            background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)',
            color: '#F87171', fontSize: 12,
          }}>
            Failed to load compliance report. Please try again.
          </div>
        )}

        {report && (
          <>
            {/* Top metric cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 16 }}>
              <MetricCard
                label="Total Alerts"
                value={report.alerts.total}
                sub={`${report.alerts.open} open`}
                color="#F97316"
                icon={AlertTriangle}
              />
              <MetricCard
                label="Investigations"
                value={report.investigations.total}
                sub={`${report.investigations.open} open`}
                color="#8B5CF6"
                icon={FileText}
              />
              <MetricCard
                label="Agent Coverage"
                value={`${report.agents.coverage_pct.toFixed(0)}%`}
                sub={`${report.agents.online_agents} / ${report.agents.total_agents} online`}
                color="#10B981"
                icon={Monitor}
              />
              <MetricCard
                label="Events Collected"
                value={report.events.total_events.toLocaleString()}
                color="#3B82F6"
                icon={Activity}
              />
            </div>

            {/* Detail panels */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 16 }}>

              {/* Alert breakdown */}
              <div style={{
                background: '#0D0D0D', border: '1px solid rgba(255,255,255,0.06)',
                borderRadius: 8, padding: '16px 18px',
              }}>
                <div style={{
                  fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
                  letterSpacing: '1.5px', color: '#5C6373', marginBottom: 14,
                }}>
                  Alert Status Breakdown
                </div>
                <ProgressBar label="Open"           value={report.alerts.open}          max={report.alerts.total} color="#EF4444" />
                <ProgressBar label="Acknowledged"   value={report.alerts.acknowledged}  max={report.alerts.total} color="#F59E0B" />
                <ProgressBar label="Closed"         value={report.alerts.closed}        max={report.alerts.total} color="#10B981" />
                <ProgressBar label="False Positive" value={report.alerts.false_positive} max={report.alerts.total} color="#5C6373" />

                {(report.alerts.mean_time_to_acknowledge_hours != null || report.alerts.mean_time_to_close_hours != null) && (
                  <div style={{
                    marginTop: 14, paddingTop: 12,
                    borderTop: '1px solid rgba(255,255,255,0.05)',
                    display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10,
                  }}>
                    {report.alerts.mean_time_to_acknowledge_hours != null && (
                      <div>
                        <div style={{ fontSize: 9, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 3 }}>MTTA</div>
                        <div style={{ fontSize: 16, fontWeight: 700, color: '#F5F7FA', fontFamily: "'Space Grotesk', sans-serif" }}>
                          {report.alerts.mean_time_to_acknowledge_hours.toFixed(1)}h
                        </div>
                      </div>
                    )}
                    {report.alerts.mean_time_to_close_hours != null && (
                      <div>
                        <div style={{ fontSize: 9, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 3 }}>MTTC</div>
                        <div style={{ fontSize: 16, fontWeight: 700, color: '#F5F7FA', fontFamily: "'Space Grotesk', sans-serif" }}>
                          {report.alerts.mean_time_to_close_hours.toFixed(1)}h
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Alert severity + investigations */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {/* By severity */}
                {Object.keys(report.alerts.by_severity ?? {}).length > 0 && (
                  <div style={{
                    background: '#0D0D0D', border: '1px solid rgba(255,255,255,0.06)',
                    borderRadius: 8, padding: '16px 18px', flex: 1,
                  }}>
                    <div style={{
                      fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
                      letterSpacing: '1.5px', color: '#5C6373', marginBottom: 14,
                    }}>
                      Alerts by Severity
                    </div>
                    {Object.entries(report.alerts.by_severity).map(([sev, count]) => (
                      <ProgressBar
                        key={sev}
                        label={sev.charAt(0).toUpperCase() + sev.slice(1)}
                        value={count}
                        max={report.alerts.total}
                        color={severityColors[sev] ?? '#8B95A7'}
                      />
                    ))}
                  </div>
                )}

                {/* Investigations */}
                <div style={{
                  background: '#0D0D0D', border: '1px solid rgba(255,255,255,0.06)',
                  borderRadius: 8, padding: '16px 18px', flex: 1,
                }}>
                  <div style={{
                    fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
                    letterSpacing: '1.5px', color: '#5C6373', marginBottom: 14,
                  }}>
                    Investigation Summary
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
                    {[
                      { label: 'Total', value: report.investigations.total },
                      { label: 'Open', value: report.investigations.open },
                      { label: 'High Conf.', value: report.investigations.high_confidence },
                    ].map(({ label, value }) => (
                      <div key={label} style={{
                        padding: '8px 10px', borderRadius: 6,
                        background: 'rgba(255,255,255,0.03)',
                      }}>
                        <div style={{ fontSize: 16, fontWeight: 700, color: '#F5F7FA', fontFamily: "'Space Grotesk', sans-serif" }}>
                          {value}
                        </div>
                        <div style={{ fontSize: 9, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '1px', marginTop: 2 }}>
                          {label}
                        </div>
                      </div>
                    ))}
                  </div>
                  {report.investigations.avg_threat_score != null && (
                    <div style={{ marginTop: 10 }}>
                      <div style={{ fontSize: 10, color: '#8B95A7', marginBottom: 5 }}>Average Threat Score</div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div style={{ flex: 1, height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2 }}>
                          <div style={{
                            height: '100%', borderRadius: 2,
                            width: `${Math.min(100, report.investigations.avg_threat_score)}%`,
                            background: report.investigations.avg_threat_score >= 75 ? '#EF4444' :
                                         report.investigations.avg_threat_score >= 50 ? '#F59E0B' : '#3B82F6',
                            transition: 'width 400ms ease',
                          }} />
                        </div>
                        <span style={{ fontSize: 12, fontWeight: 700, color: '#F5F7FA' }}>
                          {report.investigations.avg_threat_score.toFixed(0)}/100
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Compliance controls */}
            {report.controls?.length > 0 && (
              <div style={{
                background: '#0D0D0D', border: '1px solid rgba(255,255,255,0.06)',
                borderRadius: 8, padding: '16px 18px', marginBottom: 16,
              }}>
                <div style={{
                  fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
                  letterSpacing: '1.5px', color: '#5C6373', marginBottom: 14,
                }}>
                  Framework Controls ({report.controls.filter(c => c.status === 'pass').length}/{report.controls.length} passing)
                </div>
                <div style={{ display: 'grid', gap: 8 }}>
                  {report.controls.map((ctrl: ComplianceControl) => {
                    const statusCfg =
                      ctrl.status === 'pass'           ? { icon: CheckCircle,  color: '#10B981' } :
                      ctrl.status === 'fail'           ? { icon: XCircle,      color: '#EF4444' } :
                      ctrl.status === 'not_applicable' ? { icon: MinusCircle,  color: '#5C6373' } :
                                                         { icon: MinusCircle,  color: '#F59E0B' }
                    const Icon = statusCfg.icon
                    return (
                      <div key={ctrl.control_id} style={{
                        display: 'flex', alignItems: 'flex-start', gap: 12,
                        padding: '10px 12px', borderRadius: 6,
                        background: 'rgba(255,255,255,0.02)',
                        border: `1px solid ${statusCfg.color}22`,
                      }}>
                        <Icon size={14} style={{ color: statusCfg.color, flexShrink: 0, marginTop: 1 }} />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                            <span style={{
                              fontSize: 10, fontWeight: 700,
                              fontFamily: "'JetBrains Mono', monospace",
                              color: '#8B95A7',
                            }}>
                              {ctrl.control_id}
                            </span>
                            <span style={{ fontSize: 12, fontWeight: 600, color: '#F5F7FA' }}>
                              {ctrl.control_name}
                            </span>
                            {ctrl.metric && (
                              <span style={{
                                marginLeft: 'auto', fontSize: 11, fontWeight: 700,
                                color: statusCfg.color,
                                fontFamily: "'JetBrains Mono', monospace",
                              }}>
                                {ctrl.metric}
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: 11, color: '#8B95A7', lineHeight: 1.5 }}>
                            {ctrl.evidence}
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}

            {/* Behaviors detected */}
            {report.investigations.behaviors_detected?.length > 0 && (
              <div style={{
                background: '#0D0D0D', border: '1px solid rgba(255,255,255,0.06)',
                borderRadius: 8, padding: '16px 18px', marginBottom: 16,
              }}>
                <div style={{
                  fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
                  letterSpacing: '1.5px', color: '#5C6373', marginBottom: 12,
                }}>
                  Detected Behaviors ({report.investigations.behaviors_detected.length})
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {report.investigations.behaviors_detected.map(b => (
                    <span key={b} style={{
                      padding: '3px 9px', borderRadius: 4,
                      fontSize: 10, fontWeight: 500,
                      background: 'rgba(255,255,255,0.05)',
                      border: '1px solid rgba(255,255,255,0.08)',
                      color: '#B8C0CC',
                      fontFamily: "'JetBrains Mono', monospace",
                    }}>
                      {b}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
