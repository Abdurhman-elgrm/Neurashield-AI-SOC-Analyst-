import { useState, useEffect } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { BookOpen, Plus, ChevronRight, Zap, Clock, CheckCircle, XCircle, X, Bot, Search } from 'lucide-react'
import { playbooksApi, type Playbook } from '@/api/playbooks'
import { Button } from '@/components/ui/Button'
import { extractApiError } from '@/lib/utils'
import { formatRelativeTime } from '@/lib/utils'

// ─── Severity badge ───────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const cfg =
    severity === 'critical' ? { color: '#EF4444', bg: 'rgba(239,68,68,0.1)' } :
    severity === 'high'     ? { color: '#F97316', bg: 'rgba(249,115,22,0.1)' } :
    severity === 'medium'   ? { color: '#F59E0B', bg: 'rgba(245,158,11,0.1)' } :
                              { color: '#3B82F6', bg: 'rgba(59,130,246,0.1)' }
  return (
    <span style={{
      padding: '2px 7px', borderRadius: 4,
      fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
      fontFamily: "'JetBrains Mono', monospace",
      color: cfg.color, background: cfg.bg,
    }}>
      {severity}
    </span>
  )
}

// ─── Status badge ─────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const cfg =
    status === 'completed'   ? { color: '#10B981', bg: 'rgba(16,185,129,0.1)',  icon: CheckCircle } :
    status === 'in_progress' ? { color: '#3B82F6', bg: 'rgba(59,130,246,0.1)', icon: Clock } :
    status === 'failed'      ? { color: '#EF4444', bg: 'rgba(239,68,68,0.1)',  icon: XCircle } :
    status === 'cancelled'   ? { color: '#5C6373', bg: 'rgba(255,255,255,0.05)', icon: XCircle } :
                               { color: '#8B95A7', bg: 'rgba(255,255,255,0.05)', icon: Clock }
  const Icon = cfg.icon
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 7px', borderRadius: 4,
      fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
      fontFamily: "'JetBrains Mono', monospace",
      color: cfg.color, background: cfg.bg,
    }}>
      <Icon size={9} />
      {status.replace('_', ' ')}
    </span>
  )
}

// ─── MITRE lookup tables (mirrors backend) ───────────────────────────────────

const TECHNIQUE_NAMES: Record<string, string> = {
  T1190: 'Exploit Public-Facing Application', T1133: 'External Remote Services',
  T1566: 'Phishing', T1078: 'Valid Accounts', T1091: 'Replication Through Removable Media',
  T1195: 'Supply Chain Compromise', T1199: 'Trusted Relationship',
  T1059: 'Command and Scripting Interpreter', T1047: 'Windows Management Instrumentation',
  T1053: 'Scheduled Task/Job', T1106: 'Native API', T1204: 'User Execution',
  T1098: 'Account Manipulation', T1136: 'Create Account', T1547: 'Boot or Logon Autostart Execution',
  T1574: 'Hijack Execution Flow', T1055: 'Process Injection', T1068: 'Exploitation for Privilege Escalation',
  T1134: 'Access Token Manipulation', T1548: 'Abuse Elevation Control Mechanism',
  T1027: 'Obfuscated Files or Information', T1036: 'Masquerading', T1070: 'Indicator Removal',
  T1112: 'Modify Registry', T1218: 'System Binary Proxy Execution', T1562: 'Impair Defenses',
  T1003: 'OS Credential Dumping', T1040: 'Network Sniffing', T1110: 'Brute Force',
  T1539: 'Steal Web Session Cookie', T1555: 'Credentials from Password Stores',
  T1558: 'Steal or Forge Kerberos Tickets', T1016: 'System Network Configuration Discovery',
  T1018: 'Remote System Discovery', T1046: 'Network Service Discovery', T1057: 'Process Discovery',
  T1082: 'System Information Discovery', T1083: 'File and Directory Discovery',
  T1087: 'Account Discovery', T1021: 'Remote Services', T1072: 'Software Deployment Tools',
  T1080: 'Taint Shared Content', T1550: 'Use Alternate Authentication Material',
  T1005: 'Data from Local System', T1074: 'Data Staged', T1114: 'Email Collection',
  T1560: 'Archive Collected Data', T1071: 'Application Layer Protocol',
  T1095: 'Non-Application Layer Protocol', T1105: 'Ingress Tool Transfer',
  T1571: 'Non-Standard Port', T1572: 'Protocol Tunneling',
  T1041: 'Exfiltration Over C2 Channel', T1048: 'Exfiltration Over Alternative Protocol',
  T1567: 'Exfiltration Over Web Service', T1485: 'Data Destruction',
  T1486: 'Data Encrypted for Impact', T1489: 'Service Stop',
  T1490: 'Inhibit System Recovery', T1498: 'Network Denial of Service',
  T1499: 'Endpoint Denial of Service', T1529: 'System Shutdown/Reboot',
}

const TACTIC_NAMES: Record<string, string> = {
  TA0001: 'Initial Access', TA0002: 'Execution', TA0003: 'Persistence',
  TA0004: 'Privilege Escalation', TA0005: 'Defense Evasion', TA0006: 'Credential Access',
  TA0007: 'Discovery', TA0008: 'Lateral Movement', TA0009: 'Collection',
  TA0010: 'Exfiltration', TA0011: 'Command and Control', TA0040: 'Impact',
  TA0042: 'Resource Development', TA0043: 'Reconnaissance',
}

const TACTIC_RE  = /^TA\d{4}$/i
const TECH_RE    = /^T\d{4}(\.\d{3})?$/i
const UUID_RE    = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

// ─── Generate Modal ───────────────────────────────────────────────────────────

function GenerateModal({ onClose, onGenerated }: { onClose: () => void; onGenerated: (id: string) => void }) {
  const [mode, setMode] = useState<'scratch' | 'alert'>('scratch')
  const [alertId, setAlertId] = useState('')
  const [tactic, setTactic] = useState('')
  const [technique, setTechnique] = useState('')
  const [severity, setSeverity] = useState('high')
  const [sourceHost, setSourceHost] = useState('')
  const [touched, setTouched] = useState<Record<string, boolean>>({})
  const [error, setError] = useState<string | null>(null)
  const qc = useQueryClient()

  // Live lookups
  const tacticKey = tactic.trim().toUpperCase()
  const techKey   = technique.trim().toUpperCase().split('.')[0]
  const tacticName  = TACTIC_NAMES[tacticKey] ?? null
  const techName    = TECHNIQUE_NAMES[techKey] ?? null

  // Field-level validation
  const alertIdErr   = mode === 'alert' && touched.alertId && alertId.trim() && !UUID_RE.test(alertId.trim())
    ? 'Must be a valid UUID' : null
  const tacticErr    = mode === 'scratch' && touched.tactic && tactic.trim() && !TACTIC_RE.test(tactic.trim())
    ? 'Format: TA0000 (e.g. TA0040)' : null
  const techniqueErr = mode === 'scratch' && touched.technique && technique.trim() && !TECH_RE.test(technique.trim())
    ? 'Format: T0000 or T0000.000 (e.g. T1486)' : null
  const techniqueRequired = mode === 'scratch' && touched.technique && !technique.trim()
    ? 'Technique is required for manual generation' : null

  const hasErrors = !!(alertIdErr || tacticErr || techniqueErr || techniqueRequired)
  const canSubmit = mode === 'alert'
    ? (alertId.trim() !== '' && !alertIdErr)
    : (technique.trim() !== '' && !techniqueErr && !tacticErr)

  const generate = useMutation({
    mutationFn: () => {
      setTouched({ alertId: true, tactic: true, technique: true })
      if (!canSubmit) throw new Error('Please fix validation errors before generating.')
      if (mode === 'alert') {
        return playbooksApi.generate({ alert_id: alertId.trim() })
      }
      return playbooksApi.generate({
        tactic:      tactic.trim().toUpperCase() || undefined,
        technique:   technique.trim().toUpperCase() || undefined,
        severity,
        source_host: sourceHost.trim() || undefined,
      })
    },
    onSuccess: (pb) => {
      qc.invalidateQueries({ queryKey: ['playbooks'] })
      onGenerated(pb.id)
    },
    onError: (err) => setError(extractApiError(err)),
  })

  const inputStyle = (hasErr: boolean) => ({
    width: '100%', padding: '7px 10px', borderRadius: 6, fontSize: 12, outline: 'none',
    background: 'rgba(255,255,255,0.04)', color: '#F5F7FA',
    fontFamily: "'JetBrains Mono', monospace",
    border: `1px solid ${hasErr ? 'rgba(248,113,113,0.5)' : 'rgba(255,255,255,0.08)'}`,
    boxSizing: 'border-box' as const,
    transition: 'border-color 0.15s',
  })
  const labelStyle = { fontSize: 10, color: '#8B95A7', display: 'block', marginBottom: 4,
    textTransform: 'uppercase' as const, letterSpacing: '0.5px', fontWeight: 600 }
  const hintStyle  = (ok: boolean) => ({ fontSize: 10, marginTop: 3, color: ok ? '#10B981' : '#EF4444' })

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 100,
      background: 'rgba(0,0,0,0.75)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        width: 500, background: '#111111',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: 12, padding: 24,
      }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: '#F5F7FA', fontFamily: "'Space Grotesk', sans-serif" }}>
              Generate Playbook
            </div>
            <div style={{ fontSize: 11, color: '#5C6373', marginTop: 2 }}>
              AI will generate a complete incident response procedure
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#5C6373', cursor: 'pointer', padding: 4 }}>
            <X size={16} />
          </button>
        </div>

        {/* Mode toggle */}
        <div style={{
          display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginBottom: 20,
          background: 'rgba(255,255,255,0.03)', borderRadius: 8, padding: 4,
        }}>
          {(['scratch', 'alert'] as const).map(m => (
            <button key={m} onClick={() => { setMode(m); setError(null); setTouched({}) }} style={{
              padding: '7px 0', borderRadius: 6, border: 'none', cursor: 'pointer',
              fontSize: 11, fontWeight: 700, transition: 'all 0.15s',
              background: mode === m ? '#1E293B' : 'transparent',
              color: mode === m ? '#F5F7FA' : '#5C6373',
              fontFamily: "'Space Grotesk', sans-serif",
            }}>
              {m === 'scratch' ? '⚡ From MITRE ATT&CK' : '🔗 From Alert ID'}
            </button>
          ))}
        </div>

        <div style={{ display: 'grid', gap: 14 }}>
          {mode === 'alert' ? (
            <div>
              <label style={labelStyle}>Alert ID <span style={{ color: '#EF4444' }}>*</span></label>
              <input
                style={inputStyle(!!alertIdErr)}
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                value={alertId}
                onChange={e => { setAlertId(e.target.value); setError(null) }}
                onBlur={() => setTouched(t => ({ ...t, alertId: true }))}
              />
              {alertIdErr && <div style={hintStyle(false)}>{alertIdErr}</div>}
              <div style={{ fontSize: 10, color: '#3A4150', marginTop: 4 }}>
                Paste an alert UUID to build the playbook from real incident data
              </div>
            </div>
          ) : (
            <>
              {/* Tactic + Technique */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div>
                  <label style={labelStyle}>MITRE Tactic</label>
                  <input
                    style={inputStyle(!!tacticErr)}
                    placeholder="e.g. TA0040"
                    value={tactic}
                    onChange={e => { setTactic(e.target.value); setError(null) }}
                    onBlur={() => setTouched(t => ({ ...t, tactic: true }))}
                  />
                  {tacticErr
                    ? <div style={hintStyle(false)}>{tacticErr}</div>
                    : tacticName
                    ? <div style={hintStyle(true)}>✓ {tacticName}</div>
                    : tactic.trim()
                    ? <div style={{ fontSize: 10, color: '#5C6373', marginTop: 3 }}>Unknown tactic ID</div>
                    : null
                  }
                </div>
                <div>
                  <label style={labelStyle}>MITRE Technique <span style={{ color: '#EF4444' }}>*</span></label>
                  <input
                    style={inputStyle(!!(techniqueErr || techniqueRequired))}
                    placeholder="e.g. T1486"
                    value={technique}
                    onChange={e => { setTechnique(e.target.value); setError(null) }}
                    onBlur={() => setTouched(t => ({ ...t, technique: true }))}
                  />
                  {techniqueErr
                    ? <div style={hintStyle(false)}>{techniqueErr}</div>
                    : techniqueRequired
                    ? <div style={hintStyle(false)}>{techniqueRequired}</div>
                    : techName
                    ? <div style={hintStyle(true)}>✓ {techName}</div>
                    : technique.trim()
                    ? <div style={{ fontSize: 10, color: '#5C6373', marginTop: 3 }}>Unknown technique ID</div>
                    : null
                  }
                </div>
              </div>

              {/* Severity + Source Host */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div>
                  <label style={labelStyle}>Severity <span style={{ color: '#EF4444' }}>*</span></label>
                  <select
                    style={{ ...inputStyle(false), appearance: 'none' as const }}
                    value={severity}
                    onChange={e => setSeverity(e.target.value)}
                  >
                    <option value="critical">🔴 Critical</option>
                    <option value="high">🟠 High</option>
                    <option value="medium">🟡 Medium</option>
                    <option value="low">🔵 Low</option>
                  </select>
                </div>
                <div>
                  <label style={labelStyle}>Source Host</label>
                  <input
                    style={inputStyle(false)}
                    placeholder="hostname or IP"
                    value={sourceHost}
                    onChange={e => setSourceHost(e.target.value)}
                  />
                  <div style={{ fontSize: 10, color: '#3A4150', marginTop: 3 }}>Optional — improves commands</div>
                </div>
              </div>

              {/* AI preview strip */}
              {(techName || tacticName) && (
                <div style={{
                  padding: '10px 12px', borderRadius: 8,
                  background: 'rgba(59,130,246,0.06)',
                  border: '1px solid rgba(59,130,246,0.15)',
                }}>
                  <div style={{ fontSize: 10, color: '#60A5FA', fontWeight: 700, marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                    AI will generate a playbook for:
                  </div>
                  <div style={{ fontSize: 12, color: '#F5F7FA', fontWeight: 600 }}>
                    {techName ?? tacticName}
                    {techName && technique.trim() && <span style={{ color: '#5C6373', fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }}> ({technique.trim().toUpperCase()})</span>}
                  </div>
                  {sourceHost.trim() && (
                    <div style={{ fontSize: 10, color: '#8B95A7', marginTop: 3 }}>
                      Target host: <span style={{ fontFamily: "'JetBrains Mono', monospace", color: '#93C5FD' }}>{sourceHost.trim()}</span>
                    </div>
                  )}
                  <div style={{ fontSize: 10, color: '#5C6373', marginTop: 6 }}>
                    8–10 steps • Real commands • Full IR lifecycle • MITRE-mapped
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {error && (
          <div style={{
            marginTop: 12, padding: '8px 12px', borderRadius: 6, fontSize: 12,
            background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)',
            color: '#F87171',
          }}>
            {error}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 20 }}>
          <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            size="sm"
            loading={generate.isPending}
            onClick={() => generate.mutate()}
            disabled={hasErrors || generate.isPending}
          >
            <Zap size={12} /> Generate Playbook
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── PlaybooksPage ────────────────────────────────────────────────────────────

const STATUS_CHIPS = [
  { value: '',            label: 'All',         color: '#8B95A7' },
  { value: 'draft',       label: 'Draft',       color: '#F59E0B' },
  { value: 'in_progress', label: 'In Progress', color: '#3B82F6' },
  { value: 'completed',   label: 'Completed',   color: '#10B981' },
  { value: 'failed',      label: 'Failed',      color: '#EF4444' },
] as const

export function PlaybooksPage() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const [statusFilter, setStatusFilter] = useState('')
  const [titleSearch, setTitleSearch] = useState('')
  const [showGenerate, setShowGenerate] = useState(false)

  // Auto-open generate modal when coming from investigation page
  useEffect(() => {
    if (searchParams.get('generate') === '1') {
      setShowGenerate(true)
    }
  }, [searchParams])

  const { data: rawPlaybooks = [], isLoading } = useQuery({
    queryKey: ['playbooks', statusFilter],
    queryFn: () => playbooksApi.list(statusFilter ? { status: statusFilter } : undefined),
    refetchInterval: 30_000,
  })

  const playbooks = titleSearch.trim()
    ? rawPlaybooks.filter(p => p.title.toLowerCase().includes(titleSearch.toLowerCase()))
    : rawPlaybooks

  const counts = {
    total:       rawPlaybooks.length,
    in_progress: rawPlaybooks.filter(p => p.status === 'in_progress').length,
    completed:   rawPlaybooks.filter(p => p.status === 'completed').length,
    draft:       rawPlaybooks.filter(p => p.status === 'draft').length,
  }

  const statCards = [
    { label: 'Total',       value: counts.total,       color: '#8B95A7' },
    { label: 'In Progress', value: counts.in_progress, color: '#3B82F6' },
    { label: 'Completed',   value: counts.completed,   color: '#10B981' },
    { label: 'Draft',       value: counts.draft,       color: '#F59E0B' },
  ]

  return (
    <div className="page-in" style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 50px - 40px)', overflow: 'hidden' }}>

      {/* Page header */}
      <div style={{
        display: 'flex', alignItems: 'flex-start',
        justifyContent: 'space-between', paddingBottom: 12,
        borderBottom: '1px solid rgba(255,255,255,0.06)', flexShrink: 0,
      }}>
        <div>
          <h1 style={{ fontSize: 17, fontWeight: 800, color: '#F5F7FA', fontFamily: "'Space Grotesk', sans-serif" }}>
            Playbooks
          </h1>
          <p style={{ fontSize: 12, color: '#5C6373', marginTop: 3 }}>
            AI-generated incident response procedures
          </p>
        </div>
        <Button variant="primary" size="sm" onClick={() => setShowGenerate(true)}>
          <Bot size={13} /> Generate Playbook
        </Button>
      </div>

      {/* Stat cards */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)',
        gap: 10, padding: '12px 0', flexShrink: 0,
      }}>
        {statCards.map(({ label, value, color }) => (
          <div key={label} style={{
            background: '#0D0D0D', border: '1px solid rgba(255,255,255,0.06)',
            borderRadius: 8, padding: '10px 14px',
          }}>
            <div style={{ fontSize: 20, fontWeight: 800, color, fontFamily: "'JetBrains Mono', monospace" }}>
              {value}
            </div>
            <div style={{ fontSize: 9, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '1.2px', marginTop: 3, fontWeight: 700 }}>
              {label}
            </div>
          </div>
        ))}
      </div>

      {/* Filter toolbar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, padding: '4px 0 10px',
        borderBottom: '1px solid rgba(255,255,255,0.04)', flexShrink: 0,
      }}>
        {/* Status chips */}
        <div style={{
          display: 'flex', gap: 0.5,
          background: 'rgba(255,255,255,0.03)',
          border: '1px solid rgba(255,255,255,0.07)',
          borderRadius: 8, padding: 3,
        }}>
          {STATUS_CHIPS.map(chip => (
            <button
              key={chip.value}
              onClick={() => setStatusFilter(chip.value)}
              style={{
                padding: '4px 11px', borderRadius: 5, cursor: 'pointer',
                fontSize: 11, fontWeight: 600, border: 'none',
                transition: 'all 120ms',
                background: statusFilter === chip.value ? `${chip.color}18` : 'transparent',
                color: statusFilter === chip.value ? chip.color : '#5C6373',
              }}
            >
              {chip.label}
            </button>
          ))}
        </div>

        {/* Title search */}
        <div style={{ position: 'relative', flex: 1, maxWidth: 280 }}>
          <Search size={12} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: '#5C6373', pointerEvents: 'none' }} />
          <input
            value={titleSearch}
            onChange={e => setTitleSearch(e.target.value)}
            placeholder="Search playbooks…"
            style={{
              width: '100%', paddingLeft: 28, paddingRight: 10,
              height: 30, borderRadius: 6, fontSize: 12,
              background: 'rgba(255,255,255,0.04)',
              border: '1px solid rgba(255,255,255,0.07)',
              color: '#F5F7FA', outline: 'none',
              boxSizing: 'border-box',
            }}
          />
        </div>

        {titleSearch && (
          <span style={{ fontSize: 11, color: '#5C6373' }}>
            {playbooks.length} of {rawPlaybooks.length} shown
          </span>
        )}
      </div>

      {/* Table */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        <table className="data-table">
          <thead style={{ position: 'sticky', top: 0, background: '#050505', zIndex: 10 }}>
            <tr>
              <th>TITLE</th>
              <th style={{ width: 90 }}>SEVERITY</th>
              <th style={{ width: 110 }}>STATUS</th>
              <th style={{ width: 100 }}>SOURCE</th>
              <th style={{ width: 100 }}>GENERATED BY</th>
              <th style={{ width: 100 }}>CREATED</th>
              <th style={{ width: 40 }}></th>
            </tr>
          </thead>
          <tbody>
            {isLoading && Array.from({ length: 5 }).map((_, i) => (
              <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                {[200, 80, 100, 100, 100, 90, 30].map((w, j) => (
                  <td key={j} style={{ padding: '9px 12px' }}>
                    <span className="skel" style={{ width: w, height: 14, display: 'block' }} />
                  </td>
                ))}
              </tr>
            ))}

            {!isLoading && playbooks.map(pb => (
              <PlaybookRow
                key={pb.id}
                pb={pb}
                onClick={() => navigate(`/playbooks/${pb.id}`)}
              />
            ))}

            {!isLoading && playbooks.length === 0 && (
              <tr>
                <td colSpan={7}>
                  <div style={{ textAlign: 'center', padding: '60px 0' }}>
                    <BookOpen size={36} style={{ color: '#3A4150', marginBottom: 12, display: 'block', margin: '0 auto 12px' }} />
                    <div style={{ fontSize: 14, fontWeight: 600, color: '#5C6373', marginBottom: 6 }}>
                      No playbooks yet
                    </div>
                    <div style={{ fontSize: 12, color: '#3A4150', marginBottom: 20 }}>
                      Generate your first response playbook from an alert or manually
                    </div>
                    <Button variant="primary" onClick={() => setShowGenerate(true)}>
                      <Plus size={13} /> Generate Playbook
                    </Button>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {showGenerate && (
        <GenerateModal
          onClose={() => setShowGenerate(false)}
          onGenerated={(id) => {
            setShowGenerate(false)
            navigate(`/playbooks/${id}`)
          }}
        />
      )}
    </div>
  )
}

function PlaybookRow({ pb, onClick }: { pb: Playbook; onClick: () => void }) {
  const [hovered, setHovered] = useState(false)
  return (
    <tr
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        borderBottom: '1px solid rgba(255,255,255,0.04)',
        background: hovered ? 'rgba(255,255,255,0.025)' : 'transparent',
        cursor: 'pointer', transition: 'background 120ms',
      }}
    >
      <td style={{ padding: '9px 12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          <span style={{ fontSize: 12, fontWeight: 600, color: '#F5F7FA' }}>{pb.title}</span>
          {pb.created_by_id === null && (
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: 3,
              padding: '1px 6px', borderRadius: 4, fontSize: 8, fontWeight: 700,
              textTransform: 'uppercase', letterSpacing: '0.5px',
              background: 'rgba(139,92,246,0.12)', color: '#A78BFA',
              border: '1px solid rgba(139,92,246,0.2)',
              fontFamily: "'JetBrains Mono', monospace",
            }}>
              <Bot size={8} /> Auto
            </span>
          )}
        </div>
      </td>
      <td style={{ padding: '9px 12px' }}>
        <SeverityBadge severity={pb.severity} />
      </td>
      <td style={{ padding: '9px 12px' }}>
        <StatusBadge status={pb.status} />
      </td>
      <td style={{ padding: '9px 12px' }}>
        <span style={{ fontSize: 11, color: '#8B95A7', fontFamily: "'JetBrains Mono', monospace" }}>
          {pb.source_host || '—'}
        </span>
      </td>
      <td style={{ padding: '9px 12px' }}>
        <span style={{
          fontSize: 9, padding: '2px 6px', borderRadius: 4,
          background: pb.generated_by === 'llm' ? 'rgba(139,92,246,0.12)' : 'rgba(255,255,255,0.06)',
          color: pb.generated_by === 'llm' ? '#A78BFA' : '#8B95A7',
          fontFamily: "'JetBrains Mono', monospace", fontWeight: 700,
          textTransform: 'uppercase',
        }}>
          {pb.generated_by}
        </span>
      </td>
      <td style={{ padding: '9px 12px' }}>
        <span style={{ fontSize: 11, color: '#5C6373' }}>
          {formatRelativeTime(pb.created_at)}
        </span>
      </td>
      <td style={{ padding: '9px 12px', opacity: hovered ? 1 : 0, transition: 'opacity 120ms' }}>
        <ChevronRight size={14} style={{ color: '#5C6373' }} />
      </td>
    </tr>
  )
}
