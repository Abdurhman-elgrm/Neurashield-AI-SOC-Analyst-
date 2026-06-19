import { useState, useEffect, useRef, useCallback, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Play, Plus, Trash2, Save, ChevronDown, Search, Crosshair,
  Cpu, FileSearch, AlertTriangle, Globe, Shield, Activity,
} from 'lucide-react'
import { huntApi } from '@/api/hunt'
import type {
  HuntFilter, HuntResultEntry, SavedHunt, FilterLogic,
  EventHuntFilter, EventHuntQuery, EventHuntResultEntry, EventHuntSummary,
} from '@/api/hunt'
import { formatRelativeTime, extractApiError } from '@/lib/utils'

// ─── Types ────────────────────────────────────────────────────────────────────

type HuntMode = 'investigation' | 'event'
type FieldType = 'number' | 'text' | 'status' | 'confidence' | 'verdict'

// ─── Investigation Hunt Constants ─────────────────────────────────────────────

const INV_HUNT_FIELDS: Array<{ label: string; value: string; type: FieldType }> = [
  { label: 'Threat Score',       value: 'threat_score',       type: 'number'     },
  { label: 'Status',             value: 'status',             type: 'status'     },
  { label: 'Confidence',         value: 'confidence',         type: 'confidence' },
  { label: 'Verdict',            value: 'verdict',            type: 'verdict'    },
  { label: 'Title / Summary',    value: 'title',              type: 'text'       },
]

const INV_OPERATORS_BY_TYPE: Record<FieldType, Array<{ label: string; value: HuntFilter['operator'] }>> = {
  number:     [
    { label: '>=', value: 'gte' }, { label: '<=', value: 'lte' },
    { label: '>',  value: 'gt'  }, { label: '<',  value: 'lt'  },
    { label: '=',  value: 'eq'  },
  ],
  text:       [
    { label: 'contains',    value: 'contains'   },
    { label: 'equals',      value: 'eq'         },
    { label: 'starts with', value: 'startswith' },
  ],
  status:     [{ label: 'equals', value: 'eq' }],
  confidence: [{ label: 'equals', value: 'eq' }],
  verdict:    [{ label: 'equals', value: 'eq' }],
}

const STATUS_OPTIONS     = ['new', 'active', 'triaged', 'investigating', 'contained', 'resolved', 'closed', 'false_positive']
const CONFIDENCE_OPTIONS = ['high', 'medium', 'low']
const VERDICT_OPTIONS    = ['true_positive', 'false_positive', 'benign_positive', 'suspicious', 'inconclusive']

// ─── Event Hunt Constants ─────────────────────────────────────────────────────

type EventFieldType = 'text' | 'number'

const EVT_HUNT_FIELDS: Array<{ label: string; value: string; type: EventFieldType; placeholder?: string }> = [
  { label: 'Hostname',       value: 'host_name',      type: 'text',   placeholder: 'e.g. DESKTOP-01 or *srv*' },
  { label: 'Username',       value: 'username',       type: 'text',   placeholder: 'e.g. john.doe or SYSTEM'  },
  { label: 'Process Name',   value: 'process_name',   type: 'text',   placeholder: 'e.g. powershell.exe'      },
  { label: 'Source IP',      value: 'source_ip',      type: 'text',   placeholder: 'e.g. 192.168.1.100'       },
  { label: 'Dest IP',        value: 'dest_ip',        type: 'text',   placeholder: 'e.g. 10.0.0.1'            },
  { label: 'Country',        value: 'geo_country',    type: 'text',   placeholder: 'e.g. CN, RU'              },
  { label: 'Correlation ID', value: 'correlation_id', type: 'text',   placeholder: 'correlation group ID'     },
  { label: 'Severity',       value: 'severity',       type: 'number', placeholder: '1–4'                      },
]

const EVT_OPERATORS_BY_TYPE: Record<EventFieldType, Array<{ label: string; value: EventHuntFilter['operator'] }>> = {
  text:   [
    { label: 'contains',    value: 'contains'   },
    { label: 'equals',      value: 'eq'         },
    { label: 'starts with', value: 'startswith' },
  ],
  number: [
    { label: '>=', value: 'gte' }, { label: '<=', value: 'lte' },
    { label: '>',  value: 'gt'  }, { label: '<',  value: 'lt'  },
    { label: '=',  value: 'eq'  },
  ],
}

const EVENT_CATEGORIES = ['auth', 'process', 'network', 'file', 'registry', 'dns', 'system', 'other']

const UEBA_FLAG_OPTIONS = [
  'after_hours', 'new_source_ip', 'new_process_on_host', 'privileged_user',
  'impossible_travel', 'brute_force', 'brute_force_success',
  'lateral_movement', 'lateral_movement_xdomain', 'credential_stuffing',
  'insider_offhours_data', 'insider_rapid_access', 'insider_sensitive_access',
]

const TIME_RANGES = [
  { label: 'Last Hour',   value: '1h'  },
  { label: 'Last 24h',    value: '24h' },
  { label: 'Last 7 days', value: '7d'  },
  { label: 'Last 30 days',value: '30d' },
  { label: 'All time',    value: ''    },
]

const MITRE_TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access',
  'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery',
  'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getFromTs(val: string): string | null {
  const offsets: Record<string, number> = {
    '1h': 3_600_000, '24h': 86_400_000, '7d': 604_800_000, '30d': 2_592_000_000,
  }
  const ms = offsets[val]
  return ms ? new Date(Date.now() - ms).toISOString() : null
}

function getScoreColors(score: number): { bg: string; color: string } {
  if (score >= 80) return { bg: 'rgba(239,68,68,0.12)',  color: '#F87171' }
  if (score >= 50) return { bg: 'rgba(245,158,11,0.12)', color: '#FBBF24' }
  return                  { bg: 'rgba(75,85,99,0.15)',   color: '#6B7280' }
}

function getStatusColor(status: string): string {
  const map: Record<string, string> = {
    new: '#60A5FA', active: '#F59E0B', triaged: '#A78BFA',
    investigating: '#EC4899', contained: '#34D399',
    resolved: '#10B981', closed: '#6B7280', false_positive: '#10B981',
  }
  return map[status] ?? '#8B95A7'
}

function getSeverityLabel(sev: number): { label: string; color: string } {
  if (sev >= 4) return { label: 'CRITICAL', color: '#F87171' }
  if (sev >= 3) return { label: 'HIGH',     color: '#FBBF24' }
  if (sev >= 2) return { label: 'MEDIUM',   color: '#60A5FA' }
  return               { label: 'LOW',      color: '#6B7280' }
}

function getCategoryColor(cat: string): string {
  const map: Record<string, string> = {
    auth:     '#818CF8', process: '#34D399', network: '#60A5FA',
    file:     '#FBBF24', registry: '#F59E0B', dns: '#A78BFA',
    system:   '#8B95A7', other: '#6B7280',
  }
  return map[cat] ?? '#6B7280'
}

function formatTimestamp(iso: string): string {
  try {
    const d = new Date(iso)
    return d.toLocaleString('en-US', {
      month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false,
    })
  } catch {
    return iso
  }
}

// ─── Shared sub-components ────────────────────────────────────────────────────

function MitreTacticsDropdown({ selected, onChange }: { selected: string[]; onChange: (v: string[]) => void }) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const handle = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handle)
    return () => document.removeEventListener('mousedown', handle)
  }, [])

  const toggle = (t: string) =>
    onChange(selected.includes(t) ? selected.filter(x => x !== t) : [...selected, t])

  const label = selected.length === 0 ? 'Any tactic'
    : selected.length === 1 ? selected[0]
    : `${selected.length} tactics`

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button onClick={() => setOpen(!open)} className="inp" style={{
        display: 'flex', alignItems: 'center', gap: 6,
        cursor: 'pointer', width: '100%', justifyContent: 'space-between',
      }}>
        <span style={{ fontSize: 12, color: selected.length ? '#F5F7FA' : '#5C6373' }}>{label}</span>
        <ChevronDown size={13} style={{ color: '#5C6373', flexShrink: 0 }} />
      </button>
      {open && (
        <div style={{
          position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 50,
          background: '#0D0D0D', border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 8, marginTop: 4, maxHeight: 260, overflowY: 'auto',
          boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
        }}>
          {MITRE_TACTICS.map(tactic => {
            const checked = selected.includes(tactic)
            return (
              <label key={tactic} onClick={() => toggle(tactic)} style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '7px 12px', cursor: 'pointer',
                background: checked ? 'rgba(59,130,246,0.06)' : 'transparent',
                borderBottom: '1px solid rgba(255,255,255,0.03)',
              }}>
                <div style={{
                  width: 14, height: 14, borderRadius: 3, flexShrink: 0,
                  background: checked ? '#3B82F6' : 'rgba(255,255,255,0.08)',
                  border: `1px solid ${checked ? '#2563EB' : 'rgba(255,255,255,0.12)'}`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  {checked && <div style={{ width: 8, height: 8, borderRadius: 1.5, background: '#fff' }} />}
                </div>
                <span style={{ fontSize: 12, color: checked ? '#93C5FD' : '#8B95A7' }}>{tactic}</span>
              </label>
            )
          })}
        </div>
      )}
    </div>
  )
}

function SaveModal({ onSave, onClose }: {
  onSave: (name: string, desc: string) => Promise<void>
  onClose: () => void
}) {
  const [name, setName]     = useState('')
  const [desc, setDesc]     = useState('')
  const [saving, setSaving] = useState(false)
  const [err, setErr]       = useState<string | null>(null)

  const handleSave = async () => {
    if (!name.trim()) return
    setSaving(true); setErr(null)
    try { await onSave(name.trim(), desc.trim()); onClose() }
    catch (e) { setErr(extractApiError(e)) }
    finally { setSaving(false) }
  }

  return (
    <>
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 49 }} />
      <div style={{
        position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%, -50%)',
        width: 380, zIndex: 50, padding: 24,
        background: '#0D0D0D', border: '1px solid rgba(59,130,246,0.2)',
        borderRadius: 12, boxShadow: '0 0 40px rgba(59,130,246,0.1)',
      }}>
        <div style={{ fontSize: 15, fontWeight: 700, color: '#F5F7FA', marginBottom: 4, fontFamily: "'Space Grotesk', sans-serif" }}>
          Save Hunt
        </div>
        <p style={{ fontSize: 12, color: '#5C6373', marginBottom: 20 }}>Save current query for quick re-use</p>
        {(['Name', 'Description (optional)'] as const).map((lbl, i) => {
          const val  = i === 0 ? name : desc
          const set  = i === 0 ? setName : setDesc
          const ph   = i === 0 ? 'e.g. Lateral Movement — Off-hours' : 'Brief description...'
          return (
            <div key={lbl} style={{ marginBottom: 12 }}>
              <label style={{ display: 'block', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 6 }}>{lbl}</label>
              <input className="inp" style={{ width: '100%' }} placeholder={ph}
                value={val} onChange={e => set(e.target.value)}
                onKeyDown={i === 0 ? e => e.key === 'Enter' && handleSave() : undefined}
                autoFocus={i === 0}
              />
            </div>
          )
        })}
        {err && <p style={{ fontSize: 12, color: '#FCA5A5', marginBottom: 12 }}>{err}</p>}
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
          <button onClick={onClose} style={{
            padding: '7px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600,
            background: 'transparent', border: '1px solid rgba(255,255,255,0.1)',
            color: '#8B95A7', cursor: 'pointer',
          }}>Cancel</button>
          <button onClick={handleSave} disabled={!name.trim() || saving} style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '7px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600,
            background: name.trim() && !saving ? '#3B82F6' : 'rgba(59,130,246,0.3)',
            border: 'none', color: '#fff',
            cursor: name.trim() && !saving ? 'pointer' : 'default',
          }}>
            <Save size={13} />
            {saving ? 'Saving...' : 'Save'}
          </button>
        </div>
      </div>
    </>
  )
}

// ─── Investigation Hunt sub-components ───────────────────────────────────────

function InvFilterRow({
  filter, onChange, onRemove, canRemove,
}: {
  filter: HuntFilter
  onChange: (f: HuntFilter) => void
  onRemove: () => void
  canRemove: boolean
}) {
  const field = INV_HUNT_FIELDS.find(f => f.value === filter.field)
  const fieldType = field?.type ?? 'text'
  const operators = INV_OPERATORS_BY_TYPE[fieldType]

  const handleFieldChange = (fv: string) => {
    const newType = INV_HUNT_FIELDS.find(f => f.value === fv)?.type ?? 'text'
    onChange({ field: fv, operator: INV_OPERATORS_BY_TYPE[newType][0].value, value: '' })
  }

  let valueEl: ReactNode
  if (fieldType === 'status') {
    valueEl = (
      <select className="inp" style={{ flex: 1 }} value={filter.value}
        onChange={e => onChange({ ...filter, value: e.target.value })}>
        <option value="">Select...</option>
        {STATUS_OPTIONS.map(v => <option key={v} value={v}>{v.replace(/_/g, ' ')}</option>)}
      </select>
    )
  } else if (fieldType === 'confidence') {
    valueEl = (
      <select className="inp" style={{ flex: 1 }} value={filter.value}
        onChange={e => onChange({ ...filter, value: e.target.value })}>
        <option value="">Select...</option>
        {CONFIDENCE_OPTIONS.map(v => <option key={v} value={v}>{v}</option>)}
      </select>
    )
  } else if (fieldType === 'verdict') {
    valueEl = (
      <select className="inp" style={{ flex: 1 }} value={filter.value}
        onChange={e => onChange({ ...filter, value: e.target.value })}>
        <option value="">Select...</option>
        {VERDICT_OPTIONS.map(v => <option key={v} value={v}>{v.replace(/_/g, ' ')}</option>)}
      </select>
    )
  } else {
    valueEl = (
      <input className="inp" style={{ flex: 1 }}
        type={fieldType === 'number' ? 'number' : 'text'}
        placeholder="Value..."
        value={filter.value}
        onChange={e => onChange({ ...filter, value: e.target.value })}
      />
    )
  }

  return (
    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
      <select className="inp" style={{ width: 140, flexShrink: 0 }}
        value={filter.field} onChange={e => handleFieldChange(e.target.value)}>
        {INV_HUNT_FIELDS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
      </select>
      <select className="inp" style={{ width: 110, flexShrink: 0 }}
        value={filter.operator}
        onChange={e => onChange({ ...filter, operator: e.target.value as HuntFilter['operator'] })}>
        {operators.map(op => <option key={op.value} value={op.value}>{op.label}</option>)}
      </select>
      {valueEl}
      <button onClick={onRemove} disabled={!canRemove} style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        width: 28, height: 28, borderRadius: 6, flexShrink: 0,
        background: canRemove ? 'rgba(239,68,68,0.08)' : 'rgba(255,255,255,0.04)',
        border: `1px solid ${canRemove ? 'rgba(239,68,68,0.2)' : 'rgba(255,255,255,0.06)'}`,
        color: canRemove ? '#F87171' : '#3A4150',
        cursor: canRemove ? 'pointer' : 'default',
      }}>
        <Trash2 size={12} />
      </button>
    </div>
  )
}

function InvResultRow({ entry, onClick, isLast }: { entry: HuntResultEntry; onClick: () => void; isLast: boolean }) {
  const sc  = getScoreColors(entry.threat_score)
  const stC = getStatusColor(entry.status)
  return (
    <div onClick={onClick} style={{
      display: 'grid', gridTemplateColumns: '68px 1fr 116px 80px 180px 88px',
      padding: '10px 14px',
      borderBottom: isLast ? 'none' : '1px solid rgba(255,255,255,0.03)',
      cursor: 'pointer', alignItems: 'center',
    }}
    onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.025)')}
    onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
    >
      <div>
        <span style={{
          display: 'inline-block', padding: '2px 7px', borderRadius: 5,
          fontSize: 11, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace",
          background: sc.bg, color: sc.color,
        }}>{entry.threat_score}</span>
      </div>
      <div style={{ fontSize: 12, color: '#E2E8F0', paddingRight: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {entry.executive_summary}
      </div>
      <div>
        <span style={{
          display: 'inline-block', padding: '2px 8px', borderRadius: 5,
          fontSize: 10, fontWeight: 600,
          background: `${stC}1a`, color: stC, border: `1px solid ${stC}33`,
        }}>{entry.status.replace(/_/g, ' ')}</span>
      </div>
      <div style={{ fontSize: 11, color: '#5C6373' }}>{entry.confidence}</div>
      <div style={{ display: 'flex', gap: 4, flexWrap: 'nowrap', overflow: 'hidden' }}>
        {entry.match_reasons.slice(0, 2).map((r, i) => (
          <span key={i} style={{
            display: 'inline-block', padding: '1px 6px', borderRadius: 4,
            fontSize: 9, fontWeight: 600, whiteSpace: 'nowrap',
            background: 'rgba(99,102,241,0.1)', color: '#818CF8',
            border: '1px solid rgba(99,102,241,0.15)',
          }}>{r}</span>
        ))}
        {entry.match_reasons.length > 2 && (
          <span style={{ fontSize: 10, color: '#5C6373', flexShrink: 0 }}>+{entry.match_reasons.length - 2}</span>
        )}
      </div>
      <div style={{ fontSize: 10, color: '#5C6373', textAlign: 'right' }}>
        {formatRelativeTime(entry.created_at)}
      </div>
    </div>
  )
}

// ─── Event Hunt sub-components ────────────────────────────────────────────────

function EvtFilterRow({
  filter, onChange, onRemove, canRemove,
}: {
  filter: EventHuntFilter
  onChange: (f: EventHuntFilter) => void
  onRemove: () => void
  canRemove: boolean
}) {
  const field = EVT_HUNT_FIELDS.find(f => f.value === filter.field)
  const fieldType = field?.type ?? 'text'
  const operators = EVT_OPERATORS_BY_TYPE[fieldType]

  const handleFieldChange = (fv: string) => {
    const newType = EVT_HUNT_FIELDS.find(f => f.value === fv)?.type ?? 'text'
    onChange({ field: fv, operator: EVT_OPERATORS_BY_TYPE[newType][0].value, value: '' })
  }

  return (
    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
      <select className="inp" style={{ width: 140, flexShrink: 0 }}
        value={filter.field} onChange={e => handleFieldChange(e.target.value)}>
        {EVT_HUNT_FIELDS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
      </select>
      <select className="inp" style={{ width: 110, flexShrink: 0 }}
        value={filter.operator}
        onChange={e => onChange({ ...filter, operator: e.target.value as EventHuntFilter['operator'] })}>
        {operators.map(op => <option key={op.value} value={op.value}>{op.label}</option>)}
      </select>
      <input className="inp" style={{ flex: 1 }}
        type={fieldType === 'number' ? 'number' : 'text'}
        placeholder={field?.placeholder ?? 'Value...'}
        value={filter.value}
        onChange={e => onChange({ ...filter, value: e.target.value })}
      />
      <button onClick={onRemove} disabled={!canRemove} style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        width: 28, height: 28, borderRadius: 6, flexShrink: 0,
        background: canRemove ? 'rgba(239,68,68,0.08)' : 'rgba(255,255,255,0.04)',
        border: `1px solid ${canRemove ? 'rgba(239,68,68,0.2)' : 'rgba(255,255,255,0.06)'}`,
        color: canRemove ? '#F87171' : '#3A4150',
        cursor: canRemove ? 'pointer' : 'default',
      }}>
        <Trash2 size={12} />
      </button>
    </div>
  )
}

function MultiSelectDropdown({
  label: labelText, options, selected, onChange, accentColor = '#3B82F6',
}: {
  label: string
  options: string[]
  selected: string[]
  onChange: (v: string[]) => void
  accentColor?: string
}) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const handle = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handle)
    return () => document.removeEventListener('mousedown', handle)
  }, [])

  const toggle = (v: string) =>
    onChange(selected.includes(v) ? selected.filter(x => x !== v) : [...selected, v])

  const displayLabel = selected.length === 0
    ? labelText
    : selected.length === 1 ? selected[0]
    : `${selected.length} selected`

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button onClick={() => setOpen(!open)} className="inp" style={{
        display: 'flex', alignItems: 'center', gap: 6,
        cursor: 'pointer', width: '100%', justifyContent: 'space-between',
      }}>
        <span style={{ fontSize: 12, color: selected.length ? '#F5F7FA' : '#5C6373' }}>{displayLabel}</span>
        <ChevronDown size={13} style={{ color: '#5C6373', flexShrink: 0 }} />
      </button>
      {open && (
        <div style={{
          position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 50,
          background: '#0D0D0D', border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 8, marginTop: 4, maxHeight: 240, overflowY: 'auto',
          boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
        }}>
          {options.map(opt => {
            const checked = selected.includes(opt)
            return (
              <label key={opt} onClick={() => toggle(opt)} style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '7px 12px', cursor: 'pointer',
                background: checked ? `${accentColor}0d` : 'transparent',
                borderBottom: '1px solid rgba(255,255,255,0.03)',
              }}>
                <div style={{
                  width: 14, height: 14, borderRadius: 3, flexShrink: 0,
                  background: checked ? accentColor : 'rgba(255,255,255,0.08)',
                  border: `1px solid ${checked ? accentColor : 'rgba(255,255,255,0.12)'}`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  {checked && <div style={{ width: 8, height: 8, borderRadius: 1.5, background: '#fff' }} />}
                </div>
                <span style={{ fontSize: 12, color: checked ? '#F5F7FA' : '#8B95A7' }}>{opt}</span>
              </label>
            )
          })}
        </div>
      )}
    </div>
  )
}

function SummaryBar({ summary }: { summary: EventHuntSummary }) {
  const stats = [
    { icon: Cpu,           label: 'Unique Hosts',  value: summary.unique_hosts,     color: '#60A5FA' },
    { icon: Activity,      label: 'Unique Users',  value: summary.unique_users,     color: '#818CF8' },
    { icon: Globe,         label: 'Unique IPs',    value: summary.unique_ips,       color: '#34D399' },
    { icon: AlertTriangle, label: 'Anomalies',     value: summary.total_anomalies,  color: '#FBBF24' },
    { icon: Shield,        label: 'Threat IPs',    value: summary.total_threat_ips, color: '#F87171' },
  ]
  return (
    <div style={{
      display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap',
    }}>
      {stats.map(({ icon: Icon, label, value, color }) => (
        <div key={label} style={{
          display: 'flex', alignItems: 'center', gap: 8,
          padding: '8px 14px', borderRadius: 8,
          background: `${color}0d`, border: `1px solid ${color}22`,
          flex: '1 1 auto', minWidth: 110,
        }}>
          <Icon size={14} style={{ color, flexShrink: 0 }} />
          <div>
            <div style={{ fontSize: 18, fontWeight: 700, color, fontFamily: "'Space Grotesk', sans-serif", lineHeight: 1 }}>
              {value}
            </div>
            <div style={{ fontSize: 10, color: '#5C6373', marginTop: 2 }}>{label}</div>
          </div>
        </div>
      ))}
    </div>
  )
}

function EvtResultRow({ entry, isLast }: { entry: EventHuntResultEntry; isLast: boolean }) {
  const sev = getSeverityLabel(entry.severity)
  const catColor = getCategoryColor(entry.category)

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: '148px 140px 140px 120px 80px 70px 1fr',
      padding: '9px 14px',
      borderBottom: isLast ? 'none' : '1px solid rgba(255,255,255,0.03)',
      alignItems: 'center', fontSize: 12,
    }}
    onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.025)')}
    onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
    >
      {/* Timestamp */}
      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#5C6373' }}>
        {formatTimestamp(entry.timestamp)}
      </div>

      {/* Hostname */}
      <div style={{ color: '#B8C0CC', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', paddingRight: 8 }}>
        {entry.host_name ?? <span style={{ color: '#3A4150' }}>—</span>}
      </div>

      {/* Username */}
      <div style={{ color: '#B8C0CC', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', paddingRight: 8 }}>
        {entry.username ?? <span style={{ color: '#3A4150' }}>—</span>}
      </div>

      {/* Process / Source IP */}
      <div style={{ color: '#8B95A7', fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', paddingRight: 8 }}>
        {entry.process_name ?? entry.source_ip ?? <span style={{ color: '#3A4150' }}>—</span>}
      </div>

      {/* Category */}
      <div>
        <span style={{
          display: 'inline-block', padding: '2px 7px', borderRadius: 4,
          fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px',
          background: `${catColor}18`, color: catColor, border: `1px solid ${catColor}33`,
        }}>{entry.category}</span>
      </div>

      {/* Severity */}
      <div>
        <span style={{ fontSize: 9, fontWeight: 700, color: sev.color }}>{sev.label}</span>
      </div>

      {/* Flags */}
      <div style={{ display: 'flex', gap: 4, flexWrap: 'nowrap', overflow: 'hidden' }}>
        {entry.is_threat_ip && (
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 3,
            padding: '1px 6px', borderRadius: 4, fontSize: 9, fontWeight: 600,
            background: 'rgba(239,68,68,0.1)', color: '#F87171', border: '1px solid rgba(239,68,68,0.2)',
            whiteSpace: 'nowrap', flexShrink: 0,
          }}>
            <Shield size={9} /> THREAT IP
          </span>
        )}
        {entry.is_anomaly && (
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 3,
            padding: '1px 6px', borderRadius: 4, fontSize: 9, fontWeight: 600,
            background: 'rgba(245,158,11,0.1)', color: '#FBBF24', border: '1px solid rgba(245,158,11,0.2)',
            whiteSpace: 'nowrap', flexShrink: 0,
          }}>
            <AlertTriangle size={9} /> ANOMALY
          </span>
        )}
        {entry.ueba_flags.slice(0, 1).map(flag => (
          <span key={flag} style={{
            display: 'inline-block', padding: '1px 6px', borderRadius: 4,
            fontSize: 9, fontWeight: 600, whiteSpace: 'nowrap', flexShrink: 0,
            background: 'rgba(99,102,241,0.1)', color: '#818CF8', border: '1px solid rgba(99,102,241,0.15)',
          }}>{flag.replace(/_/g, ' ')}</span>
        ))}
        {entry.ueba_flags.length > 1 && (
          <span style={{ fontSize: 10, color: '#5C6373', flexShrink: 0 }}>+{entry.ueba_flags.length - 1}</span>
        )}
        {!entry.is_threat_ip && !entry.is_anomaly && entry.ueba_flags.length === 0 && (
          <span style={{ color: '#3A4150', fontSize: 10 }}>—</span>
        )}
      </div>
    </div>
  )
}

// ─── HuntPage ─────────────────────────────────────────────────────────────────

export function HuntPage() {
  const navigate = useNavigate()

  // ── Shared state ────────────────────────────────────────────────────────────
  const [mode, setMode]               = useState<HuntMode>('event')
  const [timeRange, setTimeRange]     = useState('24h')
  const [filterLogic, setFilterLogic] = useState<FilterLogic>('and')
  const [savedHunts, setSavedHunts]   = useState<SavedHunt[]>([])
  const [showSaveModal, setShowSaveModal] = useState(false)

  // ── Investigation Hunt state ─────────────────────────────────────────────────
  const [invFilters, setInvFilters]   = useState<HuntFilter[]>([{ field: 'threat_score', operator: 'gte', value: '60' }])
  const [mitreTactics, setMitreTactics] = useState<string[]>([])
  const [invResults, setInvResults]   = useState<HuntResultEntry[]>([])
  const [invCursor, setInvCursor]     = useState<string | null>(null)
  const [invHasMore, setInvHasMore]   = useState(false)
  const [invTotal, setInvTotal]       = useState<number | null>(null)
  const [invRunning, setInvRunning]   = useState(false)
  const [invLoadMore, setInvLoadMore] = useState(false)
  const [invError, setInvError]       = useState<string | null>(null)
  const [invHasRun, setInvHasRun]     = useState(false)

  // ── Event Hunt state ─────────────────────────────────────────────────────────
  const [evtFilters, setEvtFilters]   = useState<EventHuntFilter[]>([{ field: 'host_name', operator: 'contains', value: '' }])
  const [evtCategories, setEvtCategories] = useState<string[]>([])
  const [evtUebaFlags, setEvtUebaFlags]   = useState<string[]>([])
  const [evtIsAnomaly, setEvtIsAnomaly]   = useState<boolean | null>(null)
  const [evtIsThreatIp, setEvtIsThreatIp] = useState<boolean | null>(null)
  const [evtMinSeverity, setEvtMinSeverity] = useState<number | null>(null)
  const [evtResults, setEvtResults]   = useState<EventHuntResultEntry[]>([])
  const [evtSummary, setEvtSummary]   = useState<EventHuntSummary | null>(null)
  const [evtCursor, setEvtCursor]     = useState<string | null>(null)
  const [evtHasMore, setEvtHasMore]   = useState(false)
  const [evtTotal, setEvtTotal]       = useState<number | null>(null)
  const [evtRunning, setEvtRunning]   = useState(false)
  const [evtLoadMore, setEvtLoadMore] = useState(false)
  const [evtError, setEvtError]       = useState<string | null>(null)
  const [evtHasRun, setEvtHasRun]     = useState(false)

  useEffect(() => {
    huntApi.listSaved()
      .then(data => setSavedHunts(Array.isArray(data) ? data : []))
      .catch(() => {})
  }, [])

  // ── Investigation Hunt handlers ──────────────────────────────────────────────

  const buildInvQuery = useCallback((cursor?: string | null) => ({
    filters:       invFilters.filter(f => f.value.trim() !== ''),
    logic:         filterLogic,
    from_ts:       getFromTs(timeRange),
    to_ts:         null as null,
    mitre_tactics: mitreTactics,
    limit:         50,
    cursor:        cursor ?? null,
  }), [invFilters, filterLogic, timeRange, mitreTactics])

  const handleInvRun = async () => {
    setInvRunning(true); setInvError(null)
    try {
      const res = await huntApi.run(buildInvQuery())
      setInvResults(res.entries); setInvCursor(res.next_cursor)
      setInvHasMore(res.has_more); setInvTotal(res.total); setInvHasRun(true)
    } catch (e) { setInvError(extractApiError(e)) }
    finally { setInvRunning(false) }
  }

  const handleInvLoadMore = async () => {
    if (!invCursor || invLoadMore) return
    setInvLoadMore(true)
    try {
      const res = await huntApi.run(buildInvQuery(invCursor))
      setInvResults(prev => [...prev, ...res.entries])
      setInvCursor(res.next_cursor); setInvHasMore(res.has_more)
    } catch { /* silent */ }
    finally { setInvLoadMore(false) }
  }

  // ── Event Hunt handlers ──────────────────────────────────────────────────────

  const buildEvtQuery = useCallback((cursor?: string | null): EventHuntQuery => ({
    filters:       evtFilters.filter(f => f.value.trim() !== ''),
    logic:         filterLogic,
    from_ts:       getFromTs(timeRange),
    to_ts:         null,
    category:      evtCategories.length ? evtCategories : undefined,
    min_severity:  evtMinSeverity ?? undefined,
    is_anomaly:    evtIsAnomaly ?? undefined,
    is_threat_ip:  evtIsThreatIp ?? undefined,
    ueba_flags:    evtUebaFlags.length ? evtUebaFlags : undefined,
    cursor:        cursor ?? null,
    limit:         50,
    sort:          'desc',
  }), [evtFilters, filterLogic, timeRange, evtCategories, evtMinSeverity, evtIsAnomaly, evtIsThreatIp, evtUebaFlags])

  const handleEvtRun = async () => {
    setEvtRunning(true); setEvtError(null)
    try {
      const res = await huntApi.runEventHunt(buildEvtQuery())
      setEvtResults(res.entries); setEvtSummary(res.summary)
      setEvtCursor(res.next_cursor); setEvtHasMore(res.has_more)
      setEvtTotal(res.total); setEvtHasRun(true)
    } catch (e) { setEvtError(extractApiError(e)) }
    finally { setEvtRunning(false) }
  }

  const handleEvtLoadMore = async () => {
    if (!evtCursor || evtLoadMore) return
    setEvtLoadMore(true)
    try {
      const res = await huntApi.runEventHunt(buildEvtQuery(evtCursor))
      setEvtResults(prev => [...prev, ...res.entries])
      setEvtCursor(res.next_cursor); setEvtHasMore(res.has_more)
    } catch { /* silent */ }
    finally { setEvtLoadMore(false) }
  }

  // ── Saved hunt handlers ──────────────────────────────────────────────────────

  const loadSavedHunt = (hunt: SavedHunt) => {
    const q = hunt.query_params as {
      mode?: HuntMode
      filters?: HuntFilter[]; logic?: FilterLogic; mitre_tactics?: string[]
      evt_filters?: EventHuntFilter[]; evt_categories?: string[]
      evt_ueba_flags?: string[]; evt_is_anomaly?: boolean | null
      evt_is_threat_ip?: boolean | null; evt_min_severity?: number | null
    }
    if (q.mode) setMode(q.mode)
    if (Array.isArray(q.filters))         setInvFilters(q.filters)
    if (q.logic === 'and' || q.logic === 'or') setFilterLogic(q.logic)
    if (Array.isArray(q.mitre_tactics))   setMitreTactics(q.mitre_tactics)
    if (Array.isArray(q.evt_filters))     setEvtFilters(q.evt_filters)
    if (Array.isArray(q.evt_categories))  setEvtCategories(q.evt_categories)
    if (Array.isArray(q.evt_ueba_flags))  setEvtUebaFlags(q.evt_ueba_flags)
    if (q.evt_is_anomaly  !== undefined)  setEvtIsAnomaly(q.evt_is_anomaly ?? null)
    if (q.evt_is_threat_ip !== undefined) setEvtIsThreatIp(q.evt_is_threat_ip ?? null)
    if (q.evt_min_severity !== undefined) setEvtMinSeverity(q.evt_min_severity ?? null)
  }

  const handleSave = async (name: string, desc: string) => {
    const query_params: Record<string, unknown> = {
      mode, logic: filterLogic,
      filters: invFilters, mitre_tactics: mitreTactics,
      evt_filters: evtFilters, evt_categories: evtCategories,
      evt_ueba_flags: evtUebaFlags,
      evt_is_anomaly: evtIsAnomaly,
      evt_is_threat_ip: evtIsThreatIp,
      evt_min_severity: evtMinSeverity,
    }
    const hunt = await huntApi.saveHunt({ name, description: desc || undefined, query_params })
    setSavedHunts(prev => [hunt, ...prev])
  }

  const isRunning = mode === 'investigation' ? invRunning : evtRunning
  const handleRun = mode === 'investigation' ? handleInvRun : handleEvtRun

  // ── Toggle helpers ───────────────────────────────────────────────────────────

  const BoolToggle = ({ value, onChange, label }: {
    value: boolean | null; onChange: (v: boolean | null) => void; label: string
  }) => (
    <button onClick={() => onChange(value === true ? null : true)} style={{
      display: 'flex', alignItems: 'center', gap: 5,
      padding: '5px 10px', borderRadius: 6, fontSize: 11, fontWeight: 600,
      cursor: 'pointer', border: '1px solid',
      background: value === true ? 'rgba(245,158,11,0.12)' : 'rgba(255,255,255,0.04)',
      borderColor: value === true ? 'rgba(245,158,11,0.4)' : 'rgba(255,255,255,0.1)',
      color: value === true ? '#FBBF24' : '#5C6373',
    }}>
      {label}
    </button>
  )

  return (
    <div style={{ display: 'flex', height: 'calc(100vh - 50px - 40px)', overflow: 'hidden', background: '#050505' }}>

      {/* ── Saved Hunts Sidebar ─────────────────────────────────────────────── */}
      <div style={{
        width: 210, flexShrink: 0,
        borderRight: '1px solid rgba(255,255,255,0.06)',
        background: '#0A0A0A',
        display: 'flex', flexDirection: 'column', overflow: 'hidden',
      }}>
        <div style={{ padding: '16px 14px 10px' }}>
          <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 12 }}>
            Saved Hunts
          </div>
          <button onClick={() => setShowSaveModal(true)} style={{
            display: 'flex', alignItems: 'center', gap: 6,
            width: '100%', padding: '7px 10px',
            background: 'rgba(59,130,246,0.06)', border: '1px solid rgba(59,130,246,0.15)',
            borderRadius: 7, fontSize: 12, fontWeight: 600, color: '#60A5FA', cursor: 'pointer',
          }}>
            <Plus size={12} /> Save Current
          </button>
        </div>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {savedHunts.length === 0 ? (
            <div style={{ padding: '24px 14px', textAlign: 'center', fontSize: 11, color: '#3A4150', lineHeight: 1.6 }}>
              <Crosshair size={22} style={{ display: 'block', margin: '0 auto 8px', opacity: 0.2 }} />
              No saved hunts yet
            </div>
          ) : (
            savedHunts.map(hunt => (
              <button key={hunt.hunt_id} onClick={() => loadSavedHunt(hunt)} style={{
                display: 'block', width: '100%', padding: '9px 14px',
                textAlign: 'left', background: 'transparent', border: 'none',
                borderBottom: '1px solid rgba(255,255,255,0.03)',
                cursor: 'pointer',
              }}
              onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.03)')}
              onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
              >
                <div style={{ fontSize: 12, fontWeight: 600, color: '#B8C0CC', marginBottom: 2, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {hunt.name}
                </div>
                <div style={{ fontSize: 10, color: '#5C6373' }}>{hunt.run_count} run{hunt.run_count !== 1 ? 's' : ''}</div>
              </button>
            ))
          )}
        </div>
      </div>

      {/* ── Main Panel ──────────────────────────────────────────────────────── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

        {/* Header */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '14px 24px', borderBottom: '1px solid rgba(255,255,255,0.06)', flexShrink: 0,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
            <div>
              <h1 style={{ fontSize: 18, fontWeight: 700, fontFamily: "'Space Grotesk', sans-serif", color: '#F5F7FA', margin: 0 }}>
                Threat Hunt
              </h1>
              <p style={{ fontSize: 12, color: '#5C6373', margin: '2px 0 0' }}>
                {mode === 'event'
                  ? 'Hunt raw events by host, user, process, IP, UEBA flag, and more'
                  : 'Query aggregated investigations by score, status, and MITRE tactic'}
              </p>
            </div>

            {/* Mode switcher */}
            <div style={{
              display: 'flex', background: 'rgba(255,255,255,0.04)',
              border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, padding: 3,
            }}>
              {([
                { id: 'event' as HuntMode,         icon: FileSearch, label: 'Event Hunt'         },
                { id: 'investigation' as HuntMode,  icon: Crosshair,  label: 'Investigation Hunt' },
              ] as const).map(({ id, icon: Icon, label }) => (
                <button key={id} onClick={() => setMode(id)} style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  padding: '6px 12px', borderRadius: 6, fontSize: 12, fontWeight: 600,
                  border: 'none', cursor: 'pointer',
                  background: mode === id ? 'rgba(59,130,246,0.15)' : 'transparent',
                  color: mode === id ? '#60A5FA' : '#5C6373',
                }}>
                  <Icon size={13} /> {label}
                </button>
              ))}
            </div>
          </div>

          <button onClick={handleRun} disabled={isRunning} style={{
            display: 'flex', alignItems: 'center', gap: 7,
            padding: '9px 18px', borderRadius: 8,
            background: isRunning ? 'rgba(59,130,246,0.4)' : '#3B82F6',
            border: 'none', color: '#fff', fontSize: 13, fontWeight: 600,
            cursor: isRunning ? 'default' : 'pointer',
          }}>
            <Play size={14} />
            {isRunning ? 'Running...' : 'Run Hunt'}
          </button>
        </div>

        {/* Scrollable body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>

          {/* ── Shared: Time range + AND/OR logic ──────────────────────────── */}
          <div style={{
            display: 'flex', gap: 12, marginBottom: 16, alignItems: 'flex-end',
          }}>
            <div style={{ flex: 1 }}>
              <label style={{ display: 'block', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 6 }}>
                Time Range
              </label>
              <select className="inp" style={{ width: '100%' }} value={timeRange} onChange={e => setTimeRange(e.target.value)}>
                {TIME_RANGES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 6 }}>
                Filter Logic
              </label>
              <div style={{ display: 'flex', gap: 4 }}>
                {(['and', 'or'] as FilterLogic[]).map(lg => (
                  <button key={lg} onClick={() => setFilterLogic(lg)} style={{
                    padding: '7px 16px', borderRadius: 6,
                    fontSize: 11, fontWeight: 700, cursor: 'pointer',
                    textTransform: 'uppercase', letterSpacing: '0.5px',
                    background: filterLogic === lg ? 'rgba(59,130,246,0.15)' : 'rgba(255,255,255,0.04)',
                    border: `1px solid ${filterLogic === lg ? 'rgba(59,130,246,0.4)' : 'rgba(255,255,255,0.08)'}`,
                    color: filterLogic === lg ? '#60A5FA' : '#5C6373',
                  }}>{lg}</button>
                ))}
              </div>
            </div>
          </div>

          {/* ── EVENT HUNT Query Builder ────────────────────────────────────── */}
          {mode === 'event' && (
            <div style={{
              background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)',
              borderRadius: 10, padding: 16, marginBottom: 16,
            }}>
              <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 14 }}>
                Event Query Builder
              </div>

              {/* Quick filters row */}
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 14 }}>
                <BoolToggle value={evtIsAnomaly}   onChange={setEvtIsAnomaly}   label="⚡ Anomaly Only"   />
                <BoolToggle value={evtIsThreatIp}  onChange={setEvtIsThreatIp}  label="🔴 Threat IP Only" />

                {/* Min severity buttons */}
                {[1, 2, 3, 4].map(sev => {
                  const { label, color } = getSeverityLabel(sev)
                  const active = evtMinSeverity === sev
                  return (
                    <button key={sev} onClick={() => setEvtMinSeverity(active ? null : sev)} style={{
                      padding: '5px 10px', borderRadius: 6, fontSize: 11, fontWeight: 600,
                      cursor: 'pointer', border: '1px solid',
                      background: active ? `${color}18` : 'rgba(255,255,255,0.04)',
                      borderColor: active ? `${color}55` : 'rgba(255,255,255,0.1)',
                      color: active ? color : '#5C6373',
                    }}>{label}+</button>
                  )
                })}
              </div>

              {/* Category chips */}
              <div style={{ marginBottom: 14 }}>
                <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 8 }}>
                  Category
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {EVENT_CATEGORIES.map(cat => {
                    const active = evtCategories.includes(cat)
                    const color  = getCategoryColor(cat)
                    return (
                      <button key={cat} onClick={() => setEvtCategories(prev =>
                        prev.includes(cat) ? prev.filter(c => c !== cat) : [...prev, cat]
                      )} style={{
                        padding: '3px 10px', borderRadius: 5, fontSize: 11, fontWeight: 600,
                        cursor: 'pointer', border: '1px solid',
                        background: active ? `${color}18` : 'rgba(255,255,255,0.04)',
                        borderColor: active ? `${color}55` : 'rgba(255,255,255,0.08)',
                        color: active ? color : '#5C6373',
                      }}>{cat}</button>
                    )
                  })}
                </div>
              </div>

              {/* Field-level filters */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 10 }}>
                {evtFilters.map((filter, idx) => (
                  <EvtFilterRow
                    key={idx}
                    filter={filter}
                    onChange={f => setEvtFilters(prev => prev.map((x, j) => j === idx ? f : x))}
                    onRemove={() => setEvtFilters(prev => prev.filter((_, j) => j !== idx))}
                    canRemove={evtFilters.length > 1}
                  />
                ))}
              </div>
              <button onClick={() => setEvtFilters(prev => [...prev, { field: 'host_name', operator: 'contains' as const, value: '' }])} style={{
                display: 'flex', alignItems: 'center', gap: 5,
                padding: '5px 10px', borderRadius: 6, marginBottom: 14,
                background: 'transparent', border: '1px dashed rgba(255,255,255,0.1)',
                color: '#5C6373', fontSize: 11, fontWeight: 600, cursor: 'pointer',
              }}>
                <Plus size={12} /> Add Filter
              </button>

              {/* UEBA Flags */}
              <div>
                <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 6 }}>
                  UEBA Flags
                </div>
                <MultiSelectDropdown
                  label="Any flag"
                  options={UEBA_FLAG_OPTIONS}
                  selected={evtUebaFlags}
                  onChange={setEvtUebaFlags}
                  accentColor="#818CF8"
                />
              </div>
            </div>
          )}

          {/* ── INVESTIGATION HUNT Query Builder ────────────────────────────── */}
          {mode === 'investigation' && (
            <div style={{
              background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)',
              borderRadius: 10, padding: 16, marginBottom: 16,
            }}>
              <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 14 }}>
                Investigation Query Builder
              </div>

              {/* Filter rows */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 10 }}>
                {invFilters.map((filter, idx) => (
                  <div key={idx}>
                    {idx > 0 && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                        <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.04)' }} />
                        <span style={{ fontSize: 9, fontWeight: 700, color: '#5C6373', letterSpacing: '1px', textTransform: 'uppercase' }}>{filterLogic}</span>
                        <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.04)' }} />
                      </div>
                    )}
                    <InvFilterRow
                      filter={filter}
                      onChange={f => setInvFilters(prev => prev.map((x, j) => j === idx ? f : x))}
                      onRemove={() => setInvFilters(prev => prev.filter((_, j) => j !== idx))}
                      canRemove={invFilters.length > 1}
                    />
                  </div>
                ))}
              </div>
              <button onClick={() => setInvFilters(prev => [...prev, { field: 'threat_score', operator: 'gte' as const, value: '' }])} style={{
                display: 'flex', alignItems: 'center', gap: 5,
                padding: '5px 10px', borderRadius: 6, marginBottom: 14,
                background: 'transparent', border: '1px dashed rgba(255,255,255,0.1)',
                color: '#5C6373', fontSize: 11, fontWeight: 600, cursor: 'pointer',
              }}>
                <Plus size={12} /> Add Filter
              </button>

              <div>
                <label style={{ display: 'block', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 6 }}>
                  MITRE Tactic
                </label>
                <MitreTacticsDropdown selected={mitreTactics} onChange={setMitreTactics} />
              </div>
            </div>
          )}

          {/* Errors */}
          {(mode === 'event' ? evtError : invError) && (
            <div style={{
              padding: '10px 14px', marginBottom: 16, borderRadius: 8,
              background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)',
              fontSize: 12, color: '#FCA5A5',
            }}>{mode === 'event' ? evtError : invError}</div>
          )}

          {/* Pre-run empty state */}
          {!(mode === 'event' ? evtHasRun : invHasRun) && !(mode === 'event' ? evtRunning : invRunning) && (
            <div style={{ textAlign: 'center', padding: '64px 0', color: '#3A4150' }}>
              <Crosshair size={36} style={{ display: 'block', margin: '0 auto 12px', opacity: 0.15 }} />
              <div style={{ fontSize: 14, color: '#5C6373', marginBottom: 4 }}>
                Configure your query and click Run Hunt
              </div>
              <div style={{ fontSize: 12 }}>
                {mode === 'event'
                  ? 'Hunts raw events — hostname, username, process, IP, UEBA flags'
                  : 'Searches aggregated investigations by score, status, MITRE tactic'}
              </div>
            </div>
          )}

          {/* ── EVENT Results ─────────────────────────────────────────────────── */}
          {mode === 'event' && evtHasRun && (
            <div>
              {/* Summary bar */}
              {evtSummary && <SummaryBar summary={evtSummary} />}

              <div style={{ display: 'flex', alignItems: 'center', marginBottom: 12 }}>
                <span style={{ fontSize: 13, fontWeight: 600, color: '#F5F7FA' }}>Events</span>
                {evtTotal !== null && (
                  <span style={{ fontSize: 11, color: '#5C6373', marginLeft: 8 }}>
                    {evtTotal} event{evtTotal !== 1 ? 's' : ''}{evtHasMore ? '+' : ''}
                  </span>
                )}
              </div>

              {evtResults.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '48px 0', color: '#3A4150', fontSize: 13 }}>
                  <Search size={28} style={{ display: 'block', margin: '0 auto 10px', opacity: 0.2 }} />
                  No events matched your query
                </div>
              ) : (
                <div style={{
                  background: 'rgba(255,255,255,0.01)', border: '1px solid rgba(255,255,255,0.06)',
                  borderRadius: 10, overflow: 'hidden',
                }}>
                  {/* Table header */}
                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: '148px 140px 140px 120px 80px 70px 1fr',
                    padding: '8px 14px',
                    borderBottom: '1px solid rgba(255,255,255,0.06)',
                    background: 'rgba(255,255,255,0.02)',
                  }}>
                    {['Timestamp', 'Hostname', 'Username', 'Process / Source IP', 'Category', 'Severity', 'Flags'].map(col => (
                      <div key={col} style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', color: '#5C6373' }}>
                        {col}
                      </div>
                    ))}
                  </div>

                  {evtResults.map((entry, idx) => (
                    <EvtResultRow
                      key={entry.event_id}
                      entry={entry}
                      isLast={idx === evtResults.length - 1 && !evtHasMore}
                    />
                  ))}

                  {evtHasMore && (
                    <div style={{ padding: '12px 14px', borderTop: '1px solid rgba(255,255,255,0.04)' }}>
                      <button onClick={handleEvtLoadMore} disabled={evtLoadMore} style={{
                        display: 'block', width: '100%', padding: '8px',
                        borderRadius: 6, fontSize: 12, fontWeight: 600, textAlign: 'center',
                        background: evtLoadMore ? 'rgba(255,255,255,0.03)' : 'rgba(255,255,255,0.04)',
                        border: '1px solid rgba(255,255,255,0.08)',
                        color: '#8B95A7', cursor: evtLoadMore ? 'default' : 'pointer',
                      }}>
                        {evtLoadMore ? 'Loading...' : 'Load More'}
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* ── INVESTIGATION Results ────────────────────────────────────────── */}
          {mode === 'investigation' && invHasRun && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', marginBottom: 12 }}>
                <span style={{ fontSize: 13, fontWeight: 600, color: '#F5F7FA' }}>Results</span>
                {invTotal !== null && (
                  <span style={{ fontSize: 11, color: '#5C6373', marginLeft: 8 }}>
                    {invTotal} investigation{invTotal !== 1 ? 's' : ''}
                  </span>
                )}
              </div>

              {invResults.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '48px 0', color: '#3A4150', fontSize: 13 }}>
                  <Search size={28} style={{ display: 'block', margin: '0 auto 10px', opacity: 0.2 }} />
                  No investigations matched your query
                </div>
              ) : (
                <div style={{
                  background: 'rgba(255,255,255,0.01)', border: '1px solid rgba(255,255,255,0.06)',
                  borderRadius: 10, overflow: 'hidden',
                }}>
                  <div style={{
                    display: 'grid', gridTemplateColumns: '68px 1fr 116px 80px 180px 88px',
                    padding: '8px 14px',
                    borderBottom: '1px solid rgba(255,255,255,0.06)',
                    background: 'rgba(255,255,255,0.02)',
                  }}>
                    {['Score', 'Title', 'Status', 'Confidence', 'Match Reasons', 'Created'].map(col => (
                      <div key={col} style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', color: '#5C6373' }}>
                        {col}
                      </div>
                    ))}
                  </div>

                  {invResults.map((entry, idx) => (
                    <InvResultRow
                      key={entry.investigation_id}
                      entry={entry}
                      onClick={() => navigate(`/investigations/${entry.investigation_id}`)}
                      isLast={idx === invResults.length - 1 && !invHasMore}
                    />
                  ))}

                  {invHasMore && (
                    <div style={{ padding: '12px 14px', borderTop: '1px solid rgba(255,255,255,0.04)' }}>
                      <button onClick={handleInvLoadMore} disabled={invLoadMore} style={{
                        display: 'block', width: '100%', padding: '8px',
                        borderRadius: 6, fontSize: 12, fontWeight: 600, textAlign: 'center',
                        background: invLoadMore ? 'rgba(255,255,255,0.03)' : 'rgba(255,255,255,0.04)',
                        border: '1px solid rgba(255,255,255,0.08)',
                        color: '#8B95A7', cursor: invLoadMore ? 'default' : 'pointer',
                      }}>
                        {invLoadMore ? 'Loading...' : 'Load More'}
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

        </div>
      </div>

      {showSaveModal && (
        <SaveModal onSave={handleSave} onClose={() => setShowSaveModal(false)} />
      )}
    </div>
  )
}
