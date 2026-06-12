import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Play, Plus, Trash2, Save, ChevronDown, Search, Crosshair } from 'lucide-react'
import { huntApi } from '@/api/hunt'
import type { HuntFilter, HuntResultEntry, SavedHunt, FilterLogic } from '@/api/hunt'
import { formatRelativeTime, extractApiError } from '@/lib/utils'

// ─── Constants ────────────────────────────────────────────────────────────────

type FieldType = 'number' | 'text' | 'status' | 'confidence' | 'verdict'

const HUNT_FIELDS: Array<{ label: string; value: string; type: FieldType }> = [
  { label: 'Threat Score', value: 'threat_score', type: 'number'     },
  { label: 'Status',       value: 'status',       type: 'status'     },
  { label: 'Confidence',   value: 'confidence',   type: 'confidence' },
  { label: 'Verdict',      value: 'verdict',      type: 'verdict'    },
  { label: 'Title',        value: 'title',        type: 'text'       },
]

type OpDef = { label: string; value: HuntFilter['operator'] }

const OPERATORS_BY_TYPE: Record<FieldType, OpDef[]> = {
  number:     [
    { label: '>=',          value: 'gte'        },
    { label: '<=',          value: 'lte'        },
    { label: '>',           value: 'gt'         },
    { label: '<',           value: 'lt'         },
    { label: '=',           value: 'eq'         },
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

const TIME_RANGES = [
  { label: 'Last Hour',    value: '1h'  },
  { label: 'Last 24h',     value: '24h' },
  { label: 'Last 7 days',  value: '7d'  },
  { label: 'Last 30 days', value: '30d' },
  { label: 'All time',     value: ''    },
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

function getFieldType(field: string): FieldType {
  return HUNT_FIELDS.find(f => f.value === field)?.type ?? 'text'
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

// ─── FilterRow ────────────────────────────────────────────────────────────────

function FilterRow({
  filter, onChange, onRemove, canRemove,
}: {
  filter: HuntFilter
  onChange: (f: HuntFilter) => void
  onRemove: () => void
  canRemove: boolean
}) {
  const fieldType = getFieldType(filter.field)
  const operators = OPERATORS_BY_TYPE[fieldType]

  const handleFieldChange = (field: string) => {
    const newType = getFieldType(field)
    onChange({ field, operator: OPERATORS_BY_TYPE[newType][0].value, value: '' })
  }

  let valueEl: React.ReactNode
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
      <select className="inp" style={{ width: 130, flexShrink: 0 }}
        value={filter.field} onChange={e => handleFieldChange(e.target.value)}>
        {HUNT_FIELDS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
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

// ─── MitreTacticsDropdown ─────────────────────────────────────────────────────

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

  const toggle = (tactic: string) =>
    onChange(selected.includes(tactic) ? selected.filter(t => t !== tactic) : [...selected, tactic])

  const label = selected.length === 0 ? 'Any tactic'
    : selected.length === 1 ? selected[0]
    : `${selected.length} tactics`

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button onClick={() => setOpen(!open)} className="inp" style={{
        display: 'flex', alignItems: 'center', gap: 6,
        cursor: 'pointer', width: '100%', justifyContent: 'space-between', textAlign: 'left',
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

// ─── SaveModal ────────────────────────────────────────────────────────────────

function SaveModal({ onSave, onClose }: {
  onSave: (name: string, desc: string) => Promise<void>
  onClose: () => void
}) {
  const [name,   setName]   = useState('')
  const [desc,   setDesc]   = useState('')
  const [saving, setSaving] = useState(false)
  const [err,    setErr]    = useState<string | null>(null)

  const handleSave = async () => {
    if (!name.trim()) return
    setSaving(true)
    setErr(null)
    try {
      await onSave(name.trim(), desc.trim())
      onClose()
    } catch (e) {
      setErr(extractApiError(e))
    } finally {
      setSaving(false)
    }
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
        <p style={{ fontSize: 12, color: '#5C6373', marginBottom: 20 }}>
          Save the current query for quick re-use
        </p>
        {[
          { lbl: 'Name', val: name, set: setName, ph: 'e.g. High Score Open Investigations', kb: true },
          { lbl: 'Description (optional)', val: desc, set: setDesc, ph: 'Brief description...', kb: false },
        ].map(({ lbl, val, set, ph, kb }) => (
          <div key={lbl} style={{ marginBottom: 12 }}>
            <label style={{ display: 'block', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 6 }}>
              {lbl}
            </label>
            <input className="inp" style={{ width: '100%' }} placeholder={ph}
              value={val} onChange={e => set(e.target.value)}
              onKeyDown={kb ? (e => e.key === 'Enter' && handleSave()) : undefined}
              autoFocus={kb}
            />
          </div>
        ))}
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

// ─── ResultRow ────────────────────────────────────────────────────────────────

function ResultRow({ entry, onClick, isLast }: { entry: HuntResultEntry; onClick: () => void; isLast: boolean }) {
  const sc  = getScoreColors(entry.threat_score)
  const stC = getStatusColor(entry.status)
  return (
    <div onClick={onClick} style={{
      display: 'grid', gridTemplateColumns: '68px 1fr 116px 80px 180px 88px',
      padding: '10px 14px',
      borderBottom: isLast ? 'none' : '1px solid rgba(255,255,255,0.03)',
      cursor: 'pointer', alignItems: 'center', transition: 'background 100ms',
    }}
    onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.025)')}
    onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
    >
      {/* Score */}
      <div>
        <span style={{
          display: 'inline-block', padding: '2px 7px', borderRadius: 5,
          fontSize: 11, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace",
          background: sc.bg, color: sc.color,
        }}>{entry.threat_score}</span>
      </div>
      {/* Title */}
      <div style={{ fontSize: 12, color: '#E2E8F0', paddingRight: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {entry.executive_summary}
      </div>
      {/* Status */}
      <div>
        <span style={{
          display: 'inline-block', padding: '2px 8px', borderRadius: 5,
          fontSize: 10, fontWeight: 600,
          background: `${stC}1a`, color: stC, border: `1px solid ${stC}33`,
        }}>{entry.status.replace(/_/g, ' ')}</span>
      </div>
      {/* Confidence */}
      <div style={{ fontSize: 11, color: '#5C6373' }}>{entry.confidence}</div>
      {/* Match reasons */}
      <div style={{ display: 'flex', gap: 4, flexWrap: 'nowrap', alignItems: 'center', overflow: 'hidden' }}>
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
        {entry.match_reasons.length === 0 && <span style={{ fontSize: 10, color: '#3A4150' }}>—</span>}
      </div>
      {/* Created */}
      <div style={{ fontSize: 10, color: '#5C6373', textAlign: 'right' }}>
        {formatRelativeTime(entry.created_at)}
      </div>
    </div>
  )
}

// ─── HuntPage ─────────────────────────────────────────────────────────────────

export function HuntPage() {
  const navigate = useNavigate()

  // Query state
  const [filters,     setFilters]     = useState<HuntFilter[]>([{ field: 'threat_score', operator: 'gte', value: '60' }])
  const [filterLogic, setFilterLogic] = useState<FilterLogic>('and')
  const [timeRange,   setTimeRange]   = useState('24h')
  const [mitreTactics, setMitreTactics] = useState<string[]>([])

  // Results state
  const [results,    setResults]    = useState<HuntResultEntry[]>([])
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [hasMore,    setHasMore]    = useState(false)
  const [total,      setTotal]      = useState<number | null>(null)
  const [isRunning,  setIsRunning]  = useState(false)
  const [isLoadMore, setIsLoadMore] = useState(false)
  const [runError,   setRunError]   = useState<string | null>(null)
  const [hasRun,     setHasRun]     = useState(false)

  // Saved hunts state
  const [savedHunts,    setSavedHunts]    = useState<SavedHunt[]>([])
  const [showSaveModal, setShowSaveModal] = useState(false)

  useEffect(() => {
    huntApi.listSaved()
      .then(data => setSavedHunts(Array.isArray(data) ? data : []))
      .catch(() => {})
  }, [])

  const buildQuery = (cursor?: string | null) => ({
    filters:      filters.filter(f => f.value.trim() !== ''),
    logic:        filterLogic,
    from_ts:      getFromTs(timeRange),
    to_ts:        null as null,
    mitre_tactics: mitreTactics,
    limit:        50,
    cursor:       cursor ?? null,
  })

  const handleRun = async () => {
    setIsRunning(true)
    setRunError(null)
    try {
      const res = await huntApi.run(buildQuery())
      setResults(res.entries)
      setNextCursor(res.next_cursor)
      setHasMore(res.has_more)
      setTotal(res.total)
      setHasRun(true)
    } catch (e) {
      setRunError(extractApiError(e))
    } finally {
      setIsRunning(false)
    }
  }

  const handleLoadMore = async () => {
    if (!nextCursor || isLoadMore) return
    setIsLoadMore(true)
    try {
      const res = await huntApi.run(buildQuery(nextCursor))
      setResults(prev => [...prev, ...res.entries])
      setNextCursor(res.next_cursor)
      setHasMore(res.has_more)
    } catch {
      // silently ignore load-more errors
    } finally {
      setIsLoadMore(false)
    }
  }

  const loadSavedHunt = (hunt: SavedHunt) => {
    const q = hunt.query_params as { filters?: HuntFilter[]; logic?: FilterLogic; mitre_tactics?: string[] }
    if (Array.isArray(q.filters))       setFilters(q.filters)
    if (q.logic === 'and' || q.logic === 'or') setFilterLogic(q.logic)
    if (Array.isArray(q.mitre_tactics)) setMitreTactics(q.mitre_tactics)
  }

  const handleSave = async (name: string, desc: string) => {
    const hunt = await huntApi.saveHunt({
      name,
      description: desc || undefined,
      query_params: buildQuery() as unknown as Record<string, unknown>,
    })
    setSavedHunts(prev => [hunt, ...prev])
  }

  const addFilter = () => setFilters(prev => [...prev, { field: 'threat_score', operator: 'gte' as const, value: '' }])
  const updateFilter = (i: number, f: HuntFilter) => setFilters(prev => prev.map((x, j) => j === i ? f : x))
  const removeFilter = (i: number) => setFilters(prev => prev.filter((_, j) => j !== i))

  return (
    <div style={{ display: 'flex', height: 'calc(100vh - 50px - 40px)', overflow: 'hidden', background: '#050505' }}>

      {/* ── Saved Hunts Sidebar ─────────────────────────────────────────── */}
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
            <Plus size={12} />
            Save Current
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
                cursor: 'pointer', transition: 'background 100ms',
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

      {/* ── Main Panel ──────────────────────────────────────────────────── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

        {/* Header */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '14px 24px', borderBottom: '1px solid rgba(255,255,255,0.06)', flexShrink: 0,
        }}>
          <div>
            <h1 style={{ fontSize: 18, fontWeight: 700, fontFamily: "'Space Grotesk', sans-serif", color: '#F5F7FA', margin: 0 }}>
              Threat Hunt
            </h1>
            <p style={{ fontSize: 12, color: '#5C6373', margin: '2px 0 0' }}>
              Query investigations to find adversary patterns
            </p>
          </div>
          <button onClick={handleRun} disabled={isRunning} style={{
            display: 'flex', alignItems: 'center', gap: 7,
            padding: '9px 18px', borderRadius: 8,
            background: isRunning ? 'rgba(59,130,246,0.4)' : '#3B82F6',
            border: 'none', color: '#fff', fontSize: 13, fontWeight: 600,
            cursor: isRunning ? 'default' : 'pointer', transition: 'background 150ms',
          }}>
            <Play size={14} />
            {isRunning ? 'Running...' : 'Run Hunt'}
          </button>
        </div>

        {/* Scrollable body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>

          {/* Query Builder Card */}
          <div style={{
            background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)',
            borderRadius: 10, padding: 16, marginBottom: 20,
          }}>
            <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 14 }}>
              Query Builder
            </div>

            {/* Filter rows */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 10 }}>
              {filters.map((filter, idx) => (
                <div key={idx}>
                  {idx > 0 && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                      <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.04)' }} />
                      <div style={{ display: 'flex', gap: 4 }}>
                        {(['and', 'or'] as FilterLogic[]).map(lg => (
                          <button key={lg} onClick={() => setFilterLogic(lg)} style={{
                            padding: '2px 10px', borderRadius: 4,
                            fontSize: 10, fontWeight: 700, cursor: 'pointer',
                            textTransform: 'uppercase', letterSpacing: '0.5px',
                            background: filterLogic === lg ? 'rgba(59,130,246,0.15)' : 'transparent',
                            border: `1px solid ${filterLogic === lg ? 'rgba(59,130,246,0.4)' : 'rgba(255,255,255,0.08)'}`,
                            color: filterLogic === lg ? '#60A5FA' : '#5C6373',
                          }}>{lg}</button>
                        ))}
                      </div>
                      <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.04)' }} />
                    </div>
                  )}
                  <FilterRow
                    filter={filter}
                    onChange={f => updateFilter(idx, f)}
                    onRemove={() => removeFilter(idx)}
                    canRemove={filters.length > 1}
                  />
                </div>
              ))}
            </div>

            {/* Add filter */}
            <button onClick={addFilter} style={{
              display: 'flex', alignItems: 'center', gap: 5,
              padding: '5px 10px', borderRadius: 6,
              background: 'transparent', border: '1px dashed rgba(255,255,255,0.1)',
              color: '#5C6373', fontSize: 11, fontWeight: 600, cursor: 'pointer', marginBottom: 16,
            }}>
              <Plus size={12} /> Add Filter
            </button>

            {/* Time Range + MITRE Tactic */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <div>
                <label style={{ display: 'block', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 6 }}>
                  Time Range
                </label>
                <select className="inp" style={{ width: '100%' }} value={timeRange} onChange={e => setTimeRange(e.target.value)}>
                  {TIME_RANGES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                </select>
              </div>
              <div>
                <label style={{ display: 'block', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 6 }}>
                  MITRE Tactic
                </label>
                <MitreTacticsDropdown selected={mitreTactics} onChange={setMitreTactics} />
              </div>
            </div>
          </div>

          {/* Error */}
          {runError && (
            <div style={{
              padding: '10px 14px', marginBottom: 16, borderRadius: 8,
              background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)',
              fontSize: 12, color: '#FCA5A5',
            }}>{runError}</div>
          )}

          {/* Empty pre-run state */}
          {!hasRun && !isRunning && (
            <div style={{ textAlign: 'center', padding: '64px 0', color: '#3A4150' }}>
              <Crosshair size={36} style={{ display: 'block', margin: '0 auto 12px', opacity: 0.15 }} />
              <div style={{ fontSize: 14, color: '#5C6373', marginBottom: 4 }}>
                Configure your query and click Run Hunt
              </div>
              <div style={{ fontSize: 12 }}>Results will appear here</div>
            </div>
          )}

          {/* Results */}
          {hasRun && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', marginBottom: 12 }}>
                <span style={{ fontSize: 13, fontWeight: 600, color: '#F5F7FA' }}>Results</span>
                {total !== null && (
                  <span style={{ fontSize: 11, color: '#5C6373', marginLeft: 8, fontWeight: 400 }}>
                    {total} investigation{total !== 1 ? 's' : ''}
                  </span>
                )}
              </div>

              {results.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '48px 0', color: '#3A4150', fontSize: 13 }}>
                  <Search size={28} style={{ display: 'block', margin: '0 auto 10px', opacity: 0.2 }} />
                  No investigations matched your query
                </div>
              ) : (
                <div style={{
                  background: 'rgba(255,255,255,0.01)', border: '1px solid rgba(255,255,255,0.06)',
                  borderRadius: 10, overflow: 'hidden',
                }}>
                  {/* Table header */}
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

                  {/* Rows */}
                  {results.map((entry, idx) => (
                    <ResultRow
                      key={entry.investigation_id}
                      entry={entry}
                      onClick={() => navigate(`/investigations/${entry.investigation_id}`)}
                      isLast={idx === results.length - 1 && !hasMore}
                    />
                  ))}

                  {/* Load More */}
                  {hasMore && (
                    <div style={{ padding: '12px 14px', borderTop: '1px solid rgba(255,255,255,0.04)' }}>
                      <button onClick={handleLoadMore} disabled={isLoadMore} style={{
                        display: 'block', width: '100%', padding: '8px',
                        borderRadius: 6, fontSize: 12, fontWeight: 600, textAlign: 'center',
                        background: isLoadMore ? 'rgba(255,255,255,0.03)' : 'rgba(255,255,255,0.04)',
                        border: '1px solid rgba(255,255,255,0.08)',
                        color: '#8B95A7', cursor: isLoadMore ? 'default' : 'pointer',
                      }}>
                        {isLoadMore ? 'Loading...' : 'Load More'}
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Save Modal */}
      {showSaveModal && (
        <SaveModal onSave={handleSave} onClose={() => setShowSaveModal(false)} />
      )}
    </div>
  )
}
