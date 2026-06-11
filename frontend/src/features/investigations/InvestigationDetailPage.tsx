import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { apiClient } from '@/api/client'
import { useAuthStore } from '@/stores/authStore'
import {
  ArrowLeft, LayoutDashboard, Clock, Share2, Paperclip,
  StickyNote, UserPlus, ChevronDown,
} from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { SevBadge } from '@/components/ui/SevBadge'
import { formatRelativeTime } from '@/lib/utils'
import {
  useInvDetail, useInvTimeline, useInvGraph,
  useInvEvidence, useInvNotes,
  useInvUpdateStatus, useInvCreateNote,
  type InvestigationDetail,
  type TimelineEntryOut,
  type GraphNodeOut, type GraphEdgeOut,
  type EvidenceOut, type NoteOut,
} from './hooks/useInvestigationDetail'
import { GraphView } from './components/graph/GraphView'

// ─── Helpers ──────────────────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 80) return '#EF4444'
  if (score >= 60) return '#F97316'
  if (score >= 30) return '#F59E0B'
  return '#10B981'
}

function sevColor(severity: number): string {
  if (severity >= 4) return '#EF4444'
  if (severity >= 3) return '#F97316'
  if (severity >= 2) return '#F59E0B'
  return '#3B82F6'
}

function timelineLabel(entry: TimelineEntryOut): string {
  const parts: string[] = []
  if (entry.process) parts.push(entry.process)
  parts.push(entry.action)
  if (entry.outcome && entry.outcome !== 'success') parts.push(`(${entry.outcome})`)
  return parts.join(' — ')
}

// ─── StatusDropdown ───────────────────────────────────────────────────────────

const STATUS_OPTIONS = [
  { value: 'new',            label: 'New',           color: '#9CA3AF' },
  { value: 'active',         label: 'Active',        color: '#60A5FA' },
  { value: 'triaged',        label: 'Triaged',       color: '#FCD34D' },
  { value: 'investigating',  label: 'Investigating',  color: '#34D399' },
  { value: 'contained',      label: 'Contained',     color: '#F97316' },
  { value: 'resolved',       label: 'Resolved',      color: '#10B981' },
  { value: 'closed',         label: 'Closed',        color: '#4B5563' },
  { value: 'false_positive', label: 'False Positive', color: '#F87171' },
]

function StatusDropdown({ current, onChange }: {
  current: string
  onChange: (s: string) => void
}) {
  const [open, setOpen] = useState(false)
  const opt = STATUS_OPTIONS.find(o => o.value === current) ?? { label: current, color: '#9CA3AF' }

  return (
    <div style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen(v => !v)}
        style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '5px 10px', borderRadius: 6, fontSize: 11,
          fontWeight: 600, cursor: 'pointer',
          background: 'rgba(255,255,255,0.04)',
          border: '1px solid rgba(255,255,255,0.08)',
          color: opt.color,
          fontFamily: "'JetBrains Mono', monospace",
        }}
      >
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: opt.color }} />
        {opt.label}
        <ChevronDown size={11} />
      </button>

      {open && (
        <>
          <div onClick={() => setOpen(false)} style={{ position: 'fixed', inset: 0, zIndex: 19 }} />
          <div style={{
            position: 'absolute', top: '100%', left: 0,
            marginTop: 4, background: '#111111',
            border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: 7, overflow: 'hidden',
            zIndex: 20, minWidth: 170,
            boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
          }}>
            {STATUS_OPTIONS.map(o => (
              <button
                key={o.value}
                onClick={() => { onChange(o.value); setOpen(false) }}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  width: '100%', padding: '8px 12px',
                  fontSize: 12, cursor: 'pointer',
                  background: current === o.value ? 'rgba(255,255,255,0.05)' : 'transparent',
                  border: 'none', color: o.color,
                  transition: 'background 120ms', textAlign: 'left',
                }}
              >
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: o.color, flexShrink: 0 }} />
                {o.label}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

// ─── EmptyTab ─────────────────────────────────────────────────────────────────

function EmptyTab({ icon: Icon, message, sub }: {
  icon: React.ElementType
  message: string
  sub: string
}) {
  return (
    <div style={{ textAlign: 'center', padding: '60px 0' }}>
      <Icon size={36} style={{ color: '#3A4150', display: 'block', margin: '0 auto 12px' }} />
      <div style={{ fontSize: 14, fontWeight: 600, color: '#5C6373', marginBottom: 6 }}>
        {message}
      </div>
      <div style={{ fontSize: 12, color: '#3A4150' }}>{sub}</div>
    </div>
  )
}

function TabSkeleton() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="skel" style={{ height: 60, borderRadius: 8 }} />
      ))}
    </div>
  )
}

// ─── OverviewTab ──────────────────────────────────────────────────────────────

function OverviewTab({ inv }: { inv: InvestigationDetail }) {
  const color = scoreColor(inv.threat_score)

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>

      {/* Threat score */}
      <div className="card" style={{ padding: 20 }}>
        <div style={{
          fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
          letterSpacing: '1.5px', color: '#5C6373', marginBottom: 12,
        }}>Threat Score</div>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
          <span style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 48, fontWeight: 700, color, lineHeight: 1,
          }}>
            {inv.threat_score}
          </span>
          <span style={{ fontSize: 14, color: '#5C6373' }}>/100</span>
        </div>
        <div style={{
          marginTop: 12, height: 4,
          background: 'rgba(255,255,255,0.06)',
          borderRadius: 2, overflow: 'hidden',
        }}>
          <div style={{
            height: '100%', width: `${inv.threat_score}%`,
            background: color, borderRadius: 2,
            boxShadow: `0 0 8px ${color}`,
            transition: 'width 600ms ease',
          }} />
        </div>
        <div style={{ marginTop: 6, fontSize: 11, color: '#5C6373', textTransform: 'capitalize' }}>
          {inv.confidence} confidence
        </div>
      </div>

      {/* Stats */}
      <div className="card" style={{ padding: 20 }}>
        <div style={{
          fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
          letterSpacing: '1.5px', color: '#5C6373', marginBottom: 12,
        }}>Case Info</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {[
            ['Verdict',  inv.verdict?.replace(/_/g, ' ') ?? 'Pending'],
            ['Notes',    String(inv.note_count)],
            ['Evidence', String(inv.evidence_count)],
            ['TP Prob',  `${(inv.tp_probability * 100).toFixed(0)}%`],
            ['FP Prob',  `${(inv.fp_probability * 100).toFixed(0)}%`],
          ].map(([label, value]) => (
            <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 10, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                {label}
              </span>
              <span style={{ fontSize: 11, color: '#B8C0CC', fontFamily: "'JetBrains Mono', monospace" }}>
                {value}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Executive summary */}
      {inv.executive_summary && (
        <div className="card" style={{ padding: 20, gridColumn: '1 / -1' }}>
          <div style={{
            fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
            letterSpacing: '1.5px', color: '#5C6373', marginBottom: 10,
          }}>Executive Summary</div>
          <p style={{ fontSize: 13, color: '#B8C0CC', lineHeight: 1.7, margin: 0 }}>
            {inv.executive_summary}
          </p>
        </div>
      )}

      {/* Technical summary */}
      {inv.technical_summary && (
        <div className="card" style={{ padding: 20, gridColumn: '1 / -1' }}>
          <div style={{
            fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
            letterSpacing: '1.5px', color: '#5C6373', marginBottom: 10,
          }}>Technical Summary</div>
          <p style={{
            fontSize: 12, color: '#8B95A7', lineHeight: 1.7, margin: 0,
            fontFamily: "'JetBrains Mono', monospace",
          }}>
            {inv.technical_summary}
          </p>
        </div>
      )}

      {/* Attack progression (used as MITRE context) */}
      {inv.attack_progression?.length > 0 && (
        <div className="card" style={{ padding: 20, gridColumn: '1 / -1' }}>
          <div style={{
            fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
            letterSpacing: '1.5px', color: '#5C6373', marginBottom: 12,
          }}>Attack Progression</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {inv.attack_progression.map((step, i) => (
              <span key={i} style={{
                padding: '3px 8px', borderRadius: 4,
                fontSize: 10, fontWeight: 600,
                fontFamily: "'JetBrains Mono', monospace",
                background: 'rgba(139,92,246,0.1)',
                color: '#C4B5FD',
                border: '1px solid rgba(139,92,246,0.2)',
              }}>
                {step}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Recommended actions */}
      {inv.recommended_actions?.length > 0 && (
        <div className="card" style={{ padding: 20, gridColumn: '1 / -1' }}>
          <div style={{
            fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
            letterSpacing: '1.5px', color: '#5C6373', marginBottom: 12,
          }}>Recommended Actions</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {inv.recommended_actions.map((action, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                <span style={{
                  width: 20, height: 20, borderRadius: '50%',
                  background: 'rgba(59,130,246,0.1)',
                  border: '1px solid rgba(59,130,246,0.2)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 9, fontWeight: 700, color: '#60A5FA',
                  flexShrink: 0, marginTop: 1,
                }}>
                  {i + 1}
                </span>
                <span style={{ fontSize: 12, color: '#B8C0CC', lineHeight: 1.6 }}>
                  {action}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── TimelineTab ──────────────────────────────────────────────────────────────

function TimelineTab({ id }: { id: string }) {
  const { data, isLoading } = useInvTimeline(id)
  const entries = data?.entries ?? []

  if (isLoading) return <TabSkeleton />
  if (entries.length === 0) return (
    <EmptyTab icon={Clock} message="No timeline events"
      sub="Events will appear as the investigation progresses" />
  )

  return (
    <div style={{ maxWidth: 720 }}>
      <div style={{ fontSize: 11, color: '#5C6373', marginBottom: 16 }}>
        {data?.total_events ?? entries.length} total events
      </div>
      {entries.map((entry, i) => {
        const isLast = i === entries.length - 1
        const color = sevColor(entry.severity)
        const ts = new Date(entry.timestamp * 1000)

        return (
          <div key={entry.event_id} style={{ display: 'flex', gap: 16, paddingBottom: isLast ? 0 : 20 }}>
            {/* Spine */}
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
              <div style={{
                width: 8, height: 8, borderRadius: '50%',
                background: color, boxShadow: `0 0 6px ${color}`,
                marginTop: 4, flexShrink: 0,
              }} />
              {!isLast && (
                <div style={{ width: 1, flex: 1, marginTop: 4, background: 'rgba(255,255,255,0.06)' }} />
              )}
            </div>

            {/* Content */}
            <div style={{ flex: 1, paddingBottom: isLast ? 0 : 4 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span style={{
                  fontSize: 10, color: '#5C6373',
                  fontFamily: "'JetBrains Mono', monospace",
                }}>
                  {ts.toLocaleTimeString('en-GB')}
                </span>
                <SevBadge sev={entry.severity} />
                <span style={{
                  fontSize: 10, color: '#5C6373',
                  textTransform: 'uppercase', letterSpacing: '0.05em',
                }}>
                  {entry.category}
                </span>
              </div>
              <div style={{ fontSize: 12, color: '#B8C0CC', marginBottom: 2 }}>
                {timelineLabel(entry)}
              </div>
              <div style={{ fontSize: 10, color: '#5C6373', fontFamily: "'JetBrains Mono', monospace" }}>
                {entry.hostname}
                {entry.username && <span style={{ marginLeft: 8, color: '#3A4150' }}>· {entry.username}</span>}
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ─── GraphTab ─────────────────────────────────────────────────────────────────

function GraphTab({ id }: { id: string }) {
  const { data, isLoading } = useInvGraph(id)

  if (isLoading) return <TabSkeleton />
  if (!data || data.node_count === 0) return (
    <EmptyTab icon={Share2} message="No graph data"
      sub="The attack graph will be generated as events are correlated" />
  )

  return (
    <div>
      <div style={{ fontSize: 11, color: '#5C6373', marginBottom: 12 }}>
        {data.node_count} nodes · {data.edge_count} connections · depth {data.max_depth}
      </div>
      <GraphView nodes={data.nodes as GraphNodeOut[]} edges={data.edges as GraphEdgeOut[]} />
    </div>
  )
}

// ─── EvidenceTab ──────────────────────────────────────────────────────────────

function EvidenceTab({ id }: { id: string }) {
  const { data, isLoading } = useInvEvidence(id)
  const items = data ?? []

  if (isLoading) return <TabSkeleton />
  if (items.length === 0) return (
    <EmptyTab icon={Paperclip} message="No evidence attached"
      sub="Evidence will be attached automatically as events are correlated" />
  )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {items.map((ev: EvidenceOut) => (
        <div key={ev.evidence_id} className="card" style={{ padding: '12px 16px' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#F5F7FA', marginBottom: 4 }}>
                {ev.title}
              </div>
              {ev.description && (
                <div style={{ fontSize: 11, color: '#8B95A7' }}>{ev.description}</div>
              )}
            </div>
            <span style={{
              fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
              letterSpacing: '0.08em', padding: '2px 7px', borderRadius: 4,
              background: 'rgba(255,255,255,0.06)', color: '#8B95A7', flexShrink: 0,
              fontFamily: "'JetBrains Mono', monospace",
            }}>
              {ev.evidence_type.replace(/_/g, ' ')}
            </span>
          </div>
          <div style={{ marginTop: 8, fontSize: 10, color: '#5C6373', fontFamily: "'JetBrains Mono', monospace" }}>
            {formatRelativeTime(ev.created_at)}
            {ev.reference_id && (
              <span style={{ marginLeft: 10, color: '#3A4150' }}>ref: {ev.reference_id.slice(0, 12)}</span>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

// ─── NotesTab ─────────────────────────────────────────────────────────────────

function NotesTab({ id }: { id: string }) {
  const { data: notes, isLoading } = useInvNotes(id)
  const createNote = useInvCreateNote(id)
  const [content, setContent] = useState('')

  const submit = async () => {
    if (!content.trim()) return
    await createNote.mutateAsync(content.trim())
    setContent('')
  }

  return (
    <div style={{ maxWidth: 680 }}>
      {/* Composer */}
      <div className="card" style={{ padding: 14, marginBottom: 16 }}>
        <textarea
          style={{
            width: '100%', background: 'transparent',
            border: 'none', outline: 'none',
            color: '#F5F7FA', fontSize: 13,
            fontFamily: "'Inter', sans-serif",
            resize: 'none', lineHeight: 1.6, minHeight: 80,
          }}
          placeholder="Add a note..."
          value={content}
          onChange={e => setContent(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) submit()
          }}
        />
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 8 }}>
          <span style={{ fontSize: 10, color: '#3A4150' }}>Ctrl+Enter to submit</span>
          <Button
            variant="primary" size="sm"
            disabled={!content.trim()}
            loading={createNote.isPending}
            onClick={submit}
          >
            Add Note
          </Button>
        </div>
      </div>

      {/* List */}
      {isLoading && <TabSkeleton />}
      {!isLoading && (notes ?? []).length === 0 && (
        <EmptyTab icon={StickyNote} message="No notes yet" sub="Add the first note above" />
      )}
      {!isLoading && (notes ?? []).map((note: NoteOut) => (
        <div key={note.note_id} className="card" style={{ padding: '14px 16px', marginBottom: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <div style={{
              width: 24, height: 24, borderRadius: '50%',
              background: 'linear-gradient(135deg, #2563EB, #38BDF8)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 9, fontWeight: 700, color: '#fff', flexShrink: 0,
            }}>
              {note.analyst_id?.[0]?.toUpperCase() ?? 'A'}
            </div>
            <span style={{ fontSize: 11, color: '#8B95A7' }}>
              {note.analyst_id?.slice(0, 8)}
            </span>
            {note.pinned && (
              <span style={{
                fontSize: 9, padding: '1px 5px', borderRadius: 3,
                background: 'rgba(59,130,246,0.1)', color: '#60A5FA',
                fontFamily: "'JetBrains Mono', monospace",
              }}>PINNED</span>
            )}
            <span style={{
              fontSize: 10, color: '#5C6373',
              fontFamily: "'JetBrains Mono', monospace", marginLeft: 'auto',
            }}>
              {formatRelativeTime(note.created_at)}
            </span>
          </div>
          <p style={{ fontSize: 13, color: '#B8C0CC', lineHeight: 1.6, margin: 0 }}>
            {note.content}
          </p>
        </div>
      ))}
    </div>
  )
}

// ─── Skeletons ────────────────────────────────────────────────────────────────

function DetailSkeleton() {
  return (
    <div className="page-in">
      <div className="skel" style={{ width: 300, height: 24, marginBottom: 16 }} />
      <div className="skel" style={{ width: 200, height: 16, marginBottom: 24 }} />
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        {[1, 2, 3, 4].map(i => (
          <div key={i} className="skel" style={{ height: 120, borderRadius: 8 }} />
        ))}
      </div>
    </div>
  )
}

// ─── InvestigationDetailPage ──────────────────────────────────────────────────

export function InvestigationDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState<
    'overview' | 'timeline' | 'graph' | 'evidence' | 'notes'
  >('overview')

  const { data: inv, isLoading } = useInvDetail(id ?? '')
  const updateStatus = useInvUpdateStatus(id ?? '')
  const currentUser = useAuthStore((s) => s.user)
  const [assigning, setAssigning] = useState(false)
  const [assignedLabel, setAssignedLabel] = useState(false)

  const handleAssign = async () => {
    if (!currentUser || assigning) return
    setAssigning(true)
    try {
      await apiClient.patch(`/investigations/${id}/assign`, { user_id: currentUser.id })
      setAssignedLabel(true)
      setTimeout(() => setAssignedLabel(false), 2000)
    } catch (err) {
      console.error(err)
    } finally {
      setAssigning(false)
    }
  }

  if (isLoading) return <DetailSkeleton />

  if (!inv) {
    return (
      <div className="page-in" style={{ textAlign: 'center', paddingTop: 80 }}>
        <div style={{ fontSize: 14, color: '#5C6373' }}>Investigation not found.</div>
        <Button variant="ghost" size="sm" style={{ marginTop: 12 }} onClick={() => navigate('/investigations')}>
          ← Back to Investigations
        </Button>
      </div>
    )
  }

  const color = scoreColor(inv.threat_score)
  const title = inv.title ?? `Investigation ${inv.investigation_id.slice(0, 8)}`

  const TABS = [
    { id: 'overview',  label: 'Overview',  icon: LayoutDashboard },
    { id: 'timeline',  label: 'Timeline',  icon: Clock           },
    { id: 'graph',     label: 'Graph',     icon: Share2          },
    { id: 'evidence',  label: 'Evidence',  icon: Paperclip       },
    { id: 'notes',     label: 'Notes',     icon: StickyNote      },
  ] as const

  return (
    <div
      className="page-in"
      style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 50px - 40px)', overflow: 'hidden' }}
    >

      {/* Header */}
      <div style={{
        paddingBottom: 12,
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        flexShrink: 0,
      }}>

        {/* Back + title + actions */}
        <div style={{
          display: 'flex', alignItems: 'flex-start',
          justifyContent: 'space-between', marginBottom: 10,
        }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
            <button
              onClick={() => navigate('/investigations')}
              style={{
                background: 'none', border: 'none',
                color: '#5C6373', cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: 4,
                fontSize: 12, marginTop: 3, padding: 0,
              }}
            >
              <ArrowLeft size={14} /> Back
            </button>
            <div>
              <h1 style={{
                fontSize: 16, fontWeight: 700,
                fontFamily: "'Space Grotesk', sans-serif",
                color: '#F5F7FA', marginBottom: 6,
              }}>
                {title}
              </h1>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span style={{
                  fontSize: 10, padding: '2px 7px', borderRadius: 4,
                  fontFamily: "'JetBrains Mono', monospace",
                  background: inv.source === 'manual' ? 'rgba(59,130,246,0.1)' : 'rgba(107,114,128,0.1)',
                  color: inv.source === 'manual' ? '#93C5FD' : '#9CA3AF',
                }}>
                  {inv.source === 'manual' ? 'MANUAL' : 'AUTO'}
                </span>
                <span style={{
                  fontSize: 11, fontFamily: "'JetBrains Mono', monospace",
                  color, fontWeight: 700,
                }}>
                  Score: {inv.threat_score}
                </span>
                <span style={{ fontSize: 11, color: '#5C6373' }}>
                  {formatRelativeTime(inv.created_at)}
                </span>
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
            <StatusDropdown
              current={inv.status}
              onChange={status => updateStatus.mutate(status)}
            />
            <Button variant="secondary" size="sm" onClick={handleAssign} disabled={assigning}>
              <UserPlus size={12} /> {assignedLabel ? 'Assigned to you' : 'Assign'}
            </Button>
          </div>
        </div>
      </div>

      {/* Tab bar */}
      <div style={{
        display: 'flex', gap: 0,
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        flexShrink: 0,
      }}>
        {TABS.map(tab => {
          const Icon = tab.icon
          const active = activeTab === tab.id
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '10px 16px', fontSize: 12, fontWeight: 500,
                cursor: 'pointer', background: 'none', border: 'none',
                borderBottom: `2px solid ${active ? '#3B82F6' : 'transparent'}`,
                color: active ? '#93C5FD' : '#5C6373',
                transition: 'all 120ms', marginBottom: -1,
              }}
            >
              <Icon size={13} />
              {tab.label}
            </button>
          )
        })}
      </div>

      {/* Tab content */}
      <div style={{ flex: 1, overflowY: 'auto', paddingTop: 16 }}>
        {activeTab === 'overview'  && <OverviewTab  inv={inv} />}
        {activeTab === 'timeline'  && <TimelineTab  id={id!} />}
        {activeTab === 'graph'     && <GraphTab     id={id!} />}
        {activeTab === 'evidence'  && <EvidenceTab  id={id!} />}
        {activeTab === 'notes'     && <NotesTab     id={id!} />}
      </div>
    </div>
  )
}
