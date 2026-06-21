import { useState, useEffect, useMemo } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { apiClient } from '@/api/client'
import { useAuthStore } from '@/stores/authStore'
import { formatDateTime } from '@/lib/timezone'
import {
  ArrowLeft, Clock, Share2, Paperclip,
  UserPlus, ChevronDown, Brain, ChevronRight, Copy, Check,
  BookOpen, Loader2, Shield, Terminal, Globe, Hash, LayoutDashboard,
  MessagesSquare, CheckCircle2, XCircle, SkipForward, Activity,
} from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { SevBadge } from '@/components/ui/SevBadge'
import { formatRelativeTime, extractApiError } from '@/lib/utils'
import { toastError, toastSuccess } from '@/lib/toast'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { playbooksApi } from '@/api/playbooks'
import type { Playbook, PlaybookStep } from '@/api/playbooks'
import {
  useInvDetail, useInvTimeline, useInvGraph,
  useInvEvidence, useInvNotes,
  useInvUpdateStatus, useInvCreateNote, useRunAIAnalysis, useInvSetVerdict,
  type InvestigationDetail, type AIAnalysis,
  type TimelineEntryOut,
  type GraphNodeOut, type GraphEdgeOut,
  type EvidenceOut, type NoteOut,
} from './hooks/useInvestigationDetail'
import { GraphView } from './components/graph/GraphView'

// ─── Helpers ──────────────────────────────────────────────────────────────────

function scoreColor(s: number) {
  return s >= 80 ? '#EF4444' : s >= 60 ? '#F97316' : s >= 30 ? '#F59E0B' : '#10B981'
}

function scoreLabel(s: number) {
  return s >= 80 ? 'CRITICAL' : s >= 60 ? 'HIGH' : s >= 30 ? 'MEDIUM' : 'LOW'
}

function sevColor(severity: number): string {
  if (severity >= 4) return '#EF4444'
  if (severity >= 3) return '#F97316'
  if (severity >= 2) return '#F59E0B'
  return '#3B82F6'
}

function processBasename(path: string): string {
  return path.split(/[\\/]/).pop() ?? path
}

function timelineLabel(entry: TimelineEntryOut): string {
  const parts: string[] = []
  if (entry.process) parts.push(processBasename(entry.process))
  parts.push(entry.action)
  if (entry.outcome && entry.outcome !== 'success') parts.push(`(${entry.outcome})`)
  return parts.join(' — ')
}

function caseId(id: string) {
  return `INC-${id.replace(/-/g, '').slice(0, 8).toUpperCase()}`
}

// ─── SLA Timer ────────────────────────────────────────────────────────────────

function useSLAElapsed(createdAt: string) {
  const [now, setNow] = useState(Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 60_000)
    return () => clearInterval(id)
  }, [])
  const ms  = now - new Date(createdAt).getTime()
  const h   = Math.floor(ms / 3_600_000)
  const m   = Math.floor((ms % 3_600_000) / 60_000)
  const str = h > 0 ? `${h}h ${m}m` : `${m}m`
  const col = ms > 28_800_000 ? '#EF4444' : ms > 14_400_000 ? '#F97316' : ms > 3_600_000 ? '#F59E0B' : '#10B981'
  return { str, col }
}

// ─── IOC Extraction ───────────────────────────────────────────────────────────

function extractIOCs(texts: (string | undefined | null)[]) {
  const text = texts.filter(Boolean).join(' ')
  const ips       = [...new Set(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [])].slice(0, 8)
  const processes = [...new Set((text.match(/\b[\w][\w.-]*\.exe\b/gi) ?? []).map(s => s.toLowerCase()))].slice(0, 6)
  const hashes    = [...new Set(text.match(/\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi) ?? [])].slice(0, 3)
  const domains   = [...new Set(
    (text.match(/\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|biz|top|xyz|gov|edu)\b/gi) ?? [])
      .map(d => d.toLowerCase())
      .filter(d => !d.endsWith('.exe') && !ips.some(ip => d.startsWith(ip)))
  )].slice(0, 5)
  return { ips, processes, hashes, domains }
}

// ─── Constants ────────────────────────────────────────────────────────────────

const VERDICT_OPTIONS = [
  { value: 'true_positive',   label: 'True Positive',  color: '#EF4444' },
  { value: 'false_positive',  label: 'False Positive', color: '#10B981' },
  { value: 'benign_positive', label: 'Benign',         color: '#60A5FA' },
  { value: 'suspicious',      label: 'Suspicious',     color: '#F59E0B' },
  { value: 'inconclusive',    label: 'Inconclusive',   color: '#6B7280' },
]

const STATUS_OPTIONS = [
  { value: 'new',            label: 'New',            color: '#9CA3AF' },
  { value: 'active',         label: 'Active',         color: '#60A5FA' },
  { value: 'triaged',        label: 'Triaged',        color: '#FCD34D' },
  { value: 'investigating',  label: 'Investigating',  color: '#34D399' },
  { value: 'contained',      label: 'Contained',      color: '#F97316' },
  { value: 'resolved',       label: 'Resolved',       color: '#10B981' },
  { value: 'closed',         label: 'Closed',         color: '#4B5563' },
  { value: 'false_positive', label: 'False Positive', color: '#F87171' },
]

const STATUS_PIPELINE = [
  { value: 'new',           label: 'New',          color: '#9CA3AF' },
  { value: 'triaged',       label: 'Triaged',      color: '#FCD34D' },
  { value: 'investigating', label: 'Investigating', color: '#34D399' },
  { value: 'contained',     label: 'Contained',    color: '#F97316' },
  { value: 'resolved',      label: 'Resolved',     color: '#10B981' },
]

const KILL_CHAIN_LABELS = ['Recon', 'Weapon.', 'Delivery', 'Exploit', 'Install', 'C2', 'Actions']

// ─── VerdictDropdown ──────────────────────────────────────────────────────────

function VerdictDropdown({ current, onSet }: { current: string | null; onSet: (v: string) => void }) {
  const [open, setOpen] = useState(false)
  const opt = VERDICT_OPTIONS.find(o => o.value === current)

  return (
    <div style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen(v => !v)}
        style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '4px 9px', borderRadius: 5, fontSize: 11, fontWeight: 600,
          cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace",
          background: opt ? `${opt.color}18` : 'rgba(255,255,255,0.04)',
          border: `1px solid ${opt ? `${opt.color}40` : 'rgba(255,255,255,0.08)'}`,
          color: opt ? opt.color : '#5C6373',
        }}
      >
        {opt && <span style={{ width: 5, height: 5, borderRadius: '50%', background: opt.color }} />}
        {opt?.label ?? 'Verdict'}
        <ChevronDown size={10} />
      </button>
      {open && (
        <>
          <div onClick={() => setOpen(false)} style={{ position: 'fixed', inset: 0, zIndex: 19 }} />
          <div style={{
            position: 'absolute', top: '100%', right: 0, marginTop: 4,
            background: '#111111', border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: 7, overflow: 'hidden', zIndex: 20, minWidth: 160,
            boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
          }}>
            {VERDICT_OPTIONS.map(o => (
              <button key={o.value} onClick={() => { onSet(o.value); setOpen(false) }} style={{
                display: 'flex', alignItems: 'center', gap: 8,
                width: '100%', padding: '8px 12px', fontSize: 12, cursor: 'pointer',
                background: current === o.value ? 'rgba(255,255,255,0.05)' : 'transparent',
                border: 'none', color: o.color, transition: 'background 120ms', textAlign: 'left',
              }}>
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

// ─── StatusDropdown ───────────────────────────────────────────────────────────

function StatusDropdown({ current, onChange }: { current: string; onChange: (s: string) => void }) {
  const [open, setOpen] = useState(false)
  const opt = STATUS_OPTIONS.find(o => o.value === current) ?? { label: current, color: '#9CA3AF' }

  return (
    <div style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen(v => !v)}
        style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '4px 9px', borderRadius: 5, fontSize: 11, fontWeight: 600,
          cursor: 'pointer', background: 'rgba(255,255,255,0.04)',
          border: '1px solid rgba(255,255,255,0.08)', color: opt.color,
          fontFamily: "'JetBrains Mono', monospace",
        }}
      >
        <span style={{ width: 5, height: 5, borderRadius: '50%', background: opt.color }} />
        {opt.label}
        <ChevronDown size={10} />
      </button>
      {open && (
        <>
          <div onClick={() => setOpen(false)} style={{ position: 'fixed', inset: 0, zIndex: 19 }} />
          <div style={{
            position: 'absolute', top: '100%', right: 0, marginTop: 4, background: '#111111',
            border: '1px solid rgba(255,255,255,0.1)', borderRadius: 7, overflow: 'hidden',
            zIndex: 20, minWidth: 170, boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
          }}>
            {STATUS_OPTIONS.map(o => (
              <button key={o.value} onClick={() => { onChange(o.value); setOpen(false) }} style={{
                display: 'flex', alignItems: 'center', gap: 8,
                width: '100%', padding: '8px 12px', fontSize: 12, cursor: 'pointer',
                background: current === o.value ? 'rgba(255,255,255,0.05)' : 'transparent',
                border: 'none', color: o.color, transition: 'background 120ms', textAlign: 'left',
              }}>
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

// ─── StatusPipeline ───────────────────────────────────────────────────────────

function StatusPipeline({ current }: { current: string }) {
  const idx = STATUS_PIPELINE.findIndex(s => s.value === current)
  const activeIdx = idx >= 0 ? idx : 0

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 0, height: 28 }}>
      {STATUS_PIPELINE.map((stage, i) => {
        const isPast    = i < activeIdx
        const isActive  = i === activeIdx
        const color     = isActive ? stage.color : isPast ? stage.color : '#2A3140'
        const textColor = isActive ? stage.color : isPast ? `${stage.color}99` : '#3A4150'

        return (
          <div key={stage.value} style={{ display: 'flex', alignItems: 'center', flex: 1 }}>
            <div style={{
              flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
              height: 24, position: 'relative',
              background: isActive ? `${color}20` : isPast ? `${color}0D` : 'rgba(255,255,255,0.02)',
              border: `1px solid ${isActive ? `${color}50` : isPast ? `${color}25` : 'rgba(255,255,255,0.05)'}`,
              borderRadius: i === 0 ? '4px 0 0 4px' : i === STATUS_PIPELINE.length - 1 ? '0 4px 4px 0' : 0,
              borderLeft: i > 0 ? 'none' : undefined,
            }}>
              <span style={{
                fontSize: 9, fontWeight: isActive ? 700 : 500,
                color: textColor, textTransform: 'uppercase',
                letterSpacing: '0.06em', fontFamily: "'JetBrains Mono', monospace",
              }}>
                {stage.label}
              </span>
              {isActive && (
                <span style={{
                  position: 'absolute', bottom: -1, left: '50%', transform: 'translateX(-50%)',
                  width: '60%', height: 2, background: color,
                  borderRadius: '1px 1px 0 0',
                }} />
              )}
            </div>
            {i < STATUS_PIPELINE.length - 1 && (
              <div style={{
                width: 0, height: 0,
                borderTop: '12px solid transparent',
                borderBottom: '12px solid transparent',
                borderLeft: `7px solid ${isPast ? `${color}25` : 'rgba(255,255,255,0.05)'}`,
                zIndex: 1, flexShrink: 0,
              }} />
            )}
          </div>
        )
      })}
    </div>
  )
}

// ─── ScorePanel ───────────────────────────────────────────────────────────────

function ScorePanel({ score, confidence }: { score: number; confidence: string }) {
  const color = scoreColor(score)
  const label = scoreLabel(score)
  const r = 42
  const circ = 2 * Math.PI * r
  const offset = circ * (1 - score / 100)

  return (
    <div style={{
      background: 'rgba(255,255,255,0.02)',
      border: '1px solid rgba(255,255,255,0.07)',
      borderRadius: 8, padding: '14px 16px', textAlign: 'center',
    }}>
      <div style={{
        fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
        letterSpacing: '1.5px', color: '#5C6373', marginBottom: 10,
      }}>Threat Score</div>
      <svg width={100} height={100} style={{ display: 'block', margin: '0 auto' }}>
        <circle cx={50} cy={50} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={7} />
        <circle
          cx={50} cy={50} r={r} fill="none"
          stroke={color} strokeWidth={7}
          strokeDasharray={circ}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 50 50)"
          style={{ filter: `drop-shadow(0 0 6px ${color}80)`, transition: 'stroke-dashoffset 800ms ease' }}
        />
        <text x={50} y={46} textAnchor="middle" dominantBaseline="middle"
          fill={color} fontSize={20} fontWeight={700}
          fontFamily="'JetBrains Mono', monospace">
          {score}
        </text>
        <text x={50} y={62} textAnchor="middle" dominantBaseline="middle"
          fill={color} fontSize={8} fontWeight={700}
          fontFamily="'JetBrains Mono', monospace" letterSpacing={1}>
          {label}
        </text>
      </svg>
      <div style={{ marginTop: 6, fontSize: 10, color: '#5C6373', textTransform: 'capitalize' }}>
        {confidence} confidence
      </div>
    </div>
  )
}

// ─── IOCPanel ─────────────────────────────────────────────────────────────────

function IOCPanel({ inv }: { inv: InvestigationDetail }) {
  const iocs = useMemo(() =>
    extractIOCs([inv.executive_summary, inv.technical_summary, inv.title]),
    [inv.executive_summary, inv.technical_summary, inv.title]
  )
  const hasAny = iocs.ips.length + iocs.processes.length + iocs.hashes.length + iocs.domains.length > 0

  if (!hasAny) return null

  const sections: { icon: React.ElementType; color: string; label: string; items: string[] }[] = [
    { icon: Globe,    color: '#EF4444', label: 'IPs',       items: iocs.ips },
    { icon: Terminal, color: '#F97316', label: 'Processes',  items: iocs.processes },
    { icon: Globe,    color: '#60A5FA', label: 'Domains',   items: iocs.domains },
    { icon: Hash,     color: '#A78BFA', label: 'Hashes',    items: iocs.hashes },
  ].filter(s => s.items.length > 0)

  return (
    <div style={{
      background: 'rgba(255,255,255,0.02)',
      border: '1px solid rgba(255,255,255,0.07)',
      borderRadius: 8, padding: '12px 14px',
    }}>
      <div style={{
        fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
        letterSpacing: '1.5px', color: '#5C6373', marginBottom: 10,
        display: 'flex', alignItems: 'center', gap: 6,
      }}>
        <Shield size={10} style={{ color: '#5C6373' }} />
        IOC Indicators
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {sections.map(({ icon: Icon, color, label, items }) => (
          <div key={label}>
            <div style={{
              fontSize: 9, color: '#5C6373', textTransform: 'uppercase',
              letterSpacing: '0.08em', marginBottom: 4,
              display: 'flex', alignItems: 'center', gap: 4,
            }}>
              <Icon size={9} style={{ color }} />
              {label}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {items.map(item => (
                <div key={item} style={{
                  fontSize: 10, color: '#B8C0CC', padding: '2px 6px',
                  background: `${color}0D`, borderRadius: 3,
                  border: `1px solid ${color}22`,
                  fontFamily: "'JetBrains Mono', monospace",
                  wordBreak: 'break-all', lineHeight: 1.4,
                }}>
                  {item.length > 28 ? item.slice(0, 12) + '…' + item.slice(-10) : item}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── MITREPanel ───────────────────────────────────────────────────────────────

function MITREPanel({ steps }: { steps: string[] }) {
  if (!steps?.length) return null
  return (
    <div style={{
      background: 'rgba(255,255,255,0.02)',
      border: '1px solid rgba(255,255,255,0.07)',
      borderRadius: 8, padding: '12px 14px',
    }}>
      <div style={{
        fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
        letterSpacing: '1.5px', color: '#5C6373', marginBottom: 10,
        display: 'flex', alignItems: 'center', gap: 6,
      }}>
        <Activity size={10} style={{ color: '#5C6373' }} />
        Attack Chain
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        {steps.map((step, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 7 }}>
            <div style={{
              width: 14, height: 14, borderRadius: '50%',
              background: 'rgba(139,92,246,0.15)',
              border: '1px solid rgba(139,92,246,0.3)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 8, fontWeight: 700, color: '#A78BFA',
              flexShrink: 0, marginTop: 1,
            }}>{i + 1}</div>
            <span style={{
              fontSize: 10, color: '#C4B5FD',
              fontFamily: "'JetBrains Mono', monospace",
              lineHeight: 1.5,
            }}>{step}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Left Sidebar ─────────────────────────────────────────────────────────────

function LeftSidebar({ inv }: { inv: InvestigationDetail }) {
  return (
    <div style={{
      width: 240, flexShrink: 0,
      display: 'flex', flexDirection: 'column', gap: 10,
      overflowY: 'auto', paddingRight: 2,
    }}>
      <ScorePanel score={inv.threat_score} confidence={inv.confidence} />
      <IOCPanel inv={inv} />
      <MITREPanel steps={inv.attack_progression} />

      {/* Case metadata */}
      <div style={{
        background: 'rgba(255,255,255,0.02)',
        border: '1px solid rgba(255,255,255,0.07)',
        borderRadius: 8, padding: '12px 14px',
      }}>
        <div style={{
          fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
          letterSpacing: '1.5px', color: '#5C6373', marginBottom: 10,
        }}>Case Info</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
          {[
            ['TP Prob',  `${(inv.tp_probability * 100).toFixed(0)}%`],
            ['FP Prob',  `${(inv.fp_probability * 100).toFixed(0)}%`],
            ['Notes',    String(inv.note_count)],
            ['Evidence', String(inv.evidence_count)],
            ['Verdict',  inv.verdict?.replace(/_/g, ' ') ?? 'Pending'],
          ].map(([label, value]) => (
            <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 10, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                {label}
              </span>
              <span style={{ fontSize: 10, color: '#B8C0CC', fontFamily: "'JetBrains Mono', monospace" }}>
                {value}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── EmptyTab ─────────────────────────────────────────────────────────────────

function EmptyTab({ icon: Icon, message, sub }: {
  icon: React.ElementType; message: string; sub: string
}) {
  return (
    <div style={{ textAlign: 'center', padding: '60px 0' }}>
      <Icon size={36} style={{ color: '#3A4150', display: 'block', margin: '0 auto 12px' }} />
      <div style={{ fontSize: 14, fontWeight: 600, color: '#5C6373', marginBottom: 6 }}>{message}</div>
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

// ─── WarRoomTab ───────────────────────────────────────────────────────────────

type FeedItem =
  | { kind: 'note';   ts: number; note: NoteOut }
  | { kind: 'event';  ts: number; entry: TimelineEntryOut }
  | { kind: 'system'; ts: number; msg: string; color: string }

function WarRoomTab({ id, inv }: { id: string; inv: InvestigationDetail }) {
  const { data: notesData,    isLoading: notesLoading }    = useInvNotes(id)
  const { data: timelineData, isLoading: timelineLoading } = useInvTimeline(id)
  const createNote = useInvCreateNote(id)
  const [content, setContent] = useState('')

  const notes    = notesData ?? []
  const timeline = timelineData?.entries ?? []

  const feed = useMemo<FeedItem[]>(() => {
    const items: FeedItem[] = []

    // System: investigation created
    items.push({
      kind: 'system',
      ts: new Date(inv.created_at).getTime(),
      msg: `Investigation created — ${inv.source === 'manual' ? 'manually opened' : 'auto-correlated from alerts'}`,
      color: '#60A5FA',
    })

    // System: AI analysis ran
    if (inv.ai_analysis_json) {
      items.push({
        kind: 'system',
        ts: new Date(inv.updated_at).getTime(),
        msg: `AI analysis completed — verdict suggestion: ${inv.ai_analysis_json.verdict_suggestion?.replace(/_/g, ' ')}`,
        color: '#818CF8',
      })
    }

    for (const note of notes) {
      items.push({ kind: 'note', ts: new Date(note.created_at).getTime(), note })
    }

    // Include key timeline events (limit to 15 most severe)
    const sorted = [...timeline].sort((a, b) => b.severity - a.severity).slice(0, 15)
    for (const entry of sorted) {
      items.push({ kind: 'event', ts: entry.timestamp * 1000, entry })
    }

    return items.sort((a, b) => b.ts - a.ts)
  }, [notes, timeline, inv])

  const submit = async () => {
    if (!content.trim()) return
    await createNote.mutateAsync(content.trim())
    setContent('')
  }

  const isLoading = notesLoading || timelineLoading

  return (
    <div style={{ maxWidth: 760 }}>
      {/* Note composer */}
      <div style={{
        background: 'rgba(255,255,255,0.02)',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: 8, padding: 14, marginBottom: 16,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
          <MessagesSquare size={13} style={{ color: '#5C6373' }} />
          <span style={{ fontSize: 11, fontWeight: 600, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Add to War Room
          </span>
        </div>
        <textarea
          style={{
            width: '100%', background: 'transparent', border: 'none', outline: 'none',
            color: '#F5F7FA', fontSize: 13, fontFamily: "'Inter', sans-serif",
            resize: 'none', lineHeight: 1.6, minHeight: 68, boxSizing: 'border-box',
          }}
          placeholder="Post a note, observation, or action taken..."
          value={content}
          onChange={e => setContent(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) submit() }}
        />
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 8 }}>
          <span style={{ fontSize: 10, color: '#3A4150' }}>Ctrl+Enter to post</span>
          <Button variant="primary" size="sm" disabled={!content.trim()} loading={createNote.isPending} onClick={submit}>
            Post
          </Button>
        </div>
      </div>

      {/* Feed */}
      {isLoading && <TabSkeleton />}
      {!isLoading && feed.map((item, i) => {
        if (item.kind === 'note') {
          const note = item.note
          return (
            <div key={`note-${note.note_id}`} style={{ display: 'flex', gap: 12, marginBottom: 12 }}>
              <div style={{
                width: 28, height: 28, borderRadius: '50%',
                background: 'linear-gradient(135deg, #2563EB, #38BDF8)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 9, fontWeight: 700, color: '#fff', flexShrink: 0, marginTop: 2,
              }}>
                {note.analyst_name
                  ? note.analyst_name.split(' ').map((w: string) => w[0]).join('').toUpperCase().slice(0, 2)
                  : (note.analyst_id?.[0]?.toUpperCase() ?? 'A')}
              </div>
              <div style={{ flex: 1 }}>
                <div style={{
                  background: 'rgba(59,130,246,0.06)',
                  border: '1px solid rgba(59,130,246,0.15)',
                  borderRadius: '0 8px 8px 8px', padding: '10px 14px',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                    <span style={{ fontSize: 11, fontWeight: 600, color: '#93C5FD' }}>
                      {note.analyst_name ?? note.analyst_id?.slice(0, 8)}
                    </span>
                    {note.pinned && (
                      <span style={{
                        fontSize: 9, padding: '1px 5px', borderRadius: 3,
                        background: 'rgba(59,130,246,0.1)', color: '#60A5FA',
                        fontFamily: "'JetBrains Mono', monospace",
                      }}>PINNED</span>
                    )}
                    <span style={{ fontSize: 10, color: '#5C6373', marginLeft: 'auto', fontFamily: "'JetBrains Mono', monospace" }}>
                      {formatRelativeTime(note.created_at)}
                    </span>
                  </div>
                  <p style={{ fontSize: 13, color: '#D1D9E6', lineHeight: 1.65, margin: 0 }}>{note.content}</p>
                </div>
              </div>
            </div>
          )
        }

        if (item.kind === 'event') {
          const entry = item.entry
          const evColor = sevColor(entry.severity)
          return (
            <div key={`ev-${entry.event_id}`} style={{ display: 'flex', gap: 12, marginBottom: 10 }}>
              <div style={{
                width: 28, height: 28, borderRadius: '50%',
                background: `${evColor}15`, border: `1px solid ${evColor}40`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexShrink: 0, marginTop: 2,
              }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: evColor }} />
              </div>
              <div style={{ flex: 1, paddingTop: 4 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                  <SevBadge sev={entry.severity} />
                  <span style={{
                    fontSize: 9, color: '#5C6373', textTransform: 'uppercase',
                    letterSpacing: '0.05em',
                  }}>{entry.category}</span>
                  <span style={{ fontSize: 10, color: '#5C6373', marginLeft: 'auto', fontFamily: "'JetBrains Mono', monospace" }}>
                    {formatDateTime(new Date(entry.timestamp * 1000).toISOString())}
                  </span>
                </div>
                <div style={{ fontSize: 12, color: '#B8C0CC' }}>{timelineLabel(entry)}</div>
                <div style={{ fontSize: 10, color: '#5C6373', fontFamily: "'JetBrains Mono', monospace", marginTop: 2 }}>
                  {entry.hostname}
                  {entry.username && <span style={{ marginLeft: 6, color: '#3A4150' }}>· {entry.username}</span>}
                </div>
              </div>
            </div>
          )
        }

        // system
        return (
          <div key={`sys-${i}`} style={{ display: 'flex', gap: 12, marginBottom: 10 }}>
            <div style={{
              width: 28, height: 28, borderRadius: '50%',
              background: `${item.color}10`, border: `1px solid ${item.color}25`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              flexShrink: 0, marginTop: 2,
            }}>
              <span style={{ width: 5, height: 5, borderRadius: '50%', background: item.color }} />
            </div>
            <div style={{ flex: 1, paddingTop: 8 }}>
              <span style={{ fontSize: 11, color: '#5C6373', fontStyle: 'italic' }}>{item.msg}</span>
              <span style={{
                fontSize: 10, color: '#3A4150', marginLeft: 10,
                fontFamily: "'JetBrains Mono', monospace",
              }}>
                {formatRelativeTime(new Date(item.ts).toISOString())}
              </span>
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ─── PlaybookTab ──────────────────────────────────────────────────────────────

const STEP_STATUS_CONFIG: Record<PlaybookStep['status'], { icon: React.ElementType; color: string; label: string }> = {
  pending:     { icon: Clock,         color: '#5C6373', label: 'Pending'     },
  in_progress: { icon: Loader2,       color: '#60A5FA', label: 'In Progress' },
  completed:   { icon: CheckCircle2,  color: '#10B981', label: 'Done'        },
  skipped:     { icon: SkipForward,   color: '#F59E0B', label: 'Skipped'     },
  failed:      { icon: XCircle,       color: '#EF4444', label: 'Failed'      },
}

function PlaybookTab({ playbook }: { playbook: Playbook }) {
  const qc = useQueryClient()
  const { data: full, isLoading } = useQuery({
    queryKey: ['playbook', playbook.id],
    queryFn: () => playbooksApi.get(playbook.id),
    staleTime: 30_000,
  })
  const steps = full?.steps ?? []
  const done  = steps.filter(s => s.status === 'completed').length
  const pct   = steps.length > 0 ? (done / steps.length) * 100 : 0

  const [completing, setCompleting] = useState<string | null>(null)

  const handleComplete = async (step: PlaybookStep) => {
    setCompleting(step.id)
    try {
      await playbooksApi.completeStep(playbook.id, step.id, {})
      qc.invalidateQueries({ queryKey: ['playbook', playbook.id] })
    } finally {
      setCompleting(null)
    }
  }

  if (isLoading) return <TabSkeleton />

  return (
    <div style={{ maxWidth: 720 }}>
      {/* Header */}
      <div style={{
        background: 'rgba(255,255,255,0.02)',
        border: '1px solid rgba(255,255,255,0.07)',
        borderRadius: 8, padding: '14px 16px', marginBottom: 14,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#F5F7FA', marginBottom: 3 }}>
              {playbook.title}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{
                fontSize: 9, padding: '1px 6px', borderRadius: 3, fontWeight: 700,
                fontFamily: "'JetBrains Mono', monospace", textTransform: 'uppercase',
                background: playbook.created_by_id === null ? 'rgba(139,92,246,0.15)' : 'rgba(59,130,246,0.15)',
                color: playbook.created_by_id === null ? '#A78BFA' : '#93C5FD',
              }}>
                {playbook.created_by_id === null ? 'AUTO' : 'MANUAL'}
              </span>
              <span style={{ fontSize: 10, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                {playbook.severity} · {playbook.status.replace(/_/g, ' ')}
              </span>
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: 18, fontWeight: 700, color: pct === 100 ? '#10B981' : '#F5F7FA', fontFamily: "'JetBrains Mono', monospace" }}>
              {done}/{steps.length}
            </div>
            <div style={{ fontSize: 10, color: '#5C6373' }}>steps complete</div>
          </div>
        </div>
        {/* Progress bar */}
        <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2, overflow: 'hidden' }}>
          <div style={{
            height: '100%', width: `${pct}%`,
            background: pct === 100 ? '#10B981' : '#3B82F6',
            borderRadius: 2, transition: 'width 400ms ease',
            boxShadow: pct > 0 ? `0 0 8px ${pct === 100 ? '#10B98180' : '#3B82F680'}` : 'none',
          }} />
        </div>
      </div>

      {/* Steps */}
      {steps.length === 0 && (
        <EmptyTab icon={BookOpen} message="No steps" sub="This playbook has no steps defined." />
      )}
      {steps.sort((a, b) => a.step_order - b.step_order).map((step, i) => {
        const cfg = STEP_STATUS_CONFIG[step.status]
        const Icon = cfg.icon
        const isLast = i === steps.length - 1
        return (
          <div key={step.id} style={{ display: 'flex', gap: 14, paddingBottom: isLast ? 0 : 16 }}>
            {/* Spine */}
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
              <div style={{
                width: 28, height: 28, borderRadius: '50%',
                background: step.status === 'completed' ? `${cfg.color}20` : 'rgba(255,255,255,0.04)',
                border: `1.5px solid ${step.status === 'pending' ? 'rgba(255,255,255,0.08)' : cfg.color + '50'}`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexShrink: 0,
              }}>
                <Icon size={13} style={{
                  color: cfg.color,
                  animation: step.status === 'in_progress' ? 'spin 1s linear infinite' : 'none',
                }} />
              </div>
              {!isLast && (
                <div style={{ width: 1, flex: 1, marginTop: 4, background: 'rgba(255,255,255,0.05)' }} />
              )}
            </div>

            {/* Content */}
            <div style={{ flex: 1, paddingBottom: isLast ? 0 : 4 }}>
              <div style={{
                background: 'rgba(255,255,255,0.02)',
                border: `1px solid ${step.status === 'completed' ? 'rgba(16,185,129,0.15)' : 'rgba(255,255,255,0.06)'}`,
                borderRadius: 7, padding: '10px 13px',
              }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 10 }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 4 }}>
                      <span style={{
                        fontSize: 9, padding: '1px 5px', borderRadius: 3,
                        background: 'rgba(255,255,255,0.05)', color: '#5C6373',
                        fontFamily: "'JetBrains Mono', monospace", textTransform: 'uppercase',
                      }}>{step.category}</span>
                      <span style={{ fontSize: 9, color: cfg.color, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        {cfg.label}
                      </span>
                    </div>
                    <div style={{ fontSize: 12, fontWeight: 600, color: step.status === 'completed' ? '#5C6373' : '#F5F7FA', marginBottom: 4 }}>
                      {step.title}
                    </div>
                    <div style={{ fontSize: 11, color: '#8B95A7', lineHeight: 1.6 }}>
                      {step.description}
                    </div>
                    {step.notes && (
                      <div style={{ marginTop: 7, fontSize: 11, color: '#60A5FA', fontStyle: 'italic' }}>
                        Note: {step.notes}
                      </div>
                    )}
                  </div>
                  {step.status === 'pending' && (
                    <Button
                      variant="ghost" size="sm"
                      loading={completing === step.id}
                      onClick={() => handleComplete(step)}
                      style={{ flexShrink: 0, marginTop: 2 }}
                    >
                      <CheckCircle2 size={11} /> Done
                    </Button>
                  )}
                </div>
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ─── SummaryTab ───────────────────────────────────────────────────────────────

function SummaryTab({ inv }: { inv: InvestigationDetail }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, maxWidth: 800 }}>
      {inv.executive_summary && (
        <div style={{
          background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)',
          borderRadius: 8, padding: '16px 18px',
        }}>
          <div style={{
            fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
            letterSpacing: '1.5px', color: '#5C6373', marginBottom: 10,
          }}>Executive Summary</div>
          <p style={{ fontSize: 13, color: '#B8C0CC', lineHeight: 1.75, margin: 0 }}>{inv.executive_summary}</p>
        </div>
      )}

      {inv.technical_summary && (
        <div style={{
          background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)',
          borderRadius: 8, padding: '16px 18px',
        }}>
          <div style={{
            fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
            letterSpacing: '1.5px', color: '#5C6373', marginBottom: 10,
          }}>Technical Summary</div>
          <p style={{
            fontSize: 12, color: '#8B95A7', lineHeight: 1.75, margin: 0,
            fontFamily: "'JetBrains Mono', monospace",
          }}>{inv.technical_summary}</p>
        </div>
      )}

      {inv.attack_progression?.length > 0 && (
        <div style={{
          background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)',
          borderRadius: 8, padding: '16px 18px',
        }}>
          <div style={{
            fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
            letterSpacing: '1.5px', color: '#5C6373', marginBottom: 12,
          }}>Attack Progression</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {inv.attack_progression.map((step, i) => (
              <span key={i} style={{
                padding: '3px 8px', borderRadius: 4, fontSize: 10, fontWeight: 600,
                fontFamily: "'JetBrains Mono', monospace",
                background: 'rgba(139,92,246,0.1)', color: '#C4B5FD',
                border: '1px solid rgba(139,92,246,0.2)',
              }}>{step}</span>
            ))}
          </div>
        </div>
      )}

      {inv.recommended_actions?.length > 0 && (
        <div style={{
          background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)',
          borderRadius: 8, padding: '16px 18px',
        }}>
          <div style={{
            fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
            letterSpacing: '1.5px', color: '#5C6373', marginBottom: 12,
          }}>Recommended Actions</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {inv.recommended_actions.map((action, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                <span style={{
                  width: 20, height: 20, borderRadius: '50%',
                  background: 'rgba(59,130,246,0.1)', border: '1px solid rgba(59,130,246,0.2)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 9, fontWeight: 700, color: '#60A5FA', flexShrink: 0, marginTop: 1,
                }}>{i + 1}</span>
                <span style={{ fontSize: 12, color: '#B8C0CC', lineHeight: 1.65 }}>{action}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {!inv.executive_summary && !inv.technical_summary && (
        <EmptyTab icon={LayoutDashboard} message="No summary available" sub="AI analysis will populate this section." />
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
        const tsIso = new Date(entry.timestamp * 1000).toISOString()
        return (
          <div key={entry.event_id} style={{ display: 'flex', gap: 16, paddingBottom: isLast ? 0 : 20 }}>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
              <div style={{
                width: 8, height: 8, borderRadius: '50%',
                background: color, boxShadow: `0 0 6px ${color}`,
                marginTop: 4, flexShrink: 0,
              }} />
              {!isLast && <div style={{ width: 1, flex: 1, marginTop: 4, background: 'rgba(255,255,255,0.06)' }} />}
            </div>
            <div style={{ flex: 1, paddingBottom: isLast ? 0 : 4 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span style={{ fontSize: 10, color: '#5C6373', fontFamily: "'JetBrains Mono', monospace" }}>
                  {formatDateTime(tsIso)}
                </span>
                <SevBadge sev={entry.severity} />
                <span style={{ fontSize: 10, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  {entry.category}
                </span>
              </div>
              <div style={{ fontSize: 12, color: '#B8C0CC', marginBottom: 2 }}>{timelineLabel(entry)}</div>
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
        <div key={ev.evidence_id} style={{
          background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)',
          borderRadius: 8, padding: '12px 16px',
        }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#F5F7FA', marginBottom: 4 }}>{ev.title}</div>
              {ev.description && <div style={{ fontSize: 11, color: '#8B95A7' }}>{ev.description}</div>}
            </div>
            <span style={{
              fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
              letterSpacing: '0.08em', padding: '2px 7px', borderRadius: 4,
              background: 'rgba(255,255,255,0.06)', color: '#8B95A7', flexShrink: 0,
              fontFamily: "'JetBrains Mono', monospace",
            }}>{ev.evidence_type.replace(/_/g, ' ')}</span>
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

// ─── AIAnalysisTab ────────────────────────────────────────────────────────────

function KillChainBar({ index }: { index: number }) {
  return (
    <div style={{ display: 'flex', gap: 3, alignItems: 'center' }}>
      {KILL_CHAIN_LABELS.map((label, i) => {
        const isPast    = i < index
        const isCurrent = i === index
        const color     = isCurrent ? '#EF4444' : isPast ? '#F97316' : '#3A4150'
        return (
          <div key={i} style={{ flex: 1, textAlign: 'center' }}>
            <div style={{
              height: 6, borderRadius: 3, background: color,
              boxShadow: isCurrent ? `0 0 8px ${color}` : 'none', marginBottom: 5,
            }} />
            <div style={{
              fontSize: 8, fontWeight: isCurrent ? 700 : 500,
              color: isCurrent ? '#F5F7FA' : isPast ? '#8B95A7' : '#3A4150',
              fontFamily: "'JetBrains Mono', monospace",
              textTransform: 'uppercase', letterSpacing: '0.3px',
            }}>{label}</div>
          </div>
        )
      })}
    </div>
  )
}

function VerdictCard({ analysis }: { analysis: AIAnalysis }) {
  const { verdict_suggestion: v, verdict_confidence: conf } = analysis
  const cfg = v === 'true_positive'
    ? { label: 'True Positive',       color: '#EF4444' }
    : v === 'false_positive'
    ? { label: 'False Positive',      color: '#10B981' }
    : { label: 'Needs Investigation', color: '#F59E0B' }
  const pct = Math.round(conf * 100)
  return (
    <div style={{
      padding: '14px 16px', borderRadius: 8,
      border: `1px solid ${cfg.color}40`, background: `${cfg.color}0A`,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: cfg.color, boxShadow: `0 0 6px ${cfg.color}` }} />
        <span style={{ fontSize: 13, fontWeight: 700, color: cfg.color }}>{cfg.label}</span>
      </div>
      <div style={{ fontSize: 11, color: '#8B95A7', marginBottom: 6 }}>
        Confidence: <span style={{ color: '#F5F7FA', fontWeight: 600 }}>{pct}%</span>
      </div>
      <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, borderRadius: 2, background: cfg.color, transition: 'width 600ms ease' }} />
      </div>
    </div>
  )
}

function CopyableAction({ text, index }: { text: string; index: number }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) })
  }
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
      <span style={{
        width: 20, height: 20, borderRadius: '50%',
        background: 'rgba(59,130,246,0.1)', border: '1px solid rgba(59,130,246,0.2)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: 9, fontWeight: 700, color: '#60A5FA', flexShrink: 0, marginTop: 1,
      }}>{index + 1}</span>
      <span style={{ flex: 1, fontSize: 12, color: '#B8C0CC', lineHeight: 1.6 }}>{text}</span>
      <button onClick={copy} style={{
        background: 'none', border: 'none', cursor: 'pointer',
        color: copied ? '#10B981' : '#3A4150', padding: '2px 4px', flexShrink: 0,
      }}>
        {copied ? <Check size={12} /> : <Copy size={12} />}
      </button>
    </div>
  )
}

function EvidencePill({ text }: { text: string }) {
  return (
    <div style={{
      fontSize: 11, color: '#B8C0CC', padding: '5px 10px',
      background: 'rgba(255,255,255,0.03)', borderRadius: 5,
      border: '1px solid rgba(255,255,255,0.06)', lineHeight: 1.5,
    }}>{text}</div>
  )
}

function AIAnalysisTab({ inv, id }: { inv: InvestigationDetail; id: string }) {
  const runAnalysis = useRunAIAnalysis(id)
  const [narrativeOpen, setNarrativeOpen] = useState(false)
  const analysis = inv.ai_analysis_json

  if (runAnalysis.isPending) {
    return (
      <div style={{ textAlign: 'center', padding: '80px 0' }}>
        <div style={{
          width: 40, height: 40, borderRadius: '50%',
          border: '3px solid rgba(99,102,241,0.2)', borderTop: '3px solid #818CF8',
          margin: '0 auto 16px', animation: 'spin 1s linear infinite',
        }} />
        <div style={{ fontSize: 14, fontWeight: 600, color: '#5C6373' }}>Analyzing investigation...</div>
        <div style={{ fontSize: 12, color: '#3A4150', marginTop: 4 }}>This may take 10–30 seconds</div>
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      </div>
    )
  }

  if (!analysis) {
    return (
      <div style={{ textAlign: 'center', padding: '80px 0' }}>
        <div style={{
          width: 64, height: 64, borderRadius: '50%',
          background: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.2)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px',
        }}>
          <Brain size={28} style={{ color: '#818CF8' }} />
        </div>
        <div style={{ fontSize: 15, fontWeight: 700, color: '#5C6373', marginBottom: 6 }}>No AI Analysis Yet</div>
        <div style={{ fontSize: 12, color: '#3A4150', marginBottom: 24 }}>
          Automatically runs for HIGH/CRITICAL investigations
        </div>
        <Button variant="primary" size="sm" onClick={() => runAnalysis.mutate()}>
          <Brain size={13} /> Run AI Analysis
        </Button>
      </div>
    )
  }

  const actor = analysis.threat_actor_details
  const actorConf = Math.round((actor?.confidence ?? 0) * 100)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, maxWidth: 800 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Brain size={16} style={{ color: '#818CF8' }} />
          <span style={{ fontSize: 13, fontWeight: 700, color: '#F5F7FA' }}>AI Analysis</span>
          <span style={{
            fontSize: 9, padding: '1px 6px', borderRadius: 3,
            background: 'rgba(99,102,241,0.15)', color: '#818CF8',
            fontFamily: "'JetBrains Mono', monospace", fontWeight: 600,
          }}>{analysis.rag_sources_used?.length ?? 0} sources</span>
        </div>
        <Button variant="ghost" size="sm" onClick={() => runAnalysis.mutate()}>Re-analyze</Button>
      </div>

      <div style={{
        background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)',
        borderRadius: 8, padding: '14px 16px',
      }}>
        <div style={{
          fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
          letterSpacing: '1.5px', color: '#5C6373', marginBottom: 12,
        }}>Kill Chain Stage</div>
        <KillChainBar index={analysis.kill_chain_index ?? 3} />
        <div style={{ marginTop: 8, fontSize: 11, color: '#818CF8', fontWeight: 600 }}>{analysis.kill_chain_stage}</div>
      </div>

      <VerdictCard analysis={analysis} />

      <div style={{
        background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)',
        borderRadius: 8, padding: '14px 16px',
      }}>
        <div style={{
          fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
          letterSpacing: '1.5px', color: '#5C6373', marginBottom: 10,
        }}>Threat Actor Attribution</div>
        {analysis.threat_actor_attribution === 'Unknown' ? (
          <div style={{ fontSize: 12, color: '#5C6373' }}>No known threat actor match</div>
        ) : (
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#F5F7FA', marginBottom: 4 }}>
              Likely: {analysis.threat_actor_attribution}
              {actorConf > 0 && (
                <span style={{ marginLeft: 8, fontSize: 11, color: '#818CF8', fontWeight: 500 }}>({actorConf}% match)</span>
              )}
            </div>
            {actor?.matching_ttps?.length > 0 && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 6 }}>
                {actor.matching_ttps.map((ttp: string) => (
                  <span key={ttp} style={{
                    fontSize: 10, padding: '1px 6px', borderRadius: 3,
                    background: 'rgba(139,92,246,0.1)', color: '#C4B5FD',
                    border: '1px solid rgba(139,92,246,0.2)',
                    fontFamily: "'JetBrains Mono', monospace",
                  }}>{ttp}</span>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {analysis.executive_summary && (
        <div style={{
          background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)',
          borderRadius: 8, padding: '14px 16px',
        }}>
          <div style={{
            fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
            letterSpacing: '1.5px', color: '#5C6373', marginBottom: 10,
          }}>Executive Summary</div>
          <p style={{ fontSize: 13, color: '#B8C0CC', lineHeight: 1.7, margin: 0 }}>{analysis.executive_summary}</p>
        </div>
      )}

      {(() => {
        const ev = analysis.evidence_strength
        const hasEvidence = (ev?.strong?.length ?? 0) + (ev?.circumstantial?.length ?? 0) + (ev?.noise?.length ?? 0) > 0
        if (!hasEvidence) return null
        return (
          <div style={{
            background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)',
            borderRadius: 8, padding: '14px 16px',
          }}>
            <div style={{
              fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
              letterSpacing: '1.5px', color: '#5C6373', marginBottom: 12,
            }}>Evidence Strength</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
              {([
                { label: 'Strong',          color: '#EF4444', items: ev?.strong ?? []         },
                { label: 'Circumstantial',  color: '#F59E0B', items: ev?.circumstantial ?? [] },
                { label: 'Noise',           color: '#8B95A7', items: ev?.noise ?? []          },
              ] as const).map(({ label, color, items }) => (
                <div key={label}>
                  <div style={{ fontSize: 10, fontWeight: 700, color, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 5 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, display: 'inline-block' }} />
                    {label} ({items.length})
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {items.map((s: string, i: number) => <EvidencePill key={i} text={s} />)}
                    {items.length === 0 && <span style={{ fontSize: 11, color: '#3A4150' }}>None</span>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )
      })()}

      {analysis.recommended_actions?.length > 0 && (
        <div style={{
          background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)',
          borderRadius: 8, padding: '14px 16px',
        }}>
          <div style={{
            fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
            letterSpacing: '1.5px', color: '#5C6373', marginBottom: 12,
          }}>Recommended Actions</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {analysis.recommended_actions.map((action: string, i: number) => (
              <CopyableAction key={i} text={action} index={i} />
            ))}
          </div>
        </div>
      )}

      {analysis.attack_narrative && (
        <div style={{
          background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)',
          borderRadius: 8, padding: '14px 16px',
        }}>
          <button
            onClick={() => setNarrativeOpen(v => !v)}
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              width: '100%', background: 'none', border: 'none', cursor: 'pointer', padding: 0,
            }}
          >
            <div style={{
              fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
              letterSpacing: '1.5px', color: '#5C6373',
            }}>Attack Narrative</div>
            <ChevronRight size={14} style={{
              color: '#5C6373',
              transform: narrativeOpen ? 'rotate(90deg)' : 'rotate(0deg)',
              transition: 'transform 150ms',
            }} />
          </button>
          {narrativeOpen && (
            <p style={{
              fontSize: 12, color: '#8B95A7', lineHeight: 1.8, margin: '10px 0 0',
              fontFamily: "'JetBrains Mono', monospace",
            }}>{analysis.attack_narrative}</p>
          )}
        </div>
      )}

      {analysis.analyst_feedback && (
        <div style={{ fontSize: 11, color: '#5C6373', display: 'flex', alignItems: 'center', gap: 6 }}>
          <Check size={12} style={{ color: '#10B981' }} />
          Analyst feedback: {analysis.analyst_feedback.verdict?.replace(/_/g, ' ')}
          {analysis.analyst_feedback.agreed_with_ai !== null && (
            <span style={{ color: analysis.analyst_feedback.agreed_with_ai ? '#10B981' : '#F59E0B' }}>
              · {analysis.analyst_feedback.agreed_with_ai ? 'Agreed with AI' : 'Disagreed with AI'}
            </span>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Skeleton ─────────────────────────────────────────────────────────────────

function DetailSkeleton() {
  return (
    <div className="page-in">
      <div className="skel" style={{ width: 300, height: 24, marginBottom: 16 }} />
      <div className="skel" style={{ width: 200, height: 16, marginBottom: 24 }} />
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        {[1, 2, 3, 4].map(i => <div key={i} className="skel" style={{ height: 120, borderRadius: 8 }} />)}
      </div>
    </div>
  )
}

// ─── InvestigationDetailPage ──────────────────────────────────────────────────

type TabId = 'warroom' | 'summary' | 'ai_analysis' | 'timeline' | 'graph' | 'evidence' | 'playbook'

export function InvestigationDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState<TabId>('warroom')

  const { data: inv, isLoading } = useInvDetail(id ?? '')
  const updateStatus = useInvUpdateStatus(id ?? '')
  const setVerdict   = useInvSetVerdict(id ?? '')
  const currentUser  = useAuthStore((s) => s.user)
  const queryClient  = useQueryClient()
  const [assigning, setAssigning]       = useState(false)
  const [assignedLabel, setAssignedLabel] = useState(false)

  const { data: invPlaybooks, isLoading: playbooksLoading } = useQuery({
    queryKey: ['playbooks', 'investigation', id],
    queryFn:  () => playbooksApi.list({ investigation_id: id }),
    enabled:  !!id,
    staleTime: 30_000,
    refetchInterval: isLoading ? false : 15_000,
  })
  const linkedPlaybook = invPlaybooks?.[0] ?? null

  const sla = useSLAElapsed(inv?.created_at ?? new Date().toISOString())

  const handleAssign = async () => {
    if (!currentUser || assigning) return
    setAssigning(true)
    try {
      await apiClient.patch(`/investigations/${id}/assign`, { assigned_to: currentUser.id })
      setAssignedLabel(true)
      toastSuccess('Investigation assigned to you', 'Assigned')
      queryClient.invalidateQueries({ queryKey: ['inv-detail', id] })
      setTimeout(() => setAssignedLabel(false), 2000)
    } catch (err) {
      toastError(extractApiError(err), 'Assignment failed')
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
          ← Back
        </Button>
      </div>
    )
  }

  const color = scoreColor(inv.threat_score)
  const title = inv.title ?? `Investigation ${inv.investigation_id.slice(0, 8)}`

  const TABS: { id: TabId; label: string; icon: React.ElementType; badge?: boolean; disabled?: boolean }[] = [
    { id: 'warroom',     label: 'War Room',   icon: MessagesSquare                      },
    { id: 'summary',     label: 'Summary',    icon: LayoutDashboard                     },
    { id: 'ai_analysis', label: 'AI',         icon: Brain, badge: !!inv.ai_analysis_json },
    { id: 'timeline',    label: 'Timeline',   icon: Clock                               },
    { id: 'graph',       label: 'Graph',      icon: Share2                              },
    { id: 'evidence',    label: 'Evidence',   icon: Paperclip                           },
    { id: 'playbook',    label: 'Playbook',   icon: BookOpen, disabled: !linkedPlaybook  },
  ]

  return (
    <div
      className="page-in"
      style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 50px - 40px)', overflow: 'hidden', gap: 0 }}
    >
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>

      {/* ── Compact Header ── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '8px 0 10px', borderBottom: '1px solid rgba(255,255,255,0.06)',
        flexShrink: 0, flexWrap: 'wrap',
      }}>
        <button
          onClick={() => navigate('/investigations')}
          style={{
            background: 'none', border: 'none', color: '#5C6373', cursor: 'pointer',
            display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, padding: 0, flexShrink: 0,
          }}
        >
          <ArrowLeft size={14} />
        </button>

        <span style={{
          fontSize: 10, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace",
          color: '#5C6373', flexShrink: 0, letterSpacing: '0.04em',
        }}>
          {caseId(inv.investigation_id)}
        </span>

        <h1 style={{
          fontSize: 14, fontWeight: 700, color: '#F5F7FA',
          fontFamily: "'Space Grotesk', sans-serif",
          flex: 1, minWidth: 0, overflow: 'hidden',
          textOverflow: 'ellipsis', whiteSpace: 'nowrap', margin: 0,
        }}>
          {title}
        </h1>

        {/* Score pill */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0,
          padding: '3px 9px', borderRadius: 5,
          background: `${color}18`, border: `1px solid ${color}40`,
        }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: color, boxShadow: `0 0 4px ${color}` }} />
          <span style={{ fontSize: 11, fontWeight: 700, color, fontFamily: "'JetBrains Mono', monospace" }}>
            {inv.threat_score}
          </span>
          <span style={{ fontSize: 9, fontWeight: 700, color: `${color}CC`, textTransform: 'uppercase' }}>
            {scoreLabel(inv.threat_score)}
          </span>
        </div>

        {/* SLA timer */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0,
          padding: '3px 9px', borderRadius: 5,
          background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)',
        }}>
          <Clock size={11} style={{ color: sla.col }} />
          <span style={{ fontSize: 11, fontWeight: 600, color: sla.col, fontFamily: "'JetBrains Mono', monospace" }}>
            {sla.str}
          </span>
        </div>

        {/* Controls */}
        <div style={{ display: 'flex', gap: 5, flexShrink: 0, alignItems: 'center' }}>
          {playbooksLoading ? (
            <Loader2 size={11} style={{ color: '#5C6373', animation: 'spin 1s linear infinite' }} />
          ) : linkedPlaybook ? (
            <button
              onClick={() => setActiveTab('playbook')}
              style={{
                display: 'flex', alignItems: 'center', gap: 5,
                padding: '4px 9px', borderRadius: 5, fontSize: 11, fontWeight: 600,
                cursor: 'pointer', background: 'rgba(59,130,246,0.08)',
                border: '1px solid rgba(59,130,246,0.2)', color: '#93C5FD',
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              <BookOpen size={11} />
              Playbook
              <span style={{
                fontSize: 8, padding: '0 4px', borderRadius: 2, fontWeight: 700,
                background: linkedPlaybook.created_by_id === null ? 'rgba(139,92,246,0.2)' : 'rgba(59,130,246,0.2)',
                color: linkedPlaybook.created_by_id === null ? '#A78BFA' : '#93C5FD',
              }}>
                {linkedPlaybook.created_by_id === null ? 'AUTO' : 'MANUAL'}
              </span>
            </button>
          ) : null}
          <VerdictDropdown current={inv.verdict} onSet={v => setVerdict.mutate(v)} />
          <StatusDropdown current={inv.status} onChange={s => updateStatus.mutate(s)} />
          <Button variant="secondary" size="sm" onClick={handleAssign} disabled={assigning}>
            <UserPlus size={11} /> {assignedLabel ? 'Assigned' : 'Assign'}
          </Button>
        </div>
      </div>

      {/* ── Status Pipeline ── */}
      <div style={{ padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.05)', flexShrink: 0 }}>
        <StatusPipeline current={inv.status} />
      </div>

      {/* ── Body: sidebar + tabs ── */}
      <div style={{ flex: 1, display: 'flex', gap: 16, overflow: 'hidden', paddingTop: 14 }}>

        {/* Left sidebar */}
        <LeftSidebar inv={inv} />

        {/* Right: tab bar + content */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {/* Tab bar */}
          <div style={{
            display: 'flex', gap: 0, borderBottom: '1px solid rgba(255,255,255,0.06)',
            flexShrink: 0, overflowX: 'auto',
          }}>
            {TABS.map(tab => {
              const Icon = tab.icon
              const active = activeTab === tab.id
              return (
                <button
                  key={tab.id}
                  onClick={() => !tab.disabled && setActiveTab(tab.id)}
                  disabled={tab.disabled}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 5,
                    padding: '8px 14px', fontSize: 11, fontWeight: 500,
                    cursor: tab.disabled ? 'not-allowed' : 'pointer',
                    background: 'none', border: 'none',
                    borderBottom: `2px solid ${active ? '#3B82F6' : 'transparent'}`,
                    color: tab.disabled ? '#2A3140' : active ? '#93C5FD' : '#5C6373',
                    transition: 'all 120ms', marginBottom: -1, whiteSpace: 'nowrap',
                    opacity: tab.disabled ? 0.4 : 1,
                  }}
                >
                  <Icon size={12} />
                  {tab.label}
                  {tab.badge && (
                    <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#818CF8', flexShrink: 0 }} />
                  )}
                </button>
              )
            })}
          </div>

          {/* Tab content */}
          <div style={{ flex: 1, overflowY: 'auto', paddingTop: 14, paddingRight: 4 }}>
            {activeTab === 'warroom'     && <WarRoomTab     id={id!} inv={inv} />}
            {activeTab === 'summary'     && <SummaryTab     inv={inv} />}
            {activeTab === 'ai_analysis' && <AIAnalysisTab  inv={inv} id={id!} />}
            {activeTab === 'timeline'    && <TimelineTab    id={id!} />}
            {activeTab === 'graph'       && <GraphTab       id={inv.investigation_group_id} />}
            {activeTab === 'evidence'    && <EvidenceTab    id={id!} />}
            {activeTab === 'playbook'    && linkedPlaybook  && <PlaybookTab playbook={linkedPlaybook} />}
          </div>
        </div>
      </div>
    </div>
  )
}
