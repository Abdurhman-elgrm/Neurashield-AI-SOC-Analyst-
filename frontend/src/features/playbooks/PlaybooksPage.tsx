import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { BookOpen, Plus, ChevronRight, Zap, Clock, CheckCircle, XCircle, X } from 'lucide-react'
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

// ─── Generate Modal ───────────────────────────────────────────────────────────

function GenerateModal({ onClose, onGenerated }: { onClose: () => void; onGenerated: (id: string) => void }) {
  const [alertId, setAlertId] = useState('')
  const [tactic, setTactic] = useState('')
  const [technique, setTechnique] = useState('')
  const [severity, setSeverity] = useState('high')
  const [sourceHost, setSourceHost] = useState('')
  const [error, setError] = useState<string | null>(null)
  const qc = useQueryClient()

  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

  const generate = useMutation({
    mutationFn: () => {
      const trimmedAlertId = alertId.trim()
      if (trimmedAlertId && !UUID_RE.test(trimmedAlertId)) {
        throw new Error('Alert ID must be a valid UUID (e.g. 550e8400-e29b-41d4-a716-446655440000). Leave it empty to generate without an alert.')
      }
      return playbooksApi.generate({
        alert_id: trimmedAlertId || undefined,
        tactic: tactic || undefined,
        technique: technique || undefined,
        severity,
        source_host: sourceHost || undefined,
      })
    },
    onSuccess: (pb) => {
      qc.invalidateQueries({ queryKey: ['playbooks'] })
      onGenerated(pb.id)
    },
    onError: (err) => setError(extractApiError(err)),
  })

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 100,
      background: 'rgba(0,0,0,0.7)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        width: 460, background: '#111111',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: 12, padding: 24,
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: '#F5F7FA', fontFamily: "'Space Grotesk', sans-serif" }}>
            Generate Playbook
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#5C6373', cursor: 'pointer', padding: 4 }}>
            <X size={16} />
          </button>
        </div>

        <div style={{ display: 'grid', gap: 12 }}>
          <div>
            <label style={{ fontSize: 11, color: '#8B95A7', display: 'block', marginBottom: 5 }}>Alert ID (optional)</label>
            <input
              className="inp"
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              value={alertId}
              onChange={e => { setAlertId(e.target.value); setError(null) }}
            />
            <p style={{ fontSize: 10, color: '#3A4150', marginTop: 4 }}>
              Leave empty to generate manually using the fields below
            </p>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div>
              <label style={{ fontSize: 11, color: '#8B95A7', display: 'block', marginBottom: 5 }}>MITRE Tactic</label>
              <input
                className="inp"
                placeholder="e.g. TA0040"
                value={tactic}
                onChange={e => setTactic(e.target.value)}
              />
            </div>
            <div>
              <label style={{ fontSize: 11, color: '#8B95A7', display: 'block', marginBottom: 5 }}>MITRE Technique</label>
              <input
                className="inp"
                placeholder="e.g. T1486"
                value={technique}
                onChange={e => setTechnique(e.target.value)}
              />
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div>
              <label style={{ fontSize: 11, color: '#8B95A7', display: 'block', marginBottom: 5 }}>Severity</label>
              <select className="inp" value={severity} onChange={e => setSeverity(e.target.value)}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div>
              <label style={{ fontSize: 11, color: '#8B95A7', display: 'block', marginBottom: 5 }}>Source Host</label>
              <input
                className="inp"
                placeholder="hostname or IP"
                value={sourceHost}
                onChange={e => setSourceHost(e.target.value)}
              />
            </div>
          </div>
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
          >
            <Zap size={12} /> Generate
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── PlaybooksPage ────────────────────────────────────────────────────────────

export function PlaybooksPage() {
  const navigate = useNavigate()
  const [statusFilter, setStatusFilter] = useState('')
  const [showGenerate, setShowGenerate] = useState(false)

  const { data: playbooks = [], isLoading } = useQuery({
    queryKey: ['playbooks', statusFilter],
    queryFn: () => playbooksApi.list(statusFilter ? { status: statusFilter } : undefined),
    refetchInterval: 30_000,
  })

  const counts = {
    total:       playbooks.length,
    in_progress: playbooks.filter(p => p.status === 'in_progress').length,
    completed:   playbooks.filter(p => p.status === 'completed').length,
    draft:       playbooks.filter(p => p.status === 'draft').length,
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
          <Plus size={13} /> Generate Playbook
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
            <div style={{ fontSize: 20, fontWeight: 800, color, fontFamily: "'Space Grotesk', sans-serif" }}>
              {value}
            </div>
            <div style={{ fontSize: 10, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '1px', marginTop: 2 }}>
              {label}
            </div>
          </div>
        ))}
      </div>

      {/* Filter */}
      <div style={{
        display: 'flex', gap: 8, padding: '4px 0 8px',
        borderBottom: '1px solid rgba(255,255,255,0.04)',
        flexShrink: 0,
      }}>
        <select
          className="inp"
          style={{ width: 140 }}
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
        >
          <option value="">All Status</option>
          <option value="draft">Draft</option>
          <option value="in_progress">In Progress</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
          <option value="cancelled">Cancelled</option>
        </select>
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
        <span style={{ fontSize: 12, fontWeight: 600, color: '#F5F7FA' }}>
          {pb.title}
        </span>
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
