import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Play, CheckCircle, Circle, AlertCircle, ChevronDown, ChevronUp, Zap } from 'lucide-react'
import { playbooksApi, type PlaybookStep } from '@/api/playbooks'
import { Button } from '@/components/ui/Button'
import { extractApiError } from '@/lib/utils'
import { formatDateTime } from '@/lib/timezone'

// ─── Step status icon ─────────────────────────────────────────────────────────

function StepIcon({ status }: { status: string }) {
  if (status === 'completed') return <CheckCircle size={16} style={{ color: '#10B981', flexShrink: 0 }} />
  if (status === 'failed')    return <AlertCircle size={16} style={{ color: '#EF4444', flexShrink: 0 }} />
  return <Circle size={16} style={{ color: '#3A4150', flexShrink: 0 }} />
}

// ─── Step category badge ──────────────────────────────────────────────────────

function CategoryBadge({ category }: { category: string }) {
  const colors: Record<string, [string, string]> = {
    detection:     ['#3B82F6', 'rgba(59,130,246,0.1)'],
    containment:   ['#EF4444', 'rgba(239,68,68,0.1)'],
    investigation: ['#8B5CF6', 'rgba(139,92,246,0.1)'],
    eradication:   ['#F97316', 'rgba(249,115,22,0.1)'],
    recovery:      ['#10B981', 'rgba(16,185,129,0.1)'],
    communication: ['#F59E0B', 'rgba(245,158,11,0.1)'],
  }
  const [color, bg] = colors[category] ?? ['#8B95A7', 'rgba(255,255,255,0.06)']
  return (
    <span style={{
      padding: '2px 6px', borderRadius: 4,
      fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
      fontFamily: "'JetBrains Mono', monospace",
      color, background: bg,
    }}>
      {category}
    </span>
  )
}

// ─── Step card ────────────────────────────────────────────────────────────────

function StepCard({ step, playbookId, isExecuting }: { step: PlaybookStep; playbookId: string; isExecuting: boolean }) {
  const [expanded, setExpanded] = useState(false)
  const [notes, setNotes] = useState(step.notes ?? '')
  const [result, setResult] = useState(step.result ?? '')
  const [error, setError] = useState<string | null>(null)
  const qc = useQueryClient()

  const complete = useMutation({
    mutationFn: () => playbooksApi.completeStep(playbookId, step.id, { notes, result }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['playbook', playbookId] })
      setError(null)
    },
    onError: (err) => setError(extractApiError(err)),
  })

  const isDone = step.status === 'completed' || step.status === 'skipped'
  const isFailed = step.status === 'failed'

  return (
    <div style={{
      border: `1px solid ${isDone ? 'rgba(16,185,129,0.2)' : isFailed ? 'rgba(239,68,68,0.2)' : 'rgba(255,255,255,0.06)'}`,
      borderRadius: 8,
      background: isDone ? 'rgba(16,185,129,0.03)' : 'rgba(255,255,255,0.01)',
      overflow: 'hidden',
      transition: 'border-color 200ms',
    }}>
      {/* Step header */}
      <div
        style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '12px 14px', cursor: 'pointer',
        }}
        onClick={() => setExpanded(!expanded)}
      >
        <div style={{
          width: 22, height: 22, borderRadius: '50%',
          background: 'rgba(255,255,255,0.04)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0, fontSize: 10, fontWeight: 700,
          fontFamily: "'JetBrains Mono', monospace",
          color: '#5C6373',
        }}>
          {step.step_order}
        </div>

        <StepIcon status={step.status} />

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{
            fontSize: 12, fontWeight: 600, color: isDone ? '#6EE7B7' : '#F5F7FA',
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
            {step.title}
          </div>
          <div style={{ marginTop: 3 }}>
            <CategoryBadge category={step.category} />
          </div>
        </div>

        {expanded ? <ChevronUp size={14} style={{ color: '#5C6373', flexShrink: 0 }} /> : <ChevronDown size={14} style={{ color: '#5C6373', flexShrink: 0 }} />}
      </div>

      {/* Step body */}
      {expanded && (
        <div style={{
          padding: '0 14px 14px',
          borderTop: '1px solid rgba(255,255,255,0.04)',
        }}>
          <p style={{ fontSize: 12, color: '#B8C0CC', lineHeight: 1.7, marginTop: 10, marginBottom: 14 }}>
            {step.description}
          </p>

          {!isDone && isExecuting && (
            <div style={{ display: 'grid', gap: 10 }}>
              <div>
                <label style={{ fontSize: 10, color: '#8B95A7', display: 'block', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '1px' }}>
                  Result / Findings
                </label>
                <input
                  className="inp"
                  value={result}
                  onChange={e => setResult(e.target.value)}
                  placeholder="What did you find or do?"
                />
              </div>
              <div>
                <label style={{ fontSize: 10, color: '#8B95A7', display: 'block', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '1px' }}>
                  Notes (optional)
                </label>
                <textarea
                  className="inp"
                  value={notes}
                  onChange={e => setNotes(e.target.value)}
                  placeholder="Any additional notes..."
                  style={{ resize: 'vertical', minHeight: 56 }}
                />
              </div>

              {error && (
                <div style={{
                  padding: '6px 10px', borderRadius: 6, fontSize: 11,
                  background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)',
                  color: '#F87171',
                }}>
                  {error}
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <Button
                  variant="primary"
                  size="sm"
                  loading={complete.isPending}
                  onClick={() => complete.mutate()}
                >
                  <CheckCircle size={12} /> Mark Complete
                </Button>
              </div>
            </div>
          )}

          {isDone && step.result && (
            <div style={{
              padding: '8px 12px', borderRadius: 6,
              background: 'rgba(16,185,129,0.06)', border: '1px solid rgba(16,185,129,0.15)',
              fontSize: 11, color: '#6EE7B7',
            }}>
              <span style={{ opacity: 0.7, marginRight: 6 }}>Result:</span>
              {step.result}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── PlaybookDetailPage ───────────────────────────────────────────────────────

export function PlaybookDetailPage() {
  const { id = '' } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [error, setError] = useState<string | null>(null)

  const { data: playbook, isLoading } = useQuery({
    queryKey: ['playbook', id],
    queryFn: () => playbooksApi.get(id),
    enabled: !!id,
    refetchInterval: 15_000,
  })

  const execute = useMutation({
    mutationFn: () => playbooksApi.execute(id, 'manual'),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['playbook', id] })
      qc.invalidateQueries({ queryKey: ['playbooks'] })
      setError(null)
    },
    onError: (err) => setError(extractApiError(err)),
  })

  const steps = playbook?.steps ?? []
  const completedCount = steps.filter(s => s.status === 'completed').length
  const progress = steps.length ? Math.round((completedCount / steps.length) * 100) : 0
  const isExecuting = playbook?.status === 'in_progress'

  const severityColor =
    playbook?.severity === 'critical' ? '#EF4444' :
    playbook?.severity === 'high'     ? '#F97316' :
    playbook?.severity === 'medium'   ? '#F59E0B' : '#3B82F6'

  return (
    <div className="page-in" style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 50px - 40px)', overflow: 'hidden' }}>

      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10,
        paddingBottom: 12, borderBottom: '1px solid rgba(255,255,255,0.06)', flexShrink: 0,
      }}>
        <button
          onClick={() => navigate('/playbooks')}
          style={{ background: 'none', border: 'none', color: '#5C6373', cursor: 'pointer', padding: 4 }}
        >
          <ArrowLeft size={16} />
        </button>
        {isLoading ? (
          <span className="skel" style={{ width: 200, height: 20, display: 'inline-block', borderRadius: 4 }} />
        ) : (
          <>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h1 style={{ fontSize: 15, fontWeight: 700, color: '#F5F7FA', fontFamily: "'Space Grotesk', sans-serif", margin: 0 }}>
                  {playbook?.title}
                </h1>
                <span style={{
                  padding: '2px 7px', borderRadius: 4, fontSize: 9, fontWeight: 700,
                  textTransform: 'uppercase', fontFamily: "'JetBrains Mono', monospace",
                  color: severityColor, background: `${severityColor}1A`,
                }}>
                  {playbook?.severity}
                </span>
              </div>
              <div style={{ fontSize: 11, color: '#5C6373', marginTop: 2 }}>
                {playbook?.source_host && `Host: ${playbook.source_host} · `}
                {playbook?.generated_by === 'llm' ? 'AI-Generated' : `From ${playbook?.generated_by} template`}
                {' · '}
                {playbook?.created_at && formatDateTime(playbook.created_at)}
              </div>
            </div>

            {!isExecuting && playbook?.status === 'draft' && (
              <Button
                variant="primary"
                size="sm"
                loading={execute.isPending}
                onClick={() => execute.mutate()}
              >
                <Play size={12} /> Execute Playbook
              </Button>
            )}

            {isExecuting && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '4px 10px', borderRadius: 6,
                background: 'rgba(59,130,246,0.1)', border: '1px solid rgba(59,130,246,0.2)',
                fontSize: 11, color: '#60A5FA', fontWeight: 600,
              }}>
                <Zap size={11} />
                Executing
              </div>
            )}

            {playbook?.status === 'completed' && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '4px 10px', borderRadius: 6,
                background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.2)',
                fontSize: 11, color: '#10B981', fontWeight: 600,
              }}>
                <CheckCircle size={11} />
                Completed
              </div>
            )}
          </>
        )}
      </div>

      {/* Progress bar */}
      {!isLoading && steps.length > 0 && (
        <div style={{
          padding: '10px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', flexShrink: 0,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
            <span style={{ fontSize: 11, color: '#8B95A7' }}>
              Progress: {completedCount} / {steps.length} steps
            </span>
            <span style={{ fontSize: 11, fontWeight: 700, color: progress === 100 ? '#10B981' : '#3B82F6' }}>
              {progress}%
            </span>
          </div>
          <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2 }}>
            <div style={{
              height: '100%', borderRadius: 2,
              width: `${progress}%`,
              background: progress === 100 ? '#10B981' : '#3B82F6',
              transition: 'width 300ms ease',
            }} />
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div style={{
          padding: '8px 12px', margin: '8px 0', borderRadius: 6, fontSize: 12,
          background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)',
          color: '#F87171', flexShrink: 0,
        }}>
          {error}
        </div>
      )}

      {/* Steps */}
      <div style={{ flex: 1, overflowY: 'auto', paddingTop: 12 }}>
        {isLoading ? (
          <div style={{ display: 'grid', gap: 8 }}>
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="skel" style={{ height: 52, borderRadius: 8, display: 'block' }} />
            ))}
          </div>
        ) : steps.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '60px 0', color: '#5C6373', fontSize: 13 }}>
            No steps generated for this playbook.
          </div>
        ) : (
          <div style={{ display: 'grid', gap: 8 }}>
            {steps.map(step => (
              <StepCard
                key={step.id}
                step={step}
                playbookId={id}
                isExecuting={isExecuting}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
