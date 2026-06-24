import { useState, useMemo } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Play, CheckCircle, Circle, AlertCircle, ChevronDown, ChevronUp, Zap, Shield, Search, Eye, Trash2, RefreshCw, MessageSquare } from 'lucide-react'
import { playbooksApi, type PlaybookStep } from '@/api/playbooks'
import { Button } from '@/components/ui/Button'
import { extractApiError } from '@/lib/utils'
import { formatDateTime } from '@/lib/timezone'

// IR phase ordering + config
const PHASE_ORDER = ['detection', 'investigation', 'containment', 'eradication', 'recovery', 'communication']
const PHASE_CONFIG: Record<string, { label: string; color: string; icon: typeof Shield }> = {
  detection:     { label: 'Detection',     color: '#3B82F6', icon: Eye            },
  investigation: { label: 'Investigation', color: '#8B5CF6', icon: Search         },
  containment:   { label: 'Containment',   color: '#EF4444', icon: Shield         },
  eradication:   { label: 'Eradication',   color: '#F97316', icon: Trash2         },
  recovery:      { label: 'Recovery',      color: '#10B981', icon: RefreshCw      },
  communication: { label: 'Communication', color: '#F59E0B', icon: MessageSquare  },
}

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

  // Group steps by IR phase in canonical order
  const phaseGroups = useMemo(() => {
    const grouped: Record<string, PlaybookStep[]> = {}
    for (const step of steps) {
      const ph = step.category in PHASE_CONFIG ? step.category : 'detection'
      ;(grouped[ph] ??= []).push(step)
    }
    return PHASE_ORDER
      .filter(ph => ph in grouped)
      .map(ph => ({ phase: ph, steps: grouped[ph]! }))
  }, [steps])

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

      {/* Progress bar + phase summary */}
      {!isLoading && steps.length > 0 && (
        <div style={{ padding: '10px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', flexShrink: 0 }}>
          {/* Main progress row */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
            <div style={{ flex: 1, height: 5, background: 'rgba(255,255,255,0.06)', borderRadius: 3, overflow: 'hidden' }}>
              <div style={{
                height: '100%', width: `${progress}%`,
                background: progress === 100 ? '#10B981' : 'linear-gradient(90deg, #3B82F6, #60A5FA)',
                borderRadius: 3, transition: 'width 300ms ease',
              }} />
            </div>
            <span style={{
              fontSize: 13, fontWeight: 800, fontFamily: "'JetBrains Mono', monospace",
              color: progress === 100 ? '#10B981' : '#60A5FA', flexShrink: 0, minWidth: 36, textAlign: 'right',
            }}>
              {progress}%
            </span>
            <span style={{ fontSize: 10, color: '#5C6373', flexShrink: 0 }}>
              {completedCount}/{steps.length}
            </span>
          </div>

          {/* Phase chip strip */}
          {phaseGroups.length > 1 && (
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 6 }}>
              {phaseGroups.map(({ phase, steps: pSteps }) => {
                const cfg = PHASE_CONFIG[phase] ?? PHASE_CONFIG['detection']!
                const done = pSteps.filter(s => s.status === 'completed').length
                const allDone = done === pSteps.length
                return (
                  <div key={phase} style={{
                    display: 'flex', alignItems: 'center', gap: 4,
                    padding: '2px 7px', borderRadius: 4,
                    background: allDone ? `${cfg.color}15` : 'rgba(255,255,255,0.03)',
                    border: `1px solid ${allDone ? `${cfg.color}30` : 'rgba(255,255,255,0.06)'}`,
                  }}>
                    <span style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', color: allDone ? cfg.color : '#5C6373', letterSpacing: '0.5px' }}>
                      {cfg.label}
                    </span>
                    <span style={{ fontSize: 9, fontFamily: "'JetBrains Mono', monospace", color: allDone ? cfg.color : '#3A4150', fontWeight: 700 }}>
                      {done}/{pSteps.length}
                    </span>
                  </div>
                )
              })}
            </div>
          )}
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
        ) : phaseGroups.length > 1 ? (
          // Phase-grouped view
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {phaseGroups.map(({ phase, steps: pSteps }) => {
              const cfg = PHASE_CONFIG[phase] ?? PHASE_CONFIG['detection']!
              const PhaseIcon = cfg.icon
              const done = pSteps.filter(s => s.status === 'completed').length
              return (
                <div key={phase}>
                  {/* Phase section header */}
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    marginBottom: 8, paddingBottom: 8,
                    borderBottom: `1px solid ${cfg.color}20`,
                  }}>
                    <PhaseIcon size={12} style={{ color: cfg.color, flexShrink: 0 }} />
                    <span style={{
                      fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
                      letterSpacing: '1.5px', color: cfg.color,
                    }}>
                      {cfg.label}
                    </span>
                    <span style={{ fontSize: 10, color: '#3A4150', fontFamily: "'JetBrains Mono', monospace" }}>
                      {done}/{pSteps.length}
                    </span>
                    <div style={{ flex: 1, height: 1, background: `${cfg.color}15` }} />
                    {done === pSteps.length && (
                      <CheckCircle size={12} style={{ color: cfg.color, flexShrink: 0 }} />
                    )}
                  </div>
                  <div style={{ display: 'grid', gap: 6 }}>
                    {pSteps.map(step => (
                      <StepCard key={step.id} step={step} playbookId={id} isExecuting={isExecuting} />
                    ))}
                  </div>
                </div>
              )
            })}
          </div>
        ) : (
          // Flat view (single phase)
          <div style={{ display: 'grid', gap: 8 }}>
            {steps.map(step => (
              <StepCard key={step.id} step={step} playbookId={id} isExecuting={isExecuting} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
