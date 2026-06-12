import { useState, useEffect, useCallback } from 'react'
import { Plus, Edit2, Trash2, Shield, ChevronDown } from 'lucide-react'
import { rulesApi } from '@/api/rules'
import type { DetectionRule, RuleType, RuleSeverity, PatternCondition, ThresholdCondition } from '@/api/rules'
import { extractApiError } from '@/lib/utils'

// ─── Constants ────────────────────────────────────────────────────────────────

const SEV_COLORS: Record<RuleSeverity, { bg: string; color: string }> = {
  critical: { bg: 'rgba(239,68,68,0.12)',   color: '#F87171' },
  high:     { bg: 'rgba(249,115,22,0.12)',  color: '#FB923C' },
  medium:   { bg: 'rgba(245,158,11,0.12)',  color: '#FBBF24' },
  low:      { bg: 'rgba(107,114,128,0.15)', color: '#9CA3AF' },
}

const PATTERN_FIELDS = [
  'category', 'severity', 'hostname', 'username',
  'process.name', 'source.ip', 'dest.ip', 'event_id', 'tags',
]

const THRESHOLD_FIELDS = [
  'source.ip', 'username', 'process.name', 'hostname', 'dest.ip', 'category',
]

const MITRE_TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
]

// ─── Form state ───────────────────────────────────────────────────────────────

interface PatternCond { field: string; op: string; value: string }

const DEFAULT_FORM = {
  name:           '',
  description:    '',
  ruleType:       'pattern' as RuleType,
  severity:       'medium' as RuleSeverity,
  patternConds:   [{ field: 'category', op: 'eq', value: '' }] as PatternCond[],
  tField:         'source.ip',
  tGroupBy:       'hostname',
  tThreshold:     5,
  tWindowSecs:    300,
  mitreTactic:    '',
  mitreTech:      '',
  suppressionSecs: 300,
}

type FormState = typeof DEFAULT_FORM

function formFromRule(rule: DetectionRule): FormState {
  const isPattern = rule.rule_type === 'pattern'
  const patternConds: PatternCond[] = isPattern
    ? (rule.conditions as PatternCondition[]).map(c => ({
        field: c.field,
        op:    c.op,
        value: Array.isArray(c.value) ? c.value.join(', ') : String(c.value),
      }))
    : [{ field: 'category', op: 'eq', value: '' }]
  const tc = isPattern ? null : (rule.conditions as ThresholdCondition)
  return {
    name:           rule.name,
    description:    rule.description ?? '',
    ruleType:       rule.rule_type,
    severity:       rule.severity,
    patternConds,
    tField:         tc?.field         ?? 'source.ip',
    tGroupBy:       tc?.group_by      ?? 'hostname',
    tThreshold:     tc?.threshold     ?? 5,
    tWindowSecs:    tc?.window_secs   ?? 300,
    mitreTactic:    rule.mitre_tactics[0]    ?? '',
    mitreTech:      rule.mitre_techniques.join(', '),
    suppressionSecs: rule.suppression_window_secs,
  }
}

function buildConditions(fs: FormState): PatternCondition[] | ThresholdCondition {
  if (fs.ruleType === 'pattern') {
    return fs.patternConds
      .filter(c => c.field && c.value.trim())
      .map(c => ({ field: c.field, op: c.op as PatternCondition['op'], value: c.value }))
  }
  return { field: fs.tField, group_by: fs.tGroupBy, threshold: fs.tThreshold, window_secs: fs.tWindowSecs }
}

// ─── Toast ────────────────────────────────────────────────────────────────────

function Toast({ msg, type }: { msg: string; type: 'success' | 'error' }) {
  return (
    <div style={{
      position: 'fixed', top: 20, right: 20, zIndex: 200,
      padding: '10px 16px', borderRadius: 8, fontSize: 12, fontWeight: 600,
      background: type === 'success' ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)',
      border: `1px solid ${type === 'success' ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'}`,
      color: type === 'success' ? '#6EE7B7' : '#FCA5A5',
      boxShadow: '0 4px 20px rgba(0,0,0,0.4)',
      backdropFilter: 'blur(8px)',
    }}>{msg}</div>
  )
}

// ─── Enable Toggle ────────────────────────────────────────────────────────────

function EnableToggle({ enabled, loading, onToggle }: { enabled: boolean; loading: boolean; onToggle: () => void }) {
  return (
    <button onClick={e => { e.stopPropagation(); onToggle() }} disabled={loading} style={{
      width: 36, height: 20, borderRadius: 10,
      background: enabled ? '#3B82F6' : 'rgba(255,255,255,0.1)',
      border: `1px solid ${enabled ? '#2563EB' : 'rgba(255,255,255,0.1)'}`,
      position: 'relative', cursor: loading ? 'default' : 'pointer',
      transition: 'background 150ms', opacity: loading ? 0.6 : 1, flexShrink: 0,
    }}>
      <div style={{
        position: 'absolute', top: 3, left: enabled ? 17 : 3,
        width: 12, height: 12, borderRadius: '50%', background: '#fff',
        transition: 'left 150ms', boxShadow: '0 1px 3px rgba(0,0,0,0.3)',
      }} />
    </button>
  )
}

// ─── Delete Confirm Row ───────────────────────────────────────────────────────

function DeleteConfirmRow({ rule, onConfirm, onCancel, loading }: {
  rule: DetectionRule; onConfirm: () => void; onCancel: () => void; loading: boolean
}) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '10px 16px',
      background: 'rgba(239,68,68,0.06)', borderBottom: '1px solid rgba(239,68,68,0.1)',
    }}>
      <span style={{ fontSize: 12, color: '#FCA5A5' }}>
        Delete <strong>"{rule.name}"</strong>? This cannot be undone.
      </span>
      <div style={{ display: 'flex', gap: 8 }}>
        <button onClick={onCancel} style={{
          padding: '4px 12px', borderRadius: 5, fontSize: 11, fontWeight: 600,
          background: 'transparent', border: '1px solid rgba(255,255,255,0.1)',
          color: '#8B95A7', cursor: 'pointer',
        }}>Cancel</button>
        <button onClick={onConfirm} disabled={loading} style={{
          padding: '4px 12px', borderRadius: 5, fontSize: 11, fontWeight: 600,
          background: 'rgba(239,68,68,0.2)', border: '1px solid rgba(239,68,68,0.4)',
          color: '#F87171', cursor: loading ? 'default' : 'pointer',
        }}>{loading ? 'Deleting...' : 'Delete'}</button>
      </div>
    </div>
  )
}

// ─── Rule Row ─────────────────────────────────────────────────────────────────

function RuleRow({ rule, isToggling, isDeleting, deleteId, onToggle, onEdit, onDeleteClick, onDeleteConfirm, onDeleteCancel }: {
  rule: DetectionRule
  isToggling: boolean
  isDeleting: boolean
  deleteId: string | null
  onToggle: () => void
  onEdit: () => void
  onDeleteClick: () => void
  onDeleteConfirm: () => void
  onDeleteCancel: () => void
}) {
  const [hover, setHover] = useState(false)
  const sc = SEV_COLORS[rule.severity]
  const firstTech = rule.mitre_techniques[0]

  return (
    <>
      <div
        onMouseEnter={() => setHover(true)}
        onMouseLeave={() => setHover(false)}
        style={{
          display: 'grid', gridTemplateColumns: '1fr 100px 100px 90px 60px 72px',
          padding: '11px 16px', alignItems: 'center',
          borderBottom: deleteId === rule.id ? 'none' : '1px solid rgba(255,255,255,0.04)',
          background: hover ? 'rgba(255,255,255,0.02)' : 'transparent',
          transition: 'background 80ms',
        }}
      >
        {/* Name + description */}
        <div style={{ paddingRight: 12 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: '#F5F7FA', marginBottom: 1 }}>{rule.name}</div>
          {rule.description && (
            <div style={{ fontSize: 10, color: '#5C6373', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 380 }}>
              {rule.description}
            </div>
          )}
        </div>
        {/* Type */}
        <div>
          <span style={{
            display: 'inline-block', padding: '2px 8px', borderRadius: 5,
            fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px',
            background: rule.rule_type === 'pattern' ? 'rgba(59,130,246,0.12)' : 'rgba(139,92,246,0.12)',
            color: rule.rule_type === 'pattern' ? '#60A5FA' : '#A78BFA',
            border: `1px solid ${rule.rule_type === 'pattern' ? 'rgba(59,130,246,0.2)' : 'rgba(139,92,246,0.2)'}`,
          }}>{rule.rule_type}</span>
        </div>
        {/* Severity */}
        <div>
          <span style={{
            display: 'inline-block', padding: '2px 8px', borderRadius: 5,
            fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px',
            background: sc.bg, color: sc.color,
          }}>{rule.severity}</span>
        </div>
        {/* MITRE */}
        <div>
          {firstTech ? (
            <span style={{
              display: 'inline-block', padding: '1px 6px', borderRadius: 4,
              fontSize: 9, fontWeight: 600, fontFamily: "'JetBrains Mono', monospace",
              background: 'rgba(99,102,241,0.1)', color: '#818CF8',
              border: '1px solid rgba(99,102,241,0.15)',
            }}>{firstTech}</span>
          ) : <span style={{ fontSize: 10, color: '#3A4150' }}>—</span>}
        </div>
        {/* Enabled toggle */}
        <div style={{ display: 'flex', justifyContent: 'center' }}>
          <EnableToggle enabled={rule.enabled} loading={isToggling} onToggle={onToggle} />
        </div>
        {/* Actions */}
        <div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end', opacity: hover ? 1 : 0, transition: 'opacity 100ms' }}>
          <button onClick={e => { e.stopPropagation(); onEdit() }} title="Edit" style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            width: 28, height: 28, borderRadius: 6, cursor: 'pointer',
            background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.2)', color: '#60A5FA',
          }}><Edit2 size={12} /></button>
          <button onClick={e => { e.stopPropagation(); onDeleteClick() }} title="Delete" style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            width: 28, height: 28, borderRadius: 6, cursor: 'pointer',
            background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', color: '#F87171',
          }}><Trash2 size={12} /></button>
        </div>
      </div>
      {deleteId === rule.id && (
        <DeleteConfirmRow
          rule={rule}
          onConfirm={onDeleteConfirm}
          onCancel={onDeleteCancel}
          loading={isDeleting}
        />
      )}
    </>
  )
}

// ─── Pattern Condition Builder ─────────────────────────────────────────────────

function PatternBuilder({ conds, onChange }: { conds: PatternCond[]; onChange: (c: PatternCond[]) => void }) {
  const update = (i: number, c: PatternCond) => onChange(conds.map((x, j) => j === i ? c : x))
  const remove = (i: number) => onChange(conds.filter((_, j) => j !== i))
  const add    = () => onChange([...conds, { field: 'category', op: 'eq', value: '' }])

  return (
    <div>
      <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 10 }}>
        Match events where (ALL conditions):
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 8 }}>
        {conds.map((c, i) => (
          <div key={i} style={{ display: 'flex', gap: 5, alignItems: 'center' }}>
            <select className="inp" style={{ width: 130, flexShrink: 0 }} value={c.field}
              onChange={e => update(i, { ...c, field: e.target.value })}>
              {PATTERN_FIELDS.map(f => <option key={f} value={f}>{f}</option>)}
            </select>
            <select className="inp" style={{ width: 100, flexShrink: 0 }} value={c.op}
              onChange={e => update(i, { ...c, op: e.target.value })}>
              {(['eq', 'contains', 'regex', 'ne', 'in'] as const).map(op => (
                <option key={op} value={op}>{op}</option>
              ))}
            </select>
            <input className="inp" style={{ flex: 1 }} placeholder="Value..." value={c.value}
              onChange={e => update(i, { ...c, value: e.target.value })} />
            <button onClick={() => remove(i)} disabled={conds.length <= 1} style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              width: 28, height: 28, borderRadius: 6, flexShrink: 0, cursor: conds.length > 1 ? 'pointer' : 'default',
              background: conds.length > 1 ? 'rgba(239,68,68,0.08)' : 'rgba(255,255,255,0.03)',
              border: `1px solid ${conds.length > 1 ? 'rgba(239,68,68,0.2)' : 'rgba(255,255,255,0.06)'}`,
              color: conds.length > 1 ? '#F87171' : '#3A4150',
            }}><Trash2 size={11} /></button>
          </div>
        ))}
      </div>
      <button onClick={add} style={{
        display: 'flex', alignItems: 'center', gap: 5, padding: '5px 10px',
        borderRadius: 6, background: 'transparent', border: '1px dashed rgba(255,255,255,0.1)',
        color: '#5C6373', fontSize: 11, fontWeight: 600, cursor: 'pointer',
      }}><Plus size={11} /> Add Condition</button>
    </div>
  )
}

// ─── Threshold Builder ────────────────────────────────────────────────────────

function ThresholdBuilder({ fs, set }: { fs: FormState; set: (k: keyof FormState, v: unknown) => void }) {
  const lbl = (text: string) => (
    <label style={{ display: 'block', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 5 }}>
      {text}
    </label>
  )
  return (
    <div>
      <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 10 }}>
        Fire when field count exceeds threshold:
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
        <div>
          {lbl('Count Field')}
          <select className="inp" style={{ width: '100%' }} value={fs.tField} onChange={e => set('tField', e.target.value)}>
            {THRESHOLD_FIELDS.map(f => <option key={f} value={f}>{f}</option>)}
          </select>
        </div>
        <div>
          {lbl('Group By')}
          <select className="inp" style={{ width: '100%' }} value={fs.tGroupBy} onChange={e => set('tGroupBy', e.target.value)}>
            {THRESHOLD_FIELDS.map(f => <option key={f} value={f}>{f}</option>)}
          </select>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div>
          {lbl('Threshold (events)')}
          <input className="inp" style={{ width: '100%' }} type="number" min={1} value={fs.tThreshold}
            onChange={e => set('tThreshold', parseInt(e.target.value) || 1)} />
        </div>
        <div>
          {lbl('Window (seconds)')}
          <input className="inp" style={{ width: '100%' }} type="number" min={1} value={fs.tWindowSecs}
            onChange={e => set('tWindowSecs', parseInt(e.target.value) || 60)} />
        </div>
      </div>
    </div>
  )
}

// ─── Rule Modal ───────────────────────────────────────────────────────────────

function RuleModal({ editRule, onClose, onSaved }: {
  editRule: DetectionRule | null
  onClose: () => void
  onSaved: (rule: DetectionRule) => void
}) {
  const [step,    setStep]    = useState(1)
  const [fs,      setFs]      = useState<FormState>(editRule ? formFromRule(editRule) : { ...DEFAULT_FORM, patternConds: [{ field: 'category', op: 'eq', value: '' }] })
  const [saving,  setSaving]  = useState(false)
  const [err,     setErr]     = useState<string | null>(null)

  const set = (k: keyof FormState, v: unknown) => setFs(prev => ({ ...prev, [k]: v }))

  const canNext = step === 1
    ? fs.name.trim().length > 0
    : step === 2
    ? (fs.ruleType === 'pattern' ? fs.patternConds.some(c => c.value.trim()) : fs.tField && fs.tGroupBy && fs.tThreshold > 0 && fs.tWindowSecs > 0)
    : true

  const handleSave = async () => {
    setSaving(true)
    setErr(null)
    const payload = {
      name:                   fs.name.trim(),
      description:            fs.description.trim() || undefined,
      rule_type:              fs.ruleType,
      severity:               fs.severity,
      conditions:             buildConditions(fs),
      mitre_tactics:          fs.mitreTactic ? [fs.mitreTactic] : [],
      mitre_techniques:       fs.mitreTech ? fs.mitreTech.split(',').map(s => s.trim()).filter(Boolean) : [],
      suppression_window_secs: fs.suppressionSecs,
    }
    try {
      let rule: DetectionRule
      if (editRule) {
        const { rule_type: _rt, ...updatePayload } = payload
        const resp = await rulesApi.update(editRule.id, updatePayload)
        rule = resp.data.data
      } else {
        const resp = await rulesApi.create(payload)
        rule = resp.data.data
      }
      onSaved(rule)
    } catch (e) {
      setErr(extractApiError(e))
    } finally {
      setSaving(false)
    }
  }

  const lbl = (text: string) => (
    <label style={{ display: 'block', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 5 }}>
      {text}
    </label>
  )

  return (
    <>
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', zIndex: 49 }} />
      <div style={{
        position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%, -50%)',
        width: 520, maxHeight: '90vh', overflowY: 'auto', zIndex: 50,
        background: '#0D0D0D', border: '1px solid rgba(59,130,246,0.2)',
        borderRadius: 12, boxShadow: '0 0 40px rgba(59,130,246,0.1)',
      }}>
        {/* Header */}
        <div style={{ padding: '20px 24px 0', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: 16 }}>
          <div style={{ fontSize: 15, fontWeight: 700, color: '#F5F7FA', fontFamily: "'Space Grotesk', sans-serif", marginBottom: 12 }}>
            {editRule ? 'Edit Rule' : 'New Detection Rule'}
          </div>
          {/* Step indicator */}
          <div style={{ display: 'flex', gap: 4 }}>
            {[1, 2, 3].map(s => (
              <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{
                  width: 20, height: 20, borderRadius: '50%', flexShrink: 0,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 10, fontWeight: 700,
                  background: step >= s ? '#3B82F6' : 'rgba(255,255,255,0.06)',
                  color: step >= s ? '#fff' : '#5C6373',
                }}>{s}</div>
                <span style={{ fontSize: 11, color: step === s ? '#F5F7FA' : '#5C6373' }}>
                  {s === 1 ? 'Basic Info' : s === 2 ? 'Conditions' : 'MITRE & Settings'}
                </span>
                {s < 3 && <div style={{ width: 20, height: 1, background: 'rgba(255,255,255,0.08)', marginLeft: 2 }} />}
              </div>
            ))}
          </div>
        </div>

        {/* Body */}
        <div style={{ padding: '20px 24px' }}>
          {/* Step 1 — Basic Info */}
          {step === 1 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                {lbl('Name *')}
                <input className="inp" style={{ width: '100%' }} placeholder="e.g. Brute Force Login Detection"
                  value={fs.name} onChange={e => set('name', e.target.value)} autoFocus />
              </div>
              <div>
                {lbl('Description')}
                <input className="inp" style={{ width: '100%' }} placeholder="Brief description..."
                  value={fs.description} onChange={e => set('description', e.target.value)} />
              </div>
              <div>
                {lbl('Rule Type')}
                <div style={{ display: 'flex', gap: 8 }}>
                  {(['pattern', 'threshold'] as RuleType[]).map(t => (
                    <button key={t} onClick={() => set('ruleType', t)} disabled={!!editRule} style={{
                      flex: 1, padding: '10px 16px', borderRadius: 8, fontSize: 13, fontWeight: 600,
                      cursor: editRule ? 'default' : 'pointer',
                      background: fs.ruleType === t
                        ? (t === 'pattern' ? 'rgba(59,130,246,0.15)' : 'rgba(139,92,246,0.15)')
                        : 'rgba(255,255,255,0.04)',
                      border: `1px solid ${fs.ruleType === t
                        ? (t === 'pattern' ? 'rgba(59,130,246,0.4)' : 'rgba(139,92,246,0.4)')
                        : 'rgba(255,255,255,0.08)'}`,
                      color: fs.ruleType === t ? (t === 'pattern' ? '#60A5FA' : '#A78BFA') : '#8B95A7',
                      opacity: editRule ? 0.6 : 1,
                    }}>
                      {t === 'pattern' ? 'Pattern' : 'Threshold'}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                {lbl('Severity')}
                <div style={{ display: 'flex', gap: 6 }}>
                  {(['low', 'medium', 'high', 'critical'] as RuleSeverity[]).map(s => {
                    const sc = SEV_COLORS[s]
                    return (
                      <button key={s} onClick={() => set('severity', s)} style={{
                        flex: 1, padding: '8px 0', borderRadius: 7, fontSize: 11, fontWeight: 700,
                        textTransform: 'uppercase', letterSpacing: '0.5px', cursor: 'pointer',
                        background: fs.severity === s ? sc.bg : 'rgba(255,255,255,0.04)',
                        border: `1px solid ${fs.severity === s ? sc.color + '60' : 'rgba(255,255,255,0.08)'}`,
                        color: fs.severity === s ? sc.color : '#5C6373',
                      }}>{s}</button>
                    )
                  })}
                </div>
              </div>
            </div>
          )}

          {/* Step 2 — Conditions */}
          {step === 2 && (
            <div>
              {fs.ruleType === 'pattern'
                ? <PatternBuilder conds={fs.patternConds} onChange={v => set('patternConds', v)} />
                : <ThresholdBuilder fs={fs} set={set} />
              }
            </div>
          )}

          {/* Step 3 — MITRE & Settings */}
          {step === 3 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                {lbl('MITRE Tactic')}
                <select className="inp" style={{ width: '100%' }} value={fs.mitreTactic} onChange={e => set('mitreTactic', e.target.value)}>
                  <option value="">None</option>
                  {MITRE_TACTICS.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
              <div>
                {lbl('MITRE Techniques (comma-separated)')}
                <input className="inp" style={{ width: '100%' }} placeholder="e.g. T1059.001, T1059.003"
                  value={fs.mitreTech} onChange={e => set('mitreTech', e.target.value)} />
              </div>
              <div>
                {lbl('Suppression Window (seconds)')}
                <input className="inp" style={{ width: '100%' }} type="number" min={0} max={86400}
                  value={fs.suppressionSecs} onChange={e => set('suppressionSecs', parseInt(e.target.value) || 0)} />
                <div style={{ fontSize: 10, color: '#3A4150', marginTop: 4 }}>
                  Minimum time between repeated alerts from this rule (0 = no suppression)
                </div>
              </div>
            </div>
          )}

          {err && <div style={{ marginTop: 12, fontSize: 12, color: '#FCA5A5' }}>{err}</div>}
        </div>

        {/* Footer */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '14px 24px', borderTop: '1px solid rgba(255,255,255,0.06)',
        }}>
          <button onClick={onClose} style={{
            padding: '7px 16px', borderRadius: 7, fontSize: 12, fontWeight: 600,
            background: 'transparent', border: '1px solid rgba(255,255,255,0.1)',
            color: '#8B95A7', cursor: 'pointer',
          }}>Cancel</button>
          <div style={{ display: 'flex', gap: 8 }}>
            {step > 1 && (
              <button onClick={() => setStep(s => (s - 1) as 1 | 2 | 3)} style={{
                padding: '7px 16px', borderRadius: 7, fontSize: 12, fontWeight: 600,
                background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)',
                color: '#F5F7FA', cursor: 'pointer',
              }}>Back</button>
            )}
            {step < 3 ? (
              <button onClick={() => setStep(s => (s + 1) as 1 | 2 | 3)} disabled={!canNext} style={{
                padding: '7px 16px', borderRadius: 7, fontSize: 12, fontWeight: 600,
                background: canNext ? '#3B82F6' : 'rgba(59,130,246,0.3)',
                border: 'none', color: '#fff', cursor: canNext ? 'pointer' : 'default',
              }}>Next</button>
            ) : (
              <button onClick={handleSave} disabled={saving} style={{
                padding: '7px 16px', borderRadius: 7, fontSize: 12, fontWeight: 600,
                background: saving ? 'rgba(59,130,246,0.4)' : '#3B82F6',
                border: 'none', color: '#fff', cursor: saving ? 'default' : 'pointer',
              }}>{saving ? 'Saving...' : editRule ? 'Save Changes' : 'Create Rule'}</button>
            )}
          </div>
        </div>
      </div>
    </>
  )
}

// ─── RulesPage ────────────────────────────────────────────────────────────────

type FilterEnabled = 'all' | 'enabled' | 'disabled'

export function RulesPage() {
  const [rules,      setRules]      = useState<DetectionRule[]>([])
  const [loading,    setLoading]    = useState(true)
  const [loadErr,    setLoadErr]    = useState<string | null>(null)
  const [togglingId, setTogglingId] = useState<string | null>(null)
  const [deleteId,   setDeleteId]   = useState<string | null>(null)
  const [deleting,   setDeleting]   = useState(false)
  const [showModal,  setShowModal]  = useState(false)
  const [editRule,   setEditRule]   = useState<DetectionRule | null>(null)
  const [toast,      setToast]      = useState<{ msg: string; type: 'success' | 'error' } | null>(null)

  // Filters
  const [filterType,    setFilterType]    = useState<'all' | RuleType>('all')
  const [filterSev,     setFilterSev]     = useState<'all' | RuleSeverity>('all')
  const [filterEnabled, setFilterEnabled] = useState<FilterEnabled>('all')
  const [search,        setSearch]        = useState('')

  const showToast = useCallback((msg: string, type: 'success' | 'error' = 'success') => {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 3000)
  }, [])

  const loadRules = useCallback(async () => {
    setLoading(true)
    setLoadErr(null)
    try {
      const resp = await rulesApi.list({ limit: 100 })
      setRules(resp.data.data ?? [])
    } catch (e) {
      setLoadErr(extractApiError(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadRules() }, [loadRules])

  const filtered = rules.filter(r => {
    if (filterType !== 'all'    && r.rule_type !== filterType) return false
    if (filterSev  !== 'all'    && r.severity  !== filterSev)  return false
    if (filterEnabled === 'enabled'  && !r.enabled)            return false
    if (filterEnabled === 'disabled' && r.enabled)             return false
    if (search && !r.name.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  const handleToggle = async (rule: DetectionRule) => {
    if (togglingId) return
    setTogglingId(rule.id)
    const prev = rule.enabled
    setRules(rs => rs.map(r => r.id === rule.id ? { ...r, enabled: !prev } : r))
    try {
      const resp = await rulesApi.toggle(rule.id, !prev)
      setRules(rs => rs.map(r => r.id === rule.id ? resp.data.data : r))
    } catch (e) {
      setRules(rs => rs.map(r => r.id === rule.id ? { ...r, enabled: prev } : r))
      showToast(extractApiError(e), 'error')
    } finally {
      setTogglingId(null)
    }
  }

  const handleDeleteConfirm = async () => {
    if (!deleteId) return
    setDeleting(true)
    try {
      await rulesApi.delete(deleteId)
      setRules(rs => rs.filter(r => r.id !== deleteId))
      showToast('Rule deleted')
    } catch (e) {
      showToast(extractApiError(e), 'error')
    } finally {
      setDeleting(false)
      setDeleteId(null)
    }
  }

  const handleSaved = (rule: DetectionRule) => {
    setRules(rs => {
      const idx = rs.findIndex(r => r.id === rule.id)
      if (idx >= 0) return rs.map(r => r.id === rule.id ? rule : r)
      return [rule, ...rs]
    })
    setShowModal(false)
    setEditRule(null)
    showToast(editRule ? 'Rule updated' : 'Rule created')
  }

  const openCreate = () => { setEditRule(null); setShowModal(true) }
  const openEdit   = (rule: DetectionRule) => { setEditRule(rule); setShowModal(true) }

  const filterSel = (_label: string, val: string, opts: Array<{label: string; value: string}>, onSet: (v: string) => void) => (
    <div style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}>
      <select
        className="inp"
        value={val}
        onChange={e => onSet(e.target.value)}
        style={{ paddingRight: 28, fontSize: 12 }}
      >
        {opts.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
      <ChevronDown size={12} style={{ position: 'absolute', right: 8, pointerEvents: 'none', color: '#5C6373' }} />
    </div>
  )

  return (
    <div style={{ background: '#050505', minHeight: 'calc(100vh - 50px - 40px)', padding: '0 0 40px' }}>
      {toast && <Toast msg={toast.msg} type={toast.type} />}

      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '20px 24px 0', marginBottom: 20,
      }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 700, fontFamily: "'Space Grotesk', sans-serif", color: '#F5F7FA', margin: 0 }}>
            Detection Rules
          </h1>
          <p style={{ fontSize: 12, color: '#5C6373', margin: '3px 0 0' }}>
            {loading ? 'Loading...' : `${rules.length} rule${rules.length !== 1 ? 's' : ''} configured`}
          </p>
        </div>
        <button onClick={openCreate} style={{
          display: 'flex', alignItems: 'center', gap: 7,
          padding: '9px 16px', borderRadius: 8,
          background: '#3B82F6', border: 'none', color: '#fff',
          fontSize: 13, fontWeight: 600, cursor: 'pointer',
        }}>
          <Plus size={14} /> New Rule
        </button>
      </div>

      {/* Filters + Search bar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap',
        padding: '0 24px 16px',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
      }}>
        {filterSel('Type', filterType, [
          { label: 'All Types', value: 'all' },
          { label: 'Pattern', value: 'pattern' },
          { label: 'Threshold', value: 'threshold' },
        ], v => setFilterType(v as typeof filterType))}
        {filterSel('Severity', filterSev, [
          { label: 'All Severity', value: 'all' },
          { label: 'Critical', value: 'critical' },
          { label: 'High', value: 'high' },
          { label: 'Medium', value: 'medium' },
          { label: 'Low', value: 'low' },
        ], v => setFilterSev(v as typeof filterSev))}
        {filterSel('Status', filterEnabled, [
          { label: 'All Status', value: 'all' },
          { label: 'Enabled', value: 'enabled' },
          { label: 'Disabled', value: 'disabled' },
        ], v => setFilterEnabled(v as FilterEnabled))}
        <input
          className="inp"
          placeholder="Search rules..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ flex: '1 1 200px', minWidth: 160, fontSize: 12 }}
        />
      </div>

      {/* Table */}
      <div style={{ padding: '0 24px' }}>
        {loadErr ? (
          <div style={{
            marginTop: 20, padding: '12px 16px', borderRadius: 8,
            background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)',
            fontSize: 12, color: '#FCA5A5',
          }}>{loadErr}</div>
        ) : loading ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 16 }}>
            {[1, 2, 3, 4, 5].map(i => <div key={i} className="skel" style={{ height: 52, borderRadius: 8 }} />)}
          </div>
        ) : filtered.length === 0 ? (
          <div style={{
            textAlign: 'center', padding: '60px 24px', marginTop: 16,
            background: 'rgba(255,255,255,0.01)', border: '1px solid rgba(255,255,255,0.06)',
            borderRadius: 10,
          }}>
            <Shield size={36} style={{ display: 'block', margin: '0 auto 14px', opacity: 0.15, color: '#60A5FA' }} />
            <div style={{ fontSize: 15, fontWeight: 600, color: '#5C6373', marginBottom: 6 }}>
              {rules.length === 0 ? 'No detection rules configured' : 'No rules match the current filters'}
            </div>
            <p style={{ fontSize: 12, color: '#3A4150', marginBottom: 20 }}>
              {rules.length === 0 ? 'Create detection rules to start monitoring for threats' : 'Try adjusting the filters above'}
            </p>
            {rules.length === 0 && (
              <button onClick={openCreate} style={{
                display: 'inline-flex', alignItems: 'center', gap: 6,
                padding: '9px 20px', borderRadius: 8, background: '#3B82F6',
                border: 'none', color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer',
              }}>
                <Plus size={14} /> Create Your First Rule
              </button>
            )}
          </div>
        ) : (
          <div style={{
            marginTop: 16, background: 'rgba(255,255,255,0.01)',
            border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10, overflow: 'hidden',
          }}>
            {/* Table header */}
            <div style={{
              display: 'grid', gridTemplateColumns: '1fr 100px 100px 90px 60px 72px',
              padding: '8px 16px',
              borderBottom: '1px solid rgba(255,255,255,0.06)',
              background: 'rgba(255,255,255,0.025)',
            }}>
              {['Name', 'Type', 'Severity', 'MITRE', 'Enabled', ''].map(col => (
                <div key={col} style={{
                  fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
                  letterSpacing: '1px', color: '#5C6373',
                  textAlign: col === '' ? 'right' : 'left',
                }}>{col}</div>
              ))}
            </div>
            {/* Rows */}
            {filtered.map(rule => (
              <RuleRow
                key={rule.id}
                rule={rule}
                isToggling={togglingId === rule.id}
                isDeleting={deleting && deleteId === rule.id}
                deleteId={deleteId}
                onToggle={() => handleToggle(rule)}
                onEdit={() => openEdit(rule)}
                onDeleteClick={() => setDeleteId(rule.id)}
                onDeleteConfirm={handleDeleteConfirm}
                onDeleteCancel={() => setDeleteId(null)}
              />
            ))}
          </div>
        )}
      </div>

      {/* Modal */}
      {showModal && (
        <RuleModal
          editRule={editRule}
          onClose={() => { setShowModal(false); setEditRule(null) }}
          onSaved={handleSaved}
        />
      )}
    </div>
  )
}
