import { useState } from 'react'
import { Sparkles, Shield, ChevronRight, CheckCircle, AlertTriangle, Loader2, Code2, Import } from 'lucide-react'
import { Modal, ModalBody, ModalFooter } from '@/components/ui/Modal'
import { apiClient } from '@/api/client'
import { extractApiError } from '@/lib/utils'

// ─── Types ────────────────────────────────────────────────────────────────────

interface GenerateResult {
  yaml_text: string
  title: string
  description: string
  severity: string
  category: string | null
  mitre_techniques: string[]
  mitre_tactics: string[]
  conditions: unknown[]
  conditions_count: number
  attempts: number
  ready: boolean
  error: string | null
}

interface ImportResult {
  rule_id: string
  title: string
  created: boolean
  error: string | null
}

// ─── Severity badge ───────────────────────────────────────────────────────────

const SEV_STYLE: Record<string, { bg: string; color: string }> = {
  critical: { bg: 'rgba(239,68,68,0.12)',   color: '#F87171' },
  high:     { bg: 'rgba(249,115,22,0.12)',  color: '#FB923C' },
  medium:   { bg: 'rgba(245,158,11,0.12)',  color: '#FBBF24' },
  low:      { bg: 'rgba(107,114,128,0.15)', color: '#9CA3AF' },
}

function SevBadge({ severity }: { severity: string }) {
  const s = SEV_STYLE[severity] ?? SEV_STYLE.low
  return (
    <span style={{
      padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700,
      textTransform: 'capitalize', letterSpacing: '0.04em',
      background: s.bg, color: s.color,
    }}>{severity}</span>
  )
}

// ─── Category hints ───────────────────────────────────────────────────────────

const CATEGORY_OPTIONS = [
  { value: '',                    label: 'Auto-detect' },
  { value: 'process_creation',    label: 'Process Creation' },
  { value: 'network_connection',  label: 'Network Connection' },
  { value: 'authentication',      label: 'Authentication' },
  { value: 'file_event',          label: 'File Event' },
  { value: 'registry_set',        label: 'Registry' },
  { value: 'dns_query',           label: 'DNS Query' },
]

const SEVERITY_OPTIONS = [
  { value: '',         label: 'Auto-detect' },
  { value: 'critical', label: 'Critical' },
  { value: 'high',     label: 'High' },
  { value: 'medium',   label: 'Medium' },
  { value: 'low',      label: 'Low' },
]

const EXAMPLE_PROMPTS = [
  'Detect when PowerShell downloads and executes code from the internet',
  'Detect Mimikatz credential dumping via command line arguments',
  'Detect when a user logs in from two different countries within 1 hour',
  'Detect lateral movement via PsExec or WMI remote execution',
  'Detect suspicious scheduled task creation using script interpreters',
]

// ─── Main component ───────────────────────────────────────────────────────────

interface AIRuleGeneratorModalProps {
  open: boolean
  onClose: () => void
  onImported: () => void
}

export function AIRuleGeneratorModal({ open, onClose, onImported }: AIRuleGeneratorModalProps) {
  const [description,    setDescription]    = useState('')
  const [categoryHint,   setCategoryHint]   = useState('')
  const [severityHint,   setSeverityHint]   = useState('')
  const [generating,     setGenerating]     = useState(false)
  const [importing,      setImporting]      = useState(false)
  const [result,         setResult]         = useState<GenerateResult | null>(null)
  const [importDone,     setImportDone]     = useState<ImportResult | null>(null)
  const [error,          setError]          = useState<string | null>(null)
  const [showYaml,       setShowYaml]       = useState(false)

  const reset = () => {
    setResult(null)
    setImportDone(null)
    setError(null)
    setShowYaml(false)
  }

  const handleClose = () => {
    reset()
    setDescription('')
    setCategoryHint('')
    setSeverityHint('')
    onClose()
  }

  const handleGenerate = async () => {
    if (!description.trim() || generating) return
    reset()
    setGenerating(true)
    try {
      const resp = await apiClient.post<{ data: GenerateResult }>('/sigma/generate', {
        description: description.trim(),
        category_hint: categoryHint || undefined,
        severity_hint: severityHint || undefined,
      })
      const data = resp.data.data
      setResult(data)
      if (!data.ready) setError(data.error ?? 'Generation failed')
    } catch (e) {
      setError(extractApiError(e))
    } finally {
      setGenerating(false)
    }
  }

  const handleImport = async () => {
    if (!result?.ready || importing) return
    setImporting(true)
    try {
      const resp = await apiClient.post<{ data: ImportResult }>('/sigma/import', {
        yaml_text: result.yaml_text,
      })
      const data = resp.data.data
      setImportDone(data)
      onImported()
    } catch (e) {
      setError(extractApiError(e))
    } finally {
      setImporting(false)
    }
  }

  const inputStyle = {
    width: '100%', background: '#0D1117', border: '1px solid rgba(255,255,255,0.08)',
    borderRadius: 8, color: '#E2E8F0', fontSize: 13,
    outline: 'none', padding: '10px 12px', boxSizing: 'border-box' as const,
  }

  const selectStyle = {
    ...inputStyle,
    padding: '8px 12px', cursor: 'pointer', appearance: 'none' as const,
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title="AI Rule Generator"
      description="Describe what you want to detect in plain language"
      size="xl"
    >
      <ModalBody className="space-y-4">

        {/* Description input */}
        <div className="space-y-2">
          <label style={{ fontSize: 11, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>
            Detection Description
          </label>
          <textarea
            value={description}
            onChange={e => setDescription(e.target.value)}
            placeholder="e.g. Detect when PowerShell downloads and executes code from the internet..."
            rows={4}
            style={{ ...inputStyle, resize: 'vertical', lineHeight: 1.6 }}
            onKeyDown={e => { if (e.key === 'Enter' && e.ctrlKey) handleGenerate() }}
          />
          <p style={{ fontSize: 11, color: '#3D4451' }}>Ctrl+Enter to generate • Arabic and English supported</p>
        </div>

        {/* Example prompts */}
        <div className="space-y-1.5">
          <p style={{ fontSize: 11, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>
            Examples
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {EXAMPLE_PROMPTS.map((p) => (
              <button
                key={p}
                onClick={() => setDescription(p)}
                style={{
                  padding: '4px 10px', borderRadius: 6, fontSize: 11,
                  background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.2)',
                  color: '#93C5FD', cursor: 'pointer', textAlign: 'left',
                  transition: 'background 150ms',
                }}
              >{p}</button>
            ))}
          </div>
        </div>

        {/* Hints row */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div className="space-y-1.5">
            <label style={{ fontSize: 11, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>
              Category Hint
            </label>
            <select value={categoryHint} onChange={e => setCategoryHint(e.target.value)} style={selectStyle}>
              {CATEGORY_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>
          <div className="space-y-1.5">
            <label style={{ fontSize: 11, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>
              Severity Hint
            </label>
            <select value={severityHint} onChange={e => setSeverityHint(e.target.value)} style={selectStyle}>
              {SEVERITY_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>
        </div>

        {/* Error state */}
        {error && (
          <div style={{
            padding: '10px 14px', borderRadius: 8, fontSize: 12,
            background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)',
            color: '#FCA5A5', display: 'flex', alignItems: 'flex-start', gap: 8,
          }}>
            <AlertTriangle size={14} style={{ flexShrink: 0, marginTop: 1 }} />
            <span>{error}</span>
          </div>
        )}

        {/* Import success */}
        {importDone && (
          <div style={{
            padding: '10px 14px', borderRadius: 8, fontSize: 12,
            background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.2)',
            color: '#6EE7B7', display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <CheckCircle size={14} />
            Rule "{importDone.title}" imported successfully and is now active.
          </div>
        )}

        {/* Generated result */}
        {result?.ready && (
          <div style={{
            borderRadius: 10, border: '1px solid rgba(59,130,246,0.2)',
            background: 'rgba(59,130,246,0.04)', overflow: 'hidden',
          }}>
            {/* Rule header */}
            <div style={{
              padding: '12px 16px', borderBottom: '1px solid rgba(59,130,246,0.12)',
              display: 'flex', alignItems: 'center', gap: 10,
            }}>
              <Shield size={14} style={{ color: '#3B82F6', flexShrink: 0 }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <p style={{ fontSize: 13, fontWeight: 600, color: '#E2E8F0', margin: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {result.title}
                </p>
                {result.description && (
                  <p style={{ fontSize: 11, color: '#5C6373', margin: '2px 0 0' }}>
                    {result.description}
                  </p>
                )}
              </div>
              <SevBadge severity={result.severity} />
            </div>

            {/* Rule metadata */}
            <div style={{ padding: '10px 16px', display: 'flex', flexWrap: 'wrap', gap: 16 }}>
              {result.category && (
                <div>
                  <p style={{ fontSize: 10, color: '#3D4451', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, margin: 0 }}>Category</p>
                  <p style={{ fontSize: 12, color: '#93C5FD', margin: '2px 0 0', fontFamily: 'monospace' }}>{result.category}</p>
                </div>
              )}
              <div>
                <p style={{ fontSize: 10, color: '#3D4451', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, margin: 0 }}>Conditions</p>
                <p style={{ fontSize: 12, color: '#E2E8F0', margin: '2px 0 0' }}>{result.conditions_count} rule{result.conditions_count !== 1 ? 's' : ''}</p>
              </div>
              {result.mitre_techniques.length > 0 && (
                <div>
                  <p style={{ fontSize: 10, color: '#3D4451', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, margin: 0 }}>MITRE</p>
                  <div style={{ display: 'flex', gap: 4, marginTop: 2 }}>
                    {result.mitre_techniques.map(t => (
                      <span key={t} style={{
                        padding: '1px 6px', borderRadius: 4, fontSize: 11, fontFamily: 'monospace',
                        background: 'rgba(139,92,246,0.12)', color: '#C4B5FD',
                        border: '1px solid rgba(139,92,246,0.2)',
                      }}>{t}</span>
                    ))}
                  </div>
                </div>
              )}
              <div>
                <p style={{ fontSize: 10, color: '#3D4451', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, margin: 0 }}>Attempts</p>
                <p style={{ fontSize: 12, color: '#5C6373', margin: '2px 0 0' }}>{result.attempts}</p>
              </div>
            </div>

            {/* YAML toggle */}
            <div style={{ borderTop: '1px solid rgba(59,130,246,0.12)' }}>
              <button
                onClick={() => setShowYaml(v => !v)}
                style={{
                  width: '100%', padding: '8px 16px', display: 'flex', alignItems: 'center', gap: 6,
                  background: 'transparent', border: 'none', cursor: 'pointer', color: '#5C6373', fontSize: 11,
                }}
              >
                <Code2 size={12} />
                {showYaml ? 'Hide' : 'Show'} generated Sigma YAML
                <ChevronRight size={11} style={{ marginLeft: 'auto', transform: showYaml ? 'rotate(90deg)' : undefined, transition: 'transform 150ms' }} />
              </button>
              {showYaml && (
                <pre style={{
                  margin: 0, padding: '12px 16px',
                  borderTop: '1px solid rgba(59,130,246,0.08)',
                  fontSize: 11, lineHeight: 1.7, color: '#6EE7B7',
                  fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                  background: '#060A10', overflowX: 'auto', maxHeight: 280, overflowY: 'auto',
                  whiteSpace: 'pre',
                }}>{result.yaml_text}</pre>
              )}
            </div>
          </div>
        )}

      </ModalBody>

      <ModalFooter>
        <button onClick={handleClose} style={{
          padding: '8px 16px', borderRadius: 7, fontSize: 13, fontWeight: 500,
          background: 'transparent', border: '1px solid rgba(255,255,255,0.08)',
          color: '#5C6373', cursor: 'pointer',
        }}>
          {importDone ? 'Close' : 'Cancel'}
        </button>

        {result?.ready && !importDone && (
          <button onClick={handleImport} disabled={importing} style={{
            padding: '8px 16px', borderRadius: 7, fontSize: 13, fontWeight: 600,
            background: 'rgba(59,130,246,0.15)', border: '1px solid rgba(59,130,246,0.35)',
            color: '#93C5FD', cursor: importing ? 'not-allowed' : 'pointer',
            opacity: importing ? 0.6 : 1,
            display: 'flex', alignItems: 'center', gap: 6,
          }}>
            {importing ? <Loader2 size={13} className="animate-spin" /> : <Import size={13} />}
            {importing ? 'Importing…' : 'Import Rule'}
          </button>
        )}

        {!importDone && (
          <button
            onClick={handleGenerate}
            disabled={!description.trim() || generating}
            style={{
              padding: '8px 16px', borderRadius: 7, fontSize: 13, fontWeight: 600,
              background: (!description.trim() || generating) ? 'rgba(59,130,246,0.3)' : '#3B82F6',
              border: 'none', color: '#fff',
              cursor: (!description.trim() || generating) ? 'not-allowed' : 'pointer',
              display: 'flex', alignItems: 'center', gap: 6,
            }}
          >
            {generating
              ? <><Loader2 size={13} className="animate-spin" /> Generating…</>
              : <><Sparkles size={13} /> {result ? 'Regenerate' : 'Generate Rule'}</>
            }
          </button>
        )}
      </ModalFooter>
    </Modal>
  )
}
