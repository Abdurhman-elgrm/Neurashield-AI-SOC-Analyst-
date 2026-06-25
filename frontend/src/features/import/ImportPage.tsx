import { useState, useRef, useCallback } from 'react'
import { apiClient } from '@/api/client'
import { useTenantStore } from '@/stores/tenantStore'
import { extractApiError } from '@/lib/utils'
import {
  UploadCloud, FileJson, FileText, CheckCircle2,
  AlertCircle, XCircle, Info, RefreshCw, ChevronDown, ChevronUp,
} from 'lucide-react'
import { Button } from '@/components/ui/Button'

// ─── Types ────────────────────────────────────────────────────────────────────

interface ImportResult {
  accepted:  number
  duplicate: number
  rejected:  number
  total:     number
  format:    string
  errors:    string[]
}

type UploadState =
  | { kind: 'idle' }
  | { kind: 'uploading'; progress: number }
  | { kind: 'success'; result: ImportResult; filename: string }
  | { kind: 'error'; message: string }

// ─── Supported format cards ───────────────────────────────────────────────────

const FORMATS = [
  {
    ext: 'JSON',
    icon: FileJson,
    color: '#60A5FA',
    bg: 'rgba(96,165,250,0.1)',
    desc: 'Array of event objects',
    example: '[{"hostname":"srv01","category":"process","timestamp":"2024-01-15T10:00:00Z","process":{"name":"cmd.exe"}}]',
  },
  {
    ext: 'JSONL',
    icon: FileText,
    color: '#34D399',
    bg: 'rgba(52,211,153,0.1)',
    desc: 'One JSON object per line',
    example: '{"hostname":"srv01","category":"network","timestamp":"2024-01-15T10:00:00Z"}\n{"hostname":"ws02","category":"auth","timestamp":"2024-01-15T10:01:00Z"}',
  },
  {
    ext: 'CSV',
    icon: FileText,
    color: '#FBBF24',
    bg: 'rgba(251,191,36,0.1)',
    desc: 'Header row + data rows',
    example: 'hostname,category,timestamp,username\nsrv01,auth,2024-01-15T10:00:00Z,DOMAIN\\jsmith',
  },
] as const

const FIELD_DOCS: Array<{ field: string; required: boolean; desc: string }> = [
  { field: 'hostname',  required: true,  desc: 'Source host name or IP' },
  { field: 'category',  required: true,  desc: 'process | network | file | auth | registry | dns | other' },
  { field: 'timestamp', required: false, desc: 'ISO 8601 or Unix epoch. Defaults to upload time' },
  { field: 'event_id',  required: false, desc: 'Unique ID for deduplication. Auto-generated if absent' },
  { field: 'os_type',   required: false, desc: 'windows | linux | macos. Defaults to "windows"' },
  { field: 'process',   required: false, desc: 'Object — name, pid, cmdline, path, parent_pid' },
  { field: 'user',      required: false, desc: 'Object — name, domain, sid, is_admin' },
  { field: 'network',   required: false, desc: 'Object — src_ip, dst_ip, dst_port, protocol' },
  { field: 'file',      required: false, desc: 'Object — path, name, hash_md5, hash_sha256' },
]

// ─── Drop zone ────────────────────────────────────────────────────────────────

function DropZone({
  onFile,
  disabled,
}: {
  onFile: (f: File) => void
  disabled: boolean
}) {
  const [dragging, setDragging] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      setDragging(false)
      if (disabled) return
      const f = e.dataTransfer.files[0]
      if (f) onFile(f)
    },
    [onFile, disabled],
  )

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => !disabled && inputRef.current?.click()}
      style={{
        border: `2px dashed ${dragging ? '#3B82F6' : 'rgba(255,255,255,0.12)'}`,
        borderRadius: 12,
        padding: '48px 32px',
        textAlign: 'center',
        cursor: disabled ? 'not-allowed' : 'pointer',
        background: dragging ? 'rgba(59,130,246,0.06)' : 'rgba(255,255,255,0.015)',
        transition: 'all 150ms',
        opacity: disabled ? 0.5 : 1,
      }}
    >
      <UploadCloud
        size={40}
        style={{
          color: dragging ? '#60A5FA' : '#3A4150',
          display: 'block',
          margin: '0 auto 16px',
          transition: 'color 150ms',
        }}
      />
      <div style={{ fontSize: 14, fontWeight: 600, color: '#F5F7FA', marginBottom: 6 }}>
        Drop your log file here
      </div>
      <div style={{ fontSize: 12, color: '#5C6373', marginBottom: 16 }}>
        or click to browse — supports <strong style={{ color: '#B8C0CC' }}>JSON, JSONL, CSV</strong>
      </div>
      <div style={{ fontSize: 10, color: '#3A4150' }}>Maximum file size: 50 MB · Up to 100,000 events</div>

      <input
        ref={inputRef}
        type="file"
        accept=".json,.jsonl,.ndjson,.csv,application/json,text/csv,text/plain"
        style={{ display: 'none' }}
        onChange={(e) => {
          const f = e.target.files?.[0]
          if (f) onFile(f)
          if (inputRef.current) inputRef.current.value = ''
        }}
      />
    </div>
  )
}

// ─── Progress bar ─────────────────────────────────────────────────────────────

function ProgressBar({ value }: { value: number }) {
  return (
    <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2, overflow: 'hidden' }}>
      <div style={{
        height: '100%',
        width: `${value}%`,
        background: 'linear-gradient(90deg, #3B82F6, #38BDF8)',
        borderRadius: 2,
        transition: 'width 200ms ease',
        boxShadow: '0 0 8px rgba(59,130,246,0.5)',
      }} />
    </div>
  )
}

// ─── Result card ──────────────────────────────────────────────────────────────

function ResultCard({ result, filename }: { result: ImportResult; filename: string }) {
  const [errOpen, setErrOpen] = useState(false)
  const hasErrors = result.errors.length > 0

  return (
    <div style={{
      borderRadius: 10,
      border: '1px solid rgba(16,185,129,0.25)',
      background: 'rgba(16,185,129,0.04)',
      overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '14px 16px',
        borderBottom: '1px solid rgba(255,255,255,0.05)',
      }}>
        <CheckCircle2 size={18} style={{ color: '#10B981', flexShrink: 0 }} />
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: '#F5F7FA' }}>
            Import complete — {filename}
          </div>
          <div style={{ fontSize: 11, color: '#5C6373', marginTop: 2 }}>
            Events are now flowing through the detection pipeline
          </div>
        </div>
        <span style={{
          fontSize: 9, fontWeight: 700,
          padding: '2px 7px', borderRadius: 4,
          background: 'rgba(59,130,246,0.12)', color: '#60A5FA',
          fontFamily: "'JetBrains Mono', monospace",
          letterSpacing: '0.5px',
        }}>
          {result.format}
        </span>
      </div>

      {/* Stats */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)',
        gap: 1, background: 'rgba(255,255,255,0.04)',
      }}>
        {[
          { label: 'Total', value: result.total,     color: '#B8C0CC' },
          { label: 'Accepted', value: result.accepted, color: '#10B981' },
          { label: 'Duplicate', value: result.duplicate, color: '#F59E0B' },
          { label: 'Rejected', value: result.rejected,  color: '#F87171' },
        ].map(({ label, value, color }) => (
          <div key={label} style={{
            background: '#0D0D0D',
            padding: '14px 12px',
            textAlign: 'center',
          }}>
            <div style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 24, fontWeight: 700, color, marginBottom: 4,
            }}>
              {value.toLocaleString()}
            </div>
            <div style={{ fontSize: 9, fontWeight: 600, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '1px' }}>
              {label}
            </div>
          </div>
        ))}
      </div>

      {/* Errors (collapsible) */}
      {hasErrors && (
        <div style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}>
          <button
            onClick={() => setErrOpen(v => !v)}
            style={{
              display: 'flex', alignItems: 'center', gap: 8,
              width: '100%', padding: '10px 16px',
              background: 'none', border: 'none', cursor: 'pointer',
              color: '#F59E0B', fontSize: 11, fontWeight: 600,
            }}
          >
            <AlertCircle size={13} />
            {result.errors.length} parse warning{result.errors.length !== 1 ? 's' : ''}
            {errOpen ? <ChevronUp size={12} style={{ marginLeft: 'auto' }} /> : <ChevronDown size={12} style={{ marginLeft: 'auto' }} />}
          </button>
          {errOpen && (
            <div style={{ padding: '0 16px 14px' }}>
              {result.errors.map((e, i) => (
                <div key={i} style={{
                  fontSize: 11, color: '#8B95A7',
                  fontFamily: "'JetBrains Mono', monospace",
                  padding: '3px 0',
                  borderBottom: i < result.errors.length - 1 ? '1px solid rgba(255,255,255,0.03)' : 'none',
                }}>
                  {e}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Schema reference (collapsible) ───────────────────────────────────────────

function SchemaRef() {
  const [open, setOpen] = useState(false)

  return (
    <div style={{
      borderRadius: 8, border: '1px solid rgba(59,130,246,0.15)',
      background: 'rgba(59,130,246,0.04)', overflow: 'hidden',
    }}>
      <button
        onClick={() => setOpen(v => !v)}
        style={{
          display: 'flex', alignItems: 'center', gap: 8,
          width: '100%', padding: '10px 14px',
          background: 'none', border: 'none', cursor: 'pointer',
          color: '#60A5FA', fontSize: 11, fontWeight: 700,
        }}
      >
        <Info size={13} />
        Event Schema Reference
        {open ? <ChevronUp size={12} style={{ marginLeft: 'auto' }} /> : <ChevronDown size={12} style={{ marginLeft: 'auto' }} />}
      </button>
      {open && (
        <div style={{ padding: '0 14px 14px' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                {['Field', 'Required', 'Description'].map(h => (
                  <th key={h} style={{
                    textAlign: 'left', padding: '4px 8px',
                    fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
                    letterSpacing: '1px', color: '#5C6373',
                    borderBottom: '1px solid rgba(255,255,255,0.06)',
                  }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {FIELD_DOCS.map(({ field, required, desc }) => (
                <tr key={field}>
                  <td style={{ padding: '5px 8px' }}>
                    <code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#93C5FD' }}>
                      {field}
                    </code>
                  </td>
                  <td style={{ padding: '5px 8px' }}>
                    <span style={{
                      fontSize: 9, fontWeight: 700,
                      color: required ? '#F87171' : '#5C6373',
                    }}>
                      {required ? 'YES' : 'no'}
                    </span>
                  </td>
                  <td style={{ padding: '5px 8px', fontSize: 11, color: '#8B95A7' }}>{desc}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <div style={{ marginTop: 12, fontSize: 10, color: '#3A4150' }}>
            All unrecognized fields are stored in the <code style={{ color: '#93C5FD' }}>raw</code> object and
            are searchable via Threat Hunt.
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export function ImportPage({ embedded = false }: { embedded?: boolean }) {
  const tenantId = useTenantStore(s => s.activeTenant?.id)
  const [state, setState] = useState<UploadState>({ kind: 'idle' })

  const upload = async (file: File) => {
    if (!tenantId) return
    setState({ kind: 'uploading', progress: 0 })

    const form = new FormData()
    form.append('file', file)

    try {
      const resp = await apiClient.post<{ data: ImportResult }>(
        '/imports/upload',
        form,
        {
          headers: { 'Content-Type': 'multipart/form-data' },
          onUploadProgress: (e) => {
            const pct = e.total ? Math.round((e.loaded / e.total) * 95) : 50
            setState({ kind: 'uploading', progress: pct })
          },
        },
      )
      setState({ kind: 'success', result: resp.data.data!, filename: file.name })
    } catch (err) {
      setState({ kind: 'error', message: extractApiError(err) })
    }
  }

  const reset = () => setState({ kind: 'idle' })

  return (
    <div style={{
      display: 'flex', flexDirection: 'column',
      ...(embedded ? { flex: 1, overflow: 'auto' } : { height: 'calc(100vh - 50px - 40px)', overflow: 'hidden' }),
    }}>

      {/* Page header */}
      <div style={{
        paddingBottom: 12,
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        flexShrink: 0,
      }}>
        <h1 style={{ fontSize: 17, fontWeight: 800, fontFamily: "'Space Grotesk', sans-serif", color: '#F5F7FA' }}>
          Log Import
        </h1>
        <p style={{ fontSize: 12, color: '#5C6373', marginTop: 2 }}>
          Upload log files to feed historical or external events into the detection pipeline
        </p>
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflowY: 'auto', paddingTop: 20 }}>
        <div style={{ maxWidth: 760, display: 'flex', flexDirection: 'column', gap: 20 }}>

          {/* Format cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
            {FORMATS.map(({ ext, icon: Icon, color, bg, desc }) => (
              <div key={ext} style={{
                padding: '14px 16px', borderRadius: 8,
                background: bg, border: `1px solid ${color}30`,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                  <Icon size={14} style={{ color }} />
                  <span style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: 11, fontWeight: 700, color,
                  }}>
                    .{ext.toLowerCase()}
                  </span>
                </div>
                <div style={{ fontSize: 11, color: '#8B95A7' }}>{desc}</div>
              </div>
            ))}
          </div>

          {/* Upload zone or result */}
          {state.kind === 'idle' && (
            <DropZone onFile={upload} disabled={false} />
          )}

          {state.kind === 'uploading' && (
            <div style={{
              padding: '32px 24px',
              borderRadius: 12, border: '1px solid rgba(59,130,246,0.2)',
              background: 'rgba(59,130,246,0.04)',
              textAlign: 'center',
            }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: '#F5F7FA', marginBottom: 8 }}>
                Uploading and processing…
              </div>
              <div style={{ marginBottom: 12 }}>
                <ProgressBar value={state.progress} />
              </div>
              <div style={{ fontSize: 11, color: '#5C6373' }}>
                Parsing events and injecting into the detection pipeline
              </div>
            </div>
          )}

          {state.kind === 'success' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <ResultCard result={state.result} filename={state.filename} />
              <div style={{ display: 'flex', gap: 8 }}>
                <Button variant="primary" onClick={reset}>
                  <UploadCloud size={13} />
                  Upload Another File
                </Button>
                <Button variant="ghost" onClick={() => window.open('/investigations', '_self')}>
                  View Investigations
                </Button>
              </div>
            </div>
          )}

          {state.kind === 'error' && (
            <div style={{
              padding: '16px 20px', borderRadius: 10,
              border: '1px solid rgba(239,68,68,0.25)',
              background: 'rgba(239,68,68,0.05)',
            }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                <XCircle size={16} style={{ color: '#F87171', flexShrink: 0, marginTop: 1 }} />
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: '#F87171', marginBottom: 4 }}>
                    Import failed
                  </div>
                  <div style={{ fontSize: 12, color: '#FCA5A5' }}>{state.message}</div>
                </div>
              </div>
              <button
                onClick={reset}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  marginTop: 14, fontSize: 11, fontWeight: 600,
                  color: '#F87171', background: 'none', border: 'none', cursor: 'pointer',
                }}
              >
                <RefreshCw size={12} /> Try again
              </button>
            </div>
          )}

          {/* Schema reference */}
          <SchemaRef />

          {/* Pipeline info */}
          <div style={{
            padding: '14px 16px', borderRadius: 8,
            background: 'rgba(139,92,246,0.04)',
            border: '1px solid rgba(139,92,246,0.15)',
          }}>
            <div style={{
              fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
              letterSpacing: '1.5px', color: '#A78BFA', marginBottom: 10,
            }}>
              How imported events are processed
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {[
                ['Normalization', 'Events are standardized to ECS schema and enriched with process tree context'],
                ['Threat Intel',  'IPs checked against threat intelligence feeds, GeoIP enrichment applied'],
                ['Detection',     'Sigma rules evaluated — matching events create alerts'],
                ['Correlation',   'Related alerts grouped into investigation cases'],
                ['AI Analysis',   'High-severity cases receive automated AI analysis'],
              ].map(([step, desc], i) => (
                <div key={step} style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                  <span style={{
                    width: 18, height: 18, borderRadius: '50%', flexShrink: 0,
                    background: 'rgba(139,92,246,0.15)', border: '1px solid rgba(139,92,246,0.25)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 9, fontWeight: 700, color: '#A78BFA',
                  }}>
                    {i + 1}
                  </span>
                  <div>
                    <span style={{ fontSize: 11, fontWeight: 600, color: '#C4B5FD' }}>{step}</span>
                    <span style={{ fontSize: 11, color: '#5C6373' }}> — {desc}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

        </div>
      </div>
    </div>
  )
}
