import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  Search, RefreshCw, Download, X, Activity,
  Cpu, Wifi, FileText, Key, Database, Globe, Settings, Copy, FolderSearch,
} from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { SevBadge } from '@/components/ui/SevBadge'
import { useEvents } from './hooks/useEvents'
import { eventsApi, type EventResponse } from '@/api/events'
import { formatDateShort, formatDateTime } from '@/lib/timezone'

// ─── Category config ──────────────────────────────────────────────────────────

const categoryConfig: Record<string, {
  icon: React.ElementType
  color: string
  label: string
}> = {
  process:  { icon: Cpu,      color: '#60A5FA', label: 'Process'  },
  network:  { icon: Wifi,     color: '#34D399', label: 'Network'  },
  file:     { icon: FileText, color: '#FBBF24', label: 'File'     },
  auth:     { icon: Key,      color: '#F87171', label: 'Auth'     },
  registry: { icon: Database, color: '#C084FC', label: 'Registry' },
  dns:      { icon: Globe,    color: '#22D3EE', label: 'DNS'      },
  system:   { icon: Settings, color: '#94A3B8', label: 'System'   },
  other:    { icon: Activity, color: '#64748B', label: 'Other'    },
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatEventTime(ts: string): string {
  return formatDateShort(ts)
}

const EVENT_ID_DESCRIPTIONS: Record<string, string> = {
  '4624': 'Successful logon',
  '4625': 'Failed logon',
  '4634': 'Logoff',
  '4648': 'Logon with explicit credentials',
  '4672': 'Special privileges assigned',
  '4688': 'Process created',
  '4698': 'Scheduled task created',
  '4702': 'Scheduled task updated',
  '4719': 'Audit policy changed',
  '4720': 'User account created',
  '4728': 'User added to privileged group',
  '4732': 'User added to security group',
  '4768': 'Kerberos TGT request',
  '4769': 'Kerberos service ticket',
  '4776': 'Credential validation',
  '7045': 'Service installed',
  '1102': 'Audit log cleared',
  '4104': 'PowerShell script block',
}

function buildEventSummary(event: EventResponse): string {
  const process = event.process as Record<string, unknown> | null
  const network = event.network as Record<string, unknown> | null
  const file    = event.file    as Record<string, unknown> | null
  const user    = event.user    as Record<string, unknown> | null

  // Process events
  if (event.process_name) {
    const cmd = typeof process?.command_line === 'string'
      ? ` — ${(process.command_line as string).slice(0, 100)}`
      : ''
    return `${event.process_name}${cmd}`
  }

  // Network events
  if (event.dest_ip || event.source_ip) {
    const src   = event.source_ip ?? '?'
    const dst   = event.dest_ip   ?? '?'
    const port  = network?.dst_port ? `:${network.dst_port}` : ''
    const proto = typeof network?.protocol === 'string' ? ` (${network.protocol})` : ''
    return `${src} → ${dst}${port}${proto}`
  }

  // File events
  const filePath = file?.path
  if (typeof filePath === 'string') {
    const op = file?.action ?? file?.operation ?? 'access'
    return `${op}: ${filePath.slice(-60)}`
  }

  // Auth / system events — look up Windows EventID for human-readable label
  const username = event.username
    ?? (typeof user?.name === 'string' ? user.name : null)

  const winEventId = event.raw?.windows_event_id
    ?? event.raw?.EventID
    ?? event.raw?.event_id_windows
    ?? null

  if (winEventId != null) {
    const desc = EVENT_ID_DESCRIPTIONS[String(winEventId)] ?? `Event ${winEventId}`
    return username ? `${desc} — ${username}` : desc
  }

  if (username) {
    return `Auth event — ${username}`
  }

  // Category-based fallback — never show raw IDs
  const categoryDescriptions: Record<string, string> = {
    auth:     'Authentication event',
    process:  'Process activity',
    network:  'Network connection',
    file:     'File system activity',
    registry: 'Registry change',
    dns:      'DNS query',
    system:   'System event',
    other:    'Security event',
  }
  return categoryDescriptions[event.category] ?? 'Security event'
}

// ─── Section / DetailRow helper components ────────────────────────────────────

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 18 }}>
      <div style={{
        fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
        letterSpacing: '1.5px', color: '#5C6373', marginBottom: 8,
      }}>
        {title}
      </div>
      <div style={{
        background: 'rgba(255,255,255,0.02)',
        border: '1px solid rgba(255,255,255,0.05)',
        borderRadius: 6, padding: '8px 10px',
        display: 'flex', flexDirection: 'column', gap: 6,
      }}>
        {children}
      </div>
    </div>
  )
}

function DetailRow({ label, value, mono }: {
  label: string
  value: string
  mono?: boolean
}) {
  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
      <span style={{
        fontSize: 10, color: '#5C6373', minWidth: 90, flexShrink: 0, paddingTop: 1,
      }}>
        {label}
      </span>
      <span style={{
        fontSize: 11, color: '#B8C0CC', wordBreak: 'break-all',
        fontFamily: mono ? "'JetBrains Mono', monospace" : "'Inter', sans-serif",
      }}>
        {value}
      </span>
    </div>
  )
}

// ─── EventRow ─────────────────────────────────────────────────────────────────

function EventRow({ event, onClick }: { event: EventResponse; onClick: () => void }) {
  const [hovered, setHovered] = useState(false)
  const cat = categoryConfig[event.category] ?? {
    icon: Activity, color: '#64748B', label: 'Other',
  }
  const CatIcon = cat.icon
  const summary = buildEventSummary(event)

  return (
    <tr
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        borderLeft: '3px solid transparent',
        borderBottom: '1px solid rgba(255,255,255,0.03)',
        background: hovered ? 'rgba(255,255,255,0.02)' : 'transparent',
        cursor: 'pointer', transition: 'background 120ms',
      }}
    >
      {/* Severity */}
      <td style={{ padding: '7px 12px' }}>
        <SevBadge sev={event.severity} />
      </td>

      {/* Time */}
      <td style={{ padding: '7px 12px' }}>
        <span style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11, color: '#5C6373', whiteSpace: 'nowrap',
        }}>
          {formatEventTime(event.event_timestamp)}
        </span>
      </td>

      {/* Category */}
      <td style={{ padding: '7px 12px' }}>
        <span style={{
          display: 'inline-flex', alignItems: 'center', gap: 5,
          fontSize: 11, color: cat.color,
        }}>
          <CatIcon size={12} />
          {cat.label}
        </span>
      </td>

      {/* Hostname */}
      <td style={{ padding: '7px 12px' }}>
        <span style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11, color: '#B8C0CC',
        }}>
          {event.host_name ?? '—'}
        </span>
      </td>

      {/* Summary */}
      <td style={{ padding: '7px 12px', maxWidth: 400 }}>
        <span style={{
          fontSize: 12, color: '#8B95A7',
          overflow: 'hidden', textOverflow: 'ellipsis',
          whiteSpace: 'nowrap', display: 'block',
        }}>
          {summary}
        </span>
      </td>

      {/* Agent ID (short) */}
      <td style={{ padding: '7px 12px' }}>
        <span style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 10, color: '#3A4150',
        }}>
          {event.agent_id?.slice(0, 8) ?? '—'}
        </span>
      </td>
    </tr>
  )
}

// ─── EventDrawer ──────────────────────────────────────────────────────────────

function EventDrawer({ event, onClose }: { event: EventResponse; onClose: () => void }) {
  const cat = categoryConfig[event.category] ?? {
    icon: Activity, color: '#64748B', label: 'Other',
  }
  const CatIcon = cat.icon

  const process = event.process as Record<string, unknown> | null
  const network = event.network as Record<string, unknown> | null
  const file    = event.file    as Record<string, unknown> | null
  const user    = event.user    as Record<string, unknown> | null
  const reg     = event.registry as Record<string, unknown> | null

  return (
    <>
      <div onClick={onClose} style={{
        position: 'fixed', inset: 0, zIndex: 49,
        background: 'rgba(0,0,0,0.4)',
      }} />
      <div style={{
        position: 'fixed', right: 0, top: 50,
        height: 'calc(100vh - 50px)', width: 460,
        background: '#0A0A0A',
        borderLeft: '1px solid rgba(255,255,255,0.07)',
        display: 'flex', flexDirection: 'column',
        zIndex: 50,
        animation: 'slideInRight 200ms ease both',
      }}>

        {/* Header */}
        <div style={{
          padding: '14px 16px',
          borderBottom: '1px solid rgba(255,255,255,0.06)',
          display: 'flex', alignItems: 'center',
          justifyContent: 'space-between', flexShrink: 0,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <CatIcon size={16} style={{ color: cat.color }} />
            <div>
              <div style={{ fontSize: 13, fontWeight: 600, color: '#F5F7FA' }}>
                {cat.label} Event
              </div>
              <div style={{
                fontSize: 10, color: '#5C6373', marginTop: 2,
                fontFamily: "'JetBrains Mono', monospace",
              }}>
                {event.id}
              </div>
            </div>
          </div>
          <button onClick={onClose} style={{
            background: 'none', border: 'none',
            color: '#5C6373', cursor: 'pointer', padding: 4,
          }}>
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>

          {/* Meta grid */}
          <div style={{
            display: 'grid', gridTemplateColumns: '1fr 1fr',
            gap: '10px 16px', marginBottom: 20,
          }}>
            {([
              ['Severity',  <SevBadge sev={event.severity} />],
              ['Timestamp', formatDateTime(event.event_timestamp)],
              ['Hostname',  event.host_name ?? '—'],
              ['Category',  cat.label],
              ['Agent',     event.agent_id ? event.agent_id.slice(0, 8) + '...' : '—'],
              ['Tags',      event.tags.length > 0 ? event.tags.join(', ') : '—'],
            ] as [string, React.ReactNode][]).map(([label, value]) => (
              <div key={String(label)}>
                <div style={{
                  fontSize: 9, color: '#5C6373', textTransform: 'uppercase',
                  letterSpacing: '1px', marginBottom: 3,
                }}>
                  {label}
                </div>
                <div style={{
                  fontSize: 11, color: '#B8C0CC',
                  fontFamily: "'JetBrains Mono', monospace",
                }}>
                  {value}
                </div>
              </div>
            ))}
          </div>

          {/* Process */}
          {(event.process_name || process) && (
            <Section title="Process">
              {[
                ['Name',         event.process_name],
                ['PID',          process?.pid != null ? String(process.pid) : null],
                ['Parent',       process?.parent_name as string | null],
                ['Command Line', process?.command_line as string | null],
              ].filter(([, v]) => v).map(([k, v]) => (
                <DetailRow key={String(k)} label={String(k)} value={String(v)} mono={k === 'Command Line'} />
              ))}
            </Section>
          )}

          {/* Network */}
          {(event.source_ip || event.dest_ip || network) && (
            <Section title="Network">
              {[
                ['Source IP',   event.source_ip],
                ['Dest IP',     event.dest_ip],
                ['Dest Port',   network?.dst_port != null ? String(network.dst_port) : null],
                ['Protocol',    network?.protocol as string | null],
                ['Direction',   network?.direction as string | null],
              ].filter(([, v]) => v).map(([k, v]) => (
                <DetailRow key={String(k)} label={String(k)} value={String(v)} mono />
              ))}
            </Section>
          )}

          {/* File */}
          {file && (
            <Section title="File">
              {[
                ['Path',      file.path as string | null],
                ['Operation', file.operation as string | null],
                ['SHA-256',   file.hash_sha256 as string | null],
                ['Size',      file.size != null ? String(file.size) : null],
              ].filter(([, v]) => v).map(([k, v]) => (
                <DetailRow key={String(k)} label={String(k)} value={String(v)} mono={k === 'SHA-256' || k === 'Path'} />
              ))}
            </Section>
          )}

          {/* User */}
          {(event.username || user) && (
            <Section title="User">
              {[
                ['Name',   event.username ?? (user?.name as string | null)],
                ['Domain', user?.domain as string | null],
                ['SID',    user?.sid as string | null],
              ].filter(([, v]) => v).map(([k, v]) => (
                <DetailRow key={String(k)} label={String(k)} value={String(v)} />
              ))}
            </Section>
          )}

          {/* Registry */}
          {reg && (
            <Section title="Registry">
              {[
                ['Key',       reg.key as string | null],
                ['Value',     reg.value as string | null],
                ['Data',      reg.data as string | null],
                ['Operation', reg.operation as string | null],
              ].filter(([, v]) => v).map(([k, v]) => (
                <DetailRow key={String(k)} label={String(k)} value={String(v)} mono />
              ))}
            </Section>
          )}

          {/* IDs */}
          {(event.correlation_id || event.session_id || event.process_tree_id) && (
            <Section title="Correlation">
              {[
                ['Correlation', event.correlation_id],
                ['Session',     event.session_id],
                ['Process Tree',event.process_tree_id],
                ['Event Chain', event.event_chain_id],
              ].filter(([, v]) => v).map(([k, v]) => (
                <DetailRow key={String(k)} label={String(k)} value={String(v)} mono />
              ))}
            </Section>
          )}

          {/* Raw JSON */}
          <Section title="Raw Event">
            <pre style={{
              fontSize: 10, color: '#8B95A7',
              fontFamily: "'JetBrains Mono', monospace",
              whiteSpace: 'pre-wrap', wordBreak: 'break-all',
              margin: 0,
            }}>
              {JSON.stringify(event, null, 2)}
            </pre>
          </Section>
        </div>

        {/* Footer */}
        <div style={{
          padding: '12px 16px',
          borderTop: '1px solid rgba(255,255,255,0.06)',
          display: 'flex', gap: 8, flexShrink: 0,
        }}>
          <Button
            variant="secondary" size="sm" style={{ flex: 1 }}
            onClick={() => navigator.clipboard.writeText(JSON.stringify(event, null, 2))}
          >
            <Copy size={12} /> Copy JSON
          </Button>
          <Button variant="primary" size="sm">
            <FolderSearch size={12} /> Investigate
          </Button>
        </div>
      </div>
    </>
  )
}

// ─── EventsPage ───────────────────────────────────────────────────────────────

export function EventsPage() {
  const [searchParams] = useSearchParams()
  const [search,   setSearch]   = useState('')
  const [category, setCategory] = useState('')
  const [severity, setSeverity] = useState('')
  const [hostname, setHostname] = useState(searchParams.get('agent_id') ? '' : '')
  const [agentId,  setAgentId]  = useState(searchParams.get('agent_id') ?? '')
  const [selectedEvent, setSelectedEvent] = useState<EventResponse | null>(null)

  // Sync agent_id URL param on mount
  useEffect(() => {
    const aid = searchParams.get('agent_id')
    if (aid) setAgentId(aid)
  }, [searchParams])

  const { data, isLoading, refetch } = useEvents({
    query:     search   || undefined,
    category:  category || undefined,
    severity:  severity || undefined,
    host_name: hostname || undefined,
    agent_id:  agentId  || undefined,
    limit: 100,
  })

  const events = data?.items ?? []
  const total  = data?.total_estimate ?? 0

  const activeFilters = [search, category, severity, hostname, agentId].filter(Boolean).length

  const handleExport = async (format: 'csv' | 'json') => {
    try {
      const resp = await eventsApi.export({
        format,
        query:      search   || undefined,
        categories: category ? [category] : undefined,
        host_names: hostname ? [hostname] : undefined,
        agent_ids:  agentId  ? [agentId]  : undefined,
        max_rows: 10_000,
      })
      const blob = resp.data as unknown as Blob
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `neurashield-events.${format}`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      // silently fail on export error — user will see no download
    }
  }

  return (
    <div
      className="page-in"
      style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 50px - 40px)', overflow: 'hidden' }}
    >

      {/* Header */}
      <div style={{
        display: 'flex', justifyContent: 'space-between',
        alignItems: 'flex-start',
        paddingBottom: 12,
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        flexShrink: 0,
      }}>
        <div>
          <h1 style={{
            fontSize: 17, fontWeight: 800,
            fontFamily: "'Space Grotesk', sans-serif", color: '#F5F7FA',
          }}>
            Events
          </h1>
          <p style={{ fontSize: 12, color: '#5C6373', marginTop: 3 }}>
            {total > 0
              ? <><span style={{ color: '#F5F7FA', fontWeight: 500 }}>{total.toLocaleString()}</span> events · raw telemetry from all agents</>
              : 'Raw telemetry from all agents'}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <Button variant="ghost" size="sm" onClick={() => refetch()} title="Refresh">
            <RefreshCw size={12} />
          </Button>
          <Button variant="secondary" size="sm" onClick={() => handleExport('csv')}>
            <Download size={12} /> Export CSV
          </Button>
          <Button variant="secondary" size="sm" onClick={() => handleExport('json')}>
            <Download size={12} /> Export JSON
          </Button>
        </div>
      </div>

      {/* Filter bar */}
      <div style={{
        display: 'flex', gap: 6,
        padding: '8px 0',
        borderBottom: '1px solid rgba(255,255,255,0.04)',
        flexWrap: 'wrap', alignItems: 'center', flexShrink: 0,
      }}>
        {/* Search */}
        <div style={{ position: 'relative' }}>
          <Search size={12} style={{
            position: 'absolute', left: 9, top: '50%',
            transform: 'translateY(-50%)', color: '#5C6373', pointerEvents: 'none',
          }} />
          <input
            className="inp"
            style={{ width: 260, paddingLeft: 28 }}
            placeholder="Search events..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        {/* Category */}
        <select className="inp" style={{ width: 140 }}
          value={category} onChange={e => setCategory(e.target.value)}>
          <option value="">All Categories</option>
          {Object.entries(categoryConfig).map(([k, v]) => (
            <option key={k} value={k}>{v.label}</option>
          ))}
        </select>

        {/* Severity */}
        <select className="inp" style={{ width: 130 }}
          value={severity} onChange={e => setSeverity(e.target.value)}>
          <option value="">All Severity</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        {/* Hostname */}
        <input
          className="inp"
          style={{ width: 160 }}
          placeholder="Filter hostname..."
          value={hostname}
          onChange={e => setHostname(e.target.value)}
        />

        {/* Clear filters */}
        {activeFilters > 0 && (
          <button
            onClick={() => {
              setSearch('')
              setCategory('')
              setSeverity('')
              setHostname('')
              setAgentId('')
            }}
            style={{
              display: 'flex', alignItems: 'center', gap: 4,
              padding: '0 10px', height: 32, borderRadius: 5,
              fontSize: 11, color: '#8B95A7',
              background: 'rgba(255,255,255,0.04)',
              border: '1px solid rgba(255,255,255,0.07)',
              cursor: 'pointer',
              transition: 'color 120ms',
            }}
          >
            <X size={11} />
            {activeFilters} filter{activeFilters > 1 ? 's' : ''}
          </button>
        )}
      </div>

      {/* Table */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        <table className="data-table">
          <thead style={{ position: 'sticky', top: 0, background: '#050505', zIndex: 5 }}>
            <tr>
              <th style={{ width: 70  }}>SEV</th>
              <th style={{ width: 150 }}>TIME</th>
              <th style={{ width: 100 }}>CATEGORY</th>
              <th style={{ width: 130 }}>HOST</th>
              <th>SUMMARY</th>
              <th style={{ width: 80  }}>AGENT</th>
            </tr>
          </thead>
          <tbody>
            {/* Skeleton */}
            {isLoading && Array.from({ length: 12 }).map((_, i) => (
              <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                {[60, 120, 80, 120, 240, 60].map((w, j) => (
                  <td key={j} style={{ padding: '7px 12px' }}>
                    <span className="skel" style={{ width: w, height: 13, display: 'block' }} />
                  </td>
                ))}
              </tr>
            ))}

            {/* Rows */}
            {!isLoading && events.map(evt => (
              <EventRow key={evt.id} event={evt} onClick={() => setSelectedEvent(evt)} />
            ))}

            {/* Empty */}
            {!isLoading && events.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <div style={{ textAlign: 'center', padding: '60px 0' }}>
                    <Activity size={36} style={{
                      color: '#3A4150', marginBottom: 12,
                      display: 'block', margin: '0 auto 12px',
                    }} />
                    <div style={{ fontSize: 14, fontWeight: 600, color: '#5C6373', marginBottom: 6 }}>
                      No events found
                    </div>
                    <div style={{ fontSize: 12, color: '#3A4150' }}>
                      {activeFilters > 0
                        ? 'Try adjusting your filters'
                        : 'Events will appear here once agents start reporting'}
                    </div>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Event detail drawer */}
      {selectedEvent && (
        <EventDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} />
      )}
    </div>
  )
}
