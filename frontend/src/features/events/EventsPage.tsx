import { useState, useEffect, useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  RefreshCw, Download, X, Activity,
  Cpu, Wifi, FileText, Key, Database, Globe, Settings, Copy, FolderSearch,
  ShieldAlert, ShieldCheck, MapPin, AlertTriangle,
} from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { SevBadge } from '@/components/ui/SevBadge'
import { useEvents } from './hooks/useEvents'
import { eventsApi, type EventResponse, type EventSearchRequest } from '@/api/events'
import { formatDateShort, formatDateTime } from '@/lib/timezone'
import { SearchAutocomplete } from './SearchAutocomplete'
import { parseSearchQuery } from './queryParser'

// ─── Category config ──────────────────────────────────────────────────────────

const categoryConfig: Record<string, { icon: React.ElementType; color: string; label: string }> = {
  process:  { icon: Cpu,      color: '#60A5FA', label: 'Process'  },
  network:  { icon: Wifi,     color: '#34D399', label: 'Network'  },
  file:     { icon: FileText, color: '#FBBF24', label: 'File'     },
  auth:     { icon: Key,      color: '#F87171', label: 'Auth'     },
  registry: { icon: Database, color: '#C084FC', label: 'Registry' },
  dns:      { icon: Globe,    color: '#22D3EE', label: 'DNS'      },
  system:   { icon: Settings, color: '#94A3B8', label: 'System'   },
  other:    { icon: Activity, color: '#64748B', label: 'Other'    },
}

// ─── Windows Event ID labels ──────────────────────────────────────────────────

const WIN_EVENT_IDS: Record<string, string> = {
  '4624': 'Logon success',      '4625': 'Logon failed',
  '4634': 'Logoff',             '4648': 'Explicit credentials',
  '4672': 'Privileged logon',   '4688': 'Process created',
  '4698': 'Scheduled task',     '4702': 'Task updated',
  '4719': 'Audit policy changed','4720': 'User account created',
  '4728': 'Added to priv group','4732': 'Added to security group',
  '4768': 'Kerberos TGT',       '4769': 'Kerberos ticket',
  '4776': 'Credential validation','7045': 'Service installed',
  '1102': 'Audit log cleared',  '4104': 'PowerShell script',
}

function buildSummary(event: EventResponse): string {
  const process = event.process as Record<string, unknown> | null
  const network = event.network as Record<string, unknown> | null
  const file    = event.file    as Record<string, unknown> | null
  const user    = event.user    as Record<string, unknown> | null

  if (event.process_name) {
    const cmd = typeof process?.command_line === 'string'
      ? ` — ${(process.command_line as string).slice(0, 80)}`
      : ''
    return `${event.process_name}${cmd}`
  }
  if (event.dest_ip || event.source_ip) {
    const src   = event.source_ip ?? '?'
    const dst   = event.dest_ip   ?? '?'
    const port  = network?.dst_port ? `:${network.dst_port}` : ''
    const proto = typeof network?.protocol === 'string' ? ` (${network.protocol})` : ''
    return `${src} → ${dst}${port}${proto}`
  }
  const filePath = file?.path
  if (typeof filePath === 'string') {
    const op = file?.action ?? file?.operation ?? 'access'
    return `${op}: ${filePath.slice(-60)}`
  }
  const username = event.username ?? (typeof user?.name === 'string' ? user.name : null)
  const winId = event.raw?.windows_event_id ?? event.raw?.EventID ?? event.raw?.event_id_windows ?? null
  if (winId != null) {
    const desc = WIN_EVENT_IDS[String(winId)] ?? `Event ${winId}`
    return username ? `${desc} — ${username}` : desc
  }
  if (username) return `Auth — ${username}`
  const fallbacks: Record<string, string> = {
    auth: 'Authentication event', process: 'Process activity',
    network: 'Network connection', file: 'File activity',
    registry: 'Registry change', dns: 'DNS query',
    system: 'System event', other: 'Security event',
  }
  return fallbacks[event.category] ?? 'Security event'
}

// ─── Risk badge (table cell) ──────────────────────────────────────────────────

function RiskBadge({ event }: { event: EventResponse }) {
  if (event.is_threat_ip) {
    return (
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: 3,
        padding: '2px 7px', borderRadius: 3, fontSize: 9, fontWeight: 700,
        letterSpacing: '0.5px', whiteSpace: 'nowrap',
        background: 'rgba(248,113,113,0.12)', border: '1px solid rgba(248,113,113,0.35)',
        color: '#F87171',
      }}>
        <ShieldAlert size={8} /> THREAT
      </span>
    )
  }
  if (event.is_anomaly) {
    return (
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: 3,
        padding: '2px 7px', borderRadius: 3, fontSize: 9, fontWeight: 700,
        letterSpacing: '0.5px', whiteSpace: 'nowrap',
        background: 'rgba(251,191,36,0.10)', border: '1px solid rgba(251,191,36,0.30)',
        color: '#FBBF24',
      }}>
        <AlertTriangle size={8} /> ANOMALY
      </span>
    )
  }
  if (event.abuse_confidence > 25) {
    return (
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: 3,
        padding: '2px 7px', borderRadius: 3, fontSize: 9, fontWeight: 600,
        background: 'rgba(251,146,60,0.10)', border: '1px solid rgba(251,146,60,0.22)',
        color: '#FB923C', whiteSpace: 'nowrap',
      }}>
        {event.abuse_confidence}% abuse
      </span>
    )
  }
  if (event.geo_country_code && event.source_ip) {
    return (
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: 3,
        padding: '2px 7px', borderRadius: 3, fontSize: 9, fontWeight: 600,
        background: 'rgba(52,211,153,0.07)', border: '1px solid rgba(52,211,153,0.15)',
        color: '#34D399', whiteSpace: 'nowrap',
      }}>
        <MapPin size={8} /> {event.geo_country_code}
      </span>
    )
  }
  return <span style={{ color: '#2A3140', fontSize: 10 }}>—</span>
}

// ─── Section / DetailRow helpers ──────────────────────────────────────────────

function Section({ title, children, accent }: {
  title: string; children: React.ReactNode; accent?: string
}) {
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{
        fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
        letterSpacing: '1.5px', color: accent ?? '#5C6373',
        marginBottom: 7, display: 'flex', alignItems: 'center', gap: 6,
      }}>
        {accent && (
          <span style={{
            display: 'inline-block', width: 3, height: 10,
            borderRadius: 2, background: accent, flexShrink: 0,
          }} />
        )}
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
  label: string; value: string; mono?: boolean
}) {
  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
      <span style={{ fontSize: 10, color: '#4A5366', minWidth: 90, flexShrink: 0, paddingTop: 1 }}>
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
  const cat = categoryConfig[event.category] ?? { icon: Activity, color: '#64748B', label: 'Other' }
  const CatIcon = cat.icon
  const summary = buildSummary(event)
  const userObj = event.user as Record<string, unknown> | null
  const username = event.username ?? (typeof userObj?.name === 'string' ? userObj.name : null)

  const rowBg = event.is_threat_ip
    ? (hovered ? 'rgba(248,113,113,0.05)' : 'rgba(248,113,113,0.02)')
    : event.is_anomaly
      ? (hovered ? 'rgba(251,191,36,0.04)' : 'rgba(251,191,36,0.015)')
      : (hovered ? 'rgba(255,255,255,0.02)' : 'transparent')

  const leftBorder = event.is_threat_ip
    ? '2px solid rgba(248,113,113,0.5)'
    : event.is_anomaly
      ? '2px solid rgba(251,191,36,0.35)'
      : '2px solid transparent'

  return (
    <tr
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        borderLeft: leftBorder,
        borderBottom: '1px solid rgba(255,255,255,0.03)',
        background: rowBg, cursor: 'pointer', transition: 'background 100ms',
      }}
    >
      {/* Severity */}
      <td style={{ padding: '6px 10px' }}>
        <SevBadge sev={event.severity} />
      </td>

      {/* Time */}
      <td style={{ padding: '6px 10px' }}>
        <span style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 10, color: '#5C6373', whiteSpace: 'nowrap',
        }}>
          {formatDateShort(event.event_timestamp)}
        </span>
      </td>

      {/* Category */}
      <td style={{ padding: '6px 10px' }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11, color: cat.color }}>
          <CatIcon size={11} />
          {cat.label}
        </span>
      </td>

      {/* Host */}
      <td style={{ padding: '6px 10px' }}>
        <span style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 10, color: '#8B95A7',
          display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 115,
        }}>
          {event.host_name ?? '—'}
        </span>
      </td>

      {/* User */}
      <td style={{ padding: '6px 10px' }}>
        <span style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 10, color: username ? '#B8C0CC' : '#2A3140',
        }}>
          {username ? username.slice(0, 14) : '—'}
        </span>
      </td>

      {/* Source IP */}
      <td style={{ padding: '6px 10px' }}>
        {event.source_ip ? (
          <span style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 10,
            color: event.is_threat_ip ? '#F87171' : '#7A8699',
          }}>
            {event.source_ip}
          </span>
        ) : (
          <span style={{ color: '#2A3140', fontSize: 10 }}>—</span>
        )}
      </td>

      {/* Risk */}
      <td style={{ padding: '6px 10px' }}>
        <RiskBadge event={event} />
      </td>

      {/* Summary */}
      <td style={{ padding: '6px 10px' }}>
        <span style={{
          fontSize: 11, color: '#5C6880',
          overflow: 'hidden', textOverflow: 'ellipsis',
          whiteSpace: 'nowrap', display: 'block', maxWidth: 320,
        }}>
          {summary}
        </span>
      </td>
    </tr>
  )
}

// ─── EventDrawer ──────────────────────────────────────────────────────────────

function EventDrawer({ event, onClose }: { event: EventResponse; onClose: () => void }) {
  const cat = categoryConfig[event.category] ?? { icon: Activity, color: '#64748B', label: 'Other' }
  const CatIcon = cat.icon

  const process = event.process as Record<string, unknown> | null
  const network = event.network as Record<string, unknown> | null
  const file    = event.file    as Record<string, unknown> | null
  const user    = event.user    as Record<string, unknown> | null
  const reg     = event.registry as Record<string, unknown> | null

  const hasExternalIp = !!(event.source_ip || event.dest_ip)
  const threatLevel: 'threat' | 'high' | 'suspicious' | 'clean' =
    event.is_threat_ip          ? 'threat'
    : event.abuse_confidence >= 75 ? 'high'
    : event.abuse_confidence >= 25 ? 'suspicious'
    : 'clean'

  const threatColor =
    threatLevel === 'threat' || threatLevel === 'high' ? '#F87171'
    : threatLevel === 'suspicious' ? '#FB923C'
    : '#34D399'

  return (
    <>
      <div onClick={onClose} style={{
        position: 'fixed', inset: 0, zIndex: 49, background: 'rgba(0,0,0,0.45)',
      }} />
      <div style={{
        position: 'fixed', right: 0, top: 50,
        height: 'calc(100vh - 50px)', width: 490,
        background: '#070A0F',
        borderLeft: '1px solid rgba(255,255,255,0.07)',
        display: 'flex', flexDirection: 'column',
        zIndex: 50,
        animation: 'slideInRight 200ms ease both',
      }}>

        {/* Header */}
        <div style={{
          padding: '14px 16px',
          borderBottom: '1px solid rgba(255,255,255,0.06)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          flexShrink: 0,
          background: event.is_threat_ip
            ? 'rgba(248,113,113,0.03)'
            : event.is_anomaly ? 'rgba(251,191,36,0.02)' : 'transparent',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 34, height: 34, borderRadius: 8,
              background: `${cat.color}15`, border: `1px solid ${cat.color}25`,
              display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
            }}>
              <CatIcon size={16} style={{ color: cat.color }} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 13, fontWeight: 700, color: '#F5F7FA' }}>
                  {cat.label} Event
                </span>
                <SevBadge sev={event.severity} />
                {event.is_threat_ip && (
                  <span style={{
                    display: 'inline-flex', alignItems: 'center', gap: 3,
                    padding: '1px 6px', borderRadius: 3, fontSize: 9, fontWeight: 700,
                    background: 'rgba(248,113,113,0.12)', border: '1px solid rgba(248,113,113,0.35)',
                    color: '#F87171',
                  }}>
                    <ShieldAlert size={8} /> THREAT IP
                  </span>
                )}
                {event.is_anomaly && !event.is_threat_ip && (
                  <span style={{
                    display: 'inline-flex', alignItems: 'center', gap: 3,
                    padding: '1px 6px', borderRadius: 3, fontSize: 9, fontWeight: 700,
                    background: 'rgba(251,191,36,0.10)', border: '1px solid rgba(251,191,36,0.28)',
                    color: '#FBBF24',
                  }}>
                    <AlertTriangle size={8} /> ANOMALY
                  </span>
                )}
              </div>
              <div style={{
                fontSize: 9, color: '#2F3A4A', marginTop: 3,
                fontFamily: "'JetBrains Mono', monospace",
              }}>
                {event.id}
              </div>
            </div>
          </div>
          <button onClick={onClose} style={{
            background: 'none', border: 'none', color: '#4A5366', cursor: 'pointer', padding: 4,
          }}>
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>

          {/* Meta grid */}
          <div style={{
            display: 'grid', gridTemplateColumns: '1fr 1fr',
            gap: '10px 14px', marginBottom: 18,
            background: 'rgba(255,255,255,0.015)',
            border: '1px solid rgba(255,255,255,0.05)',
            borderRadius: 8, padding: '12px 14px',
          }}>
            {([
              ['Timestamp', formatDateTime(event.event_timestamp)],
              ['Host',      event.host_name ?? '—'],
              ['User',      event.username ?? (typeof user?.name === 'string' ? user.name : '—')],
              ['Source IP', event.source_ip ?? '—'],
              ['Category',  cat.label],
              ['Tags',      event.tags.length > 0 ? event.tags.join(', ') : 'None'],
            ] as [string, string][]).map(([label, value]) => (
              <div key={label}>
                <div style={{
                  fontSize: 8, color: '#2F3A4A', textTransform: 'uppercase',
                  letterSpacing: '1px', marginBottom: 3, fontWeight: 700,
                }}>
                  {label}
                </div>
                <div style={{
                  fontSize: 11, color: '#7A8699',
                  fontFamily: "'JetBrains Mono', monospace",
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                  {value}
                </div>
              </div>
            ))}
          </div>

          {/* ── Threat Intelligence ── always shown when IP present ── */}
          {(hasExternalIp || event.is_threat_ip || event.threat_intel_flags.length > 0) && (
            <Section title="Threat Intelligence" accent={threatColor}>
              {/* Status line */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                {threatLevel === 'clean'
                  ? <ShieldCheck size={14} style={{ color: '#34D399' }} />
                  : <ShieldAlert size={14} style={{ color: threatColor }} />
                }
                <span style={{ fontSize: 11, fontWeight: 700, color: threatColor }}>
                  {threatLevel === 'threat'      ? 'MALICIOUS IP DETECTED'
                   : threatLevel === 'high'      ? 'HIGH ABUSE SCORE'
                   : threatLevel === 'suspicious'? 'SUSPICIOUS IP'
                   :                              'No threats detected'}
                </span>
              </div>

              {/* Checked IP */}
              {(event.source_ip ?? event.dest_ip) && (
                <DetailRow
                  label="Checked IP"
                  value={(event.source_ip ?? event.dest_ip)!}
                  mono
                />
              )}

              {/* Abuse confidence bar */}
              <div>
                <div style={{
                  display: 'flex', justifyContent: 'space-between',
                  fontSize: 9, color: '#4A5366', textTransform: 'uppercase',
                  letterSpacing: '1px', marginBottom: 4,
                }}>
                  <span>Abuse Confidence</span>
                  <span style={{ color: '#7A8699' }}>{event.abuse_confidence}%</span>
                </div>
                <div style={{
                  height: 5, borderRadius: 3,
                  background: 'rgba(255,255,255,0.05)', overflow: 'hidden',
                }}>
                  <div style={{
                    height: '100%',
                    width: `${Math.max(event.abuse_confidence, event.is_threat_ip ? 3 : 0)}%`,
                    borderRadius: 3,
                    background: event.abuse_confidence >= 75 ? '#F87171'
                      : event.abuse_confidence >= 25 ? '#FB923C'
                      : '#34D399',
                    transition: 'width 400ms ease',
                  }} />
                </div>
              </div>

              {/* Intel flags */}
              {event.threat_intel_flags.length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 2 }}>
                  {event.threat_intel_flags.map(flag => (
                    <span key={flag} style={{
                      fontSize: 9, padding: '2px 6px', borderRadius: 3,
                      background: 'rgba(248,113,113,0.08)',
                      border: '1px solid rgba(248,113,113,0.2)',
                      color: '#F87171', fontFamily: "'JetBrains Mono', monospace",
                    }}>
                      {flag}
                    </span>
                  ))}
                </div>
              )}
            </Section>
          )}

          {/* ── UEBA Behavioral Analysis ── */}
          {(event.is_anomaly || event.ueba_flags.length > 0) && (
            <Section
              title="Behavioral Analysis (UEBA)"
              accent={event.anomaly_score >= 0.7 ? '#F87171' : '#FBBF24'}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <AlertTriangle size={14} style={{
                  color: event.anomaly_score >= 0.7 ? '#F87171' : '#FBBF24',
                }} />
                <span style={{
                  fontSize: 11, fontWeight: 700,
                  color: event.anomaly_score >= 0.7 ? '#F87171' : '#FBBF24',
                }}>
                  {event.anomaly_score >= 0.7 ? 'HIGH RISK ANOMALY' : 'BEHAVIORAL ANOMALY'}
                </span>
              </div>
              <div>
                <div style={{
                  display: 'flex', justifyContent: 'space-between',
                  fontSize: 9, color: '#4A5366', textTransform: 'uppercase',
                  letterSpacing: '1px', marginBottom: 4,
                }}>
                  <span>Anomaly Score</span>
                  <span style={{ color: '#7A8699' }}>{Math.round(event.anomaly_score * 100)}%</span>
                </div>
                <div style={{
                  height: 5, borderRadius: 3,
                  background: 'rgba(255,255,255,0.05)', overflow: 'hidden',
                }}>
                  <div style={{
                    height: '100%',
                    width: `${Math.round(event.anomaly_score * 100)}%`,
                    borderRadius: 3,
                    background: event.anomaly_score >= 0.7 ? '#F87171'
                      : event.anomaly_score >= 0.5 ? '#FBBF24'
                      : '#34D399',
                    transition: 'width 400ms ease',
                  }} />
                </div>
              </div>
              {event.ueba_flags.length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 2 }}>
                  {event.ueba_flags.map(flag => {
                    const isHigh = ['impossible_travel', 'brute_force_success', 'lateral_movement'].includes(flag)
                    return (
                      <span key={flag} style={{
                        fontSize: 9, padding: '2px 6px', borderRadius: 3,
                        background: isHigh ? 'rgba(248,113,113,0.08)' : 'rgba(251,191,36,0.08)',
                        border: `1px solid ${isHigh ? 'rgba(248,113,113,0.2)' : 'rgba(251,191,36,0.2)'}`,
                        color: isHigh ? '#F87171' : '#FBBF24',
                        fontFamily: "'JetBrains Mono', monospace",
                      }}>
                        {flag.replace(/_/g, ' ')}
                      </span>
                    )
                  })}
                </div>
              )}
            </Section>
          )}

          {/* ── GeoIP ── */}
          {(event.geo_country || event.geo_city) && (
            <Section title="Geolocation" accent="#34D399">
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <MapPin size={12} style={{ color: '#34D399' }} />
                <span style={{ fontSize: 12, color: '#F5F7FA', fontWeight: 600 }}>
                  {[event.geo_city, event.geo_country].filter(Boolean).join(', ')}
                  {event.geo_country_code && (
                    <span style={{
                      marginLeft: 8, fontSize: 9, padding: '1px 5px',
                      background: 'rgba(52,211,153,0.10)',
                      border: '1px solid rgba(52,211,153,0.20)',
                      borderRadius: 3, color: '#34D399',
                    }}>
                      {event.geo_country_code}
                    </span>
                  )}
                </span>
              </div>
              {[
                ['ISP',       event.geo_isp],
                ['Latitude',  event.geo_latitude  != null ? String(event.geo_latitude)  : null],
                ['Longitude', event.geo_longitude != null ? String(event.geo_longitude) : null],
              ].filter(([, v]) => v).map(([k, v]) => (
                <DetailRow key={String(k)} label={String(k)} value={String(v)} />
              ))}
            </Section>
          )}

          {/* ── Process ── */}
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

          {/* ── Network ── */}
          {(event.source_ip || event.dest_ip || network) && (
            <Section title="Network">
              {[
                ['Source IP',  event.source_ip],
                ['Dest IP',    event.dest_ip],
                ['Dest Port',  network?.dst_port != null ? String(network.dst_port) : null],
                ['Protocol',   network?.protocol as string | null],
                ['Direction',  network?.direction as string | null],
              ].filter(([, v]) => v).map(([k, v]) => (
                <DetailRow key={String(k)} label={String(k)} value={String(v)} mono />
              ))}
            </Section>
          )}

          {/* ── File ── */}
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

          {/* ── User ── */}
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

          {/* ── Registry ── */}
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

          {/* ── Correlation ── */}
          {(event.correlation_id || event.session_id || event.process_tree_id) && (
            <Section title="Correlation">
              {[
                ['Correlation',  event.correlation_id],
                ['Session',      event.session_id],
                ['Process Tree', event.process_tree_id],
                ['Event Chain',  event.event_chain_id],
              ].filter(([, v]) => v).map(([k, v]) => (
                <DetailRow key={String(k)} label={String(k)} value={String(v)} mono />
              ))}
            </Section>
          )}

          {/* ── Raw JSON ── */}
          <Section title="Raw Event">
            <pre style={{
              fontSize: 9, color: '#4A5366',
              fontFamily: "'JetBrains Mono', monospace",
              whiteSpace: 'pre-wrap', wordBreak: 'break-all',
              margin: 0, maxHeight: 300, overflowY: 'auto',
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

// ─── Quick searches ───────────────────────────────────────────────────────────

const QUICK_SEARCHES = [
  { label: 'Failed Logons',    query: 'category:auth severity:medium earliest:1h'   },
  { label: 'PowerShell',       query: 'process:powershell.exe earliest:24h'         },
  { label: 'Network Anomaly',  query: 'category:network severity:high earliest:24h' },
  { label: 'New Processes',    query: 'category:process earliest:1h'                },
  { label: 'Privilege Events', query: 'category:auth severity:high earliest:7d'     },
  { label: 'File Activity',    query: 'category:file earliest:24h'                  },
]

// ─── View filter ──────────────────────────────────────────────────────────────

type ViewFilter = 'all' | 'threats' | 'anomalies' | 'critical'

// ─── EventsPage ───────────────────────────────────────────────────────────────

export function EventsPage() {
  const [searchParams]  = useSearchParams()
  const [queryText,    setQueryText]    = useState('')
  const [parsedSearch, setParsedSearch] = useState<Partial<EventSearchRequest>>({})
  const [agentId,      setAgentId]      = useState(searchParams.get('agent_id') ?? '')
  const [selectedEvent, setSelectedEvent] = useState<EventResponse | null>(null)
  const [viewFilter,   setViewFilter]   = useState<ViewFilter>('all')

  useEffect(() => {
    const aid = searchParams.get('agent_id')
    if (aid) setAgentId(aid)
  }, [searchParams])

  const handleSearch = useCallback((text?: string) => {
    const q = text ?? queryText
    setParsedSearch(parseSearchQuery(q))
  }, [queryText])

  const clearSearch = () => {
    setQueryText('')
    setParsedSearch({})
    setAgentId('')
  }

  const { data, isLoading, refetch } = useEvents({
    searchRequest: parsedSearch,
    agent_id: agentId || undefined,
    limit: 200,
  })

  const allEvents = data?.items ?? []
  const total     = data?.total_estimate ?? 0

  const threatCount   = useMemo(() => allEvents.filter(e => e.is_threat_ip).length,  [allEvents])
  const anomalyCount  = useMemo(() => allEvents.filter(e => e.is_anomaly).length,    [allEvents])
  const criticalCount = useMemo(() => allEvents.filter(e => e.severity >= 3).length, [allEvents])

  const events = useMemo(() => {
    if (viewFilter === 'threats')   return allEvents.filter(e => e.is_threat_ip)
    if (viewFilter === 'anomalies') return allEvents.filter(e => e.is_anomaly)
    if (viewFilter === 'critical')  return allEvents.filter(e => e.severity >= 3)
    return allEvents
  }, [allEvents, viewFilter])

  const hasActiveSearch = !!(queryText || agentId)

  const handleExport = async (format: 'csv' | 'json') => {
    try {
      const resp = await eventsApi.export({
        format, query: parsedSearch.query,
        categories: parsedSearch.categories, severity_min: parsedSearch.severity_min,
        host_names: parsedSearch.host_names,
        agent_ids: agentId ? [agentId] : parsedSearch.agent_ids,
        from_ts: parsedSearch.from_ts, to_ts: parsedSearch.to_ts, max_rows: 10_000,
      })
      const blob = resp.data as unknown as Blob
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = `neurashield-events.${format}`; a.click()
      URL.revokeObjectURL(url)
    } catch { /* silent */ }
  }

  function pillStyle(f: ViewFilter, color: string): React.CSSProperties {
    const active = viewFilter === f
    return {
      padding: '3px 11px', borderRadius: 5, cursor: 'pointer',
      fontSize: 10, fontWeight: 700, letterSpacing: '0.2px',
      border: active ? `1px solid ${color}45` : '1px solid rgba(255,255,255,0.06)',
      background: active ? `${color}14` : 'rgba(255,255,255,0.02)',
      color: active ? color : '#4A5366',
      transition: 'all 120ms', whiteSpace: 'nowrap' as const,
    }
  }

  return (
    <div
      className="page-in"
      style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 50px - 40px)', overflow: 'hidden' }}
    >

      {/* Header */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
        paddingBottom: 10, borderBottom: '1px solid rgba(255,255,255,0.05)', flexShrink: 0,
      }}>
        <div>
          <h1 style={{
            fontSize: 16, fontWeight: 800,
            fontFamily: "'Space Grotesk', sans-serif", color: '#F5F7FA',
          }}>
            Events Explorer
          </h1>
          <p style={{ fontSize: 11, color: '#3A4150', marginTop: 2 }}>
            {total > 0
              ? <><span style={{ color: '#8B95A7', fontWeight: 600 }}>{total.toLocaleString()}</span> events · raw telemetry from all agents</>
              : 'Raw telemetry from all agents'}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 5, alignItems: 'center' }}>
          <Button variant="ghost" size="sm" onClick={() => refetch()} title="Refresh">
            <RefreshCw size={12} />
          </Button>
          <Button variant="secondary" size="sm" onClick={() => handleExport('csv')}>
            <Download size={12} /> CSV
          </Button>
          <Button variant="secondary" size="sm" onClick={() => handleExport('json')}>
            <Download size={12} /> JSON
          </Button>
        </div>
      </div>

      {/* View filter bar — only shown once events load */}
      {!isLoading && allEvents.length > 0 && (
        <div style={{
          display: 'flex', gap: 5, alignItems: 'center',
          padding: '6px 0',
          borderBottom: '1px solid rgba(255,255,255,0.04)',
          flexShrink: 0, flexWrap: 'wrap',
        }}>
          <button onClick={() => setViewFilter('all')} style={pillStyle('all', '#8B95A7')}>
            All · {allEvents.length}
          </button>
          {threatCount > 0 && (
            <button onClick={() => setViewFilter('threats')} style={pillStyle('threats', '#F87171')}>
              ⚠ Threats · {threatCount}
            </button>
          )}
          {anomalyCount > 0 && (
            <button onClick={() => setViewFilter('anomalies')} style={pillStyle('anomalies', '#FBBF24')}>
              ◆ Anomalies · {anomalyCount}
            </button>
          )}
          {criticalCount > 0 && (
            <button onClick={() => setViewFilter('critical')} style={pillStyle('critical', '#FB923C')}>
              ↑ Critical/High · {criticalCount}
            </button>
          )}
          {(threatCount === 0 && anomalyCount === 0) && (
            <span style={{ fontSize: 10, color: '#34D399', marginLeft: 4 }}>
              ✓ No threats or anomalies detected in view
            </span>
          )}
        </div>
      )}

      {/* Search bar */}
      <div style={{ padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', flexShrink: 0 }}>
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 5 }}>
          {QUICK_SEARCHES.map(t => (
            <button
              key={t.label}
              onClick={() => { setQueryText(t.query); handleSearch(t.query) }}
              style={{
                padding: '2px 8px', borderRadius: 4, fontSize: 9, fontWeight: 600,
                background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.06)',
                color: '#3A4150', cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div style={{ display: 'flex', gap: 6, alignItems: 'flex-start' }}>
          <SearchAutocomplete
            value={queryText}
            onChange={setQueryText}
            onSearch={() => handleSearch()}
          />

          {agentId && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 5,
              padding: '0 10px', height: 32, borderRadius: 5, flexShrink: 0,
              fontSize: 11, color: '#60A5FA',
              background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.2)',
              fontFamily: "'JetBrains Mono', monospace",
            }}>
              agent:{agentId.slice(0, 8)}
              <button onClick={() => setAgentId('')} style={{
                background: 'none', border: 'none', color: '#60A5FA',
                cursor: 'pointer', padding: 0, display: 'flex', alignItems: 'center',
              }}>
                <X size={11} />
              </button>
            </div>
          )}

          {hasActiveSearch && (
            <button onClick={clearSearch} style={{
              display: 'flex', alignItems: 'center', gap: 4,
              padding: '0 10px', height: 32, borderRadius: 5, flexShrink: 0,
              fontSize: 11, color: '#8B95A7',
              background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)',
              cursor: 'pointer',
            }}>
              <X size={11} /> Clear
            </button>
          )}
        </div>

        {queryText && !isLoading && (
          <div style={{ fontSize: 10, color: '#3A4150', marginTop: 3 }}>
            {total > 0 ? <>{total.toLocaleString()} results</> : <>No events found</>}
          </div>
        )}
      </div>

      {/* Table */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        <table className="data-table">
          <thead style={{ position: 'sticky', top: 0, background: '#050505', zIndex: 5 }}>
            <tr>
              <th style={{ width: 65  }}>SEV</th>
              <th style={{ width: 130 }}>TIME</th>
              <th style={{ width: 95  }}>CATEGORY</th>
              <th style={{ width: 120 }}>HOST</th>
              <th style={{ width: 110 }}>USER</th>
              <th style={{ width: 115 }}>SRC IP</th>
              <th style={{ width: 110 }}>RISK</th>
              <th>SUMMARY</th>
            </tr>
          </thead>
          <tbody>
            {/* Skeleton */}
            {isLoading && Array.from({ length: 14 }).map((_, i) => (
              <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                {[50, 110, 80, 110, 90, 100, 85, 220].map((w, j) => (
                  <td key={j} style={{ padding: '6px 10px' }}>
                    <span className="skel" style={{ width: w, height: 12, display: 'block' }} />
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
                <td colSpan={8}>
                  <div style={{ textAlign: 'center', padding: '60px 0' }}>
                    <Activity size={36} style={{ color: '#3A4150', display: 'block', margin: '0 auto 12px' }} />
                    <div style={{ fontSize: 14, fontWeight: 600, color: '#5C6373', marginBottom: 6 }}>
                      {viewFilter !== 'all' ? `No ${viewFilter} events in current view` : 'No events found'}
                    </div>
                    <div style={{ fontSize: 12, color: '#3A4150' }}>
                      {viewFilter !== 'all'
                        ? (
                          <button onClick={() => setViewFilter('all')} style={{
                            color: '#60A5FA', background: 'none', border: 'none',
                            cursor: 'pointer', fontSize: 12,
                          }}>
                            Show all events
                          </button>
                        )
                        : hasActiveSearch
                          ? 'Try adjusting your search query'
                          : 'Events appear here once agents start reporting'
                      }
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
