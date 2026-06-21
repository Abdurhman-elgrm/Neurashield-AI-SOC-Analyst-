import { useState, useEffect, useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  RefreshCw, Download, X, Activity,
  Cpu, Wifi, FileText, Key, Database, Globe, Settings, Copy, FolderSearch,
  ShieldAlert, AlertTriangle, MapPin, ChevronRight, ChevronDown,
} from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { SevBadge } from '@/components/ui/SevBadge'
import { useEvents } from './hooks/useEvents'
import { eventsApi, type EventResponse, type EventSearchRequest } from '@/api/events'
import { formatDateTime } from '@/lib/timezone'
import { SearchAutocomplete } from './SearchAutocomplete'
import { parseSearchQuery } from './queryParser'
import { CreateInvestigationModal } from '@/features/investigations/components/CreateInvestigationModal'
import { toastError } from '@/lib/toast'
import { extractApiError } from '@/lib/utils'

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

// ─── Windows Event ID → human label (comprehensive) ──────────────────────────

const WIN_EVENT_IDS: Record<string, string> = {
  // Logon / Logoff
  '4624': 'Account Logon',            '4625': 'Logon Failure',
  '4634': 'Account Logoff',           '4647': 'User Initiated Logoff',
  '4648': 'Explicit Credential Logon','4672': 'Special Privileges Assigned',
  '4675': 'SIDs Filtered',            '4776': 'NTLM Credential Validation',
  '4778': 'Session Reconnected',      '4779': 'Session Disconnected',
  '4800': 'Workstation Locked',       '4801': 'Workstation Unlocked',
  // Kerberos
  '4768': 'Kerberos TGT Requested',   '4769': 'Kerberos Service Ticket',
  '4770': 'Kerberos Ticket Renewed',  '4771': 'Kerberos Pre-Auth Failed',
  '4772': 'Kerberos Auth Ticket Failed',
  // Process
  '4688': 'Process Created',          '4689': 'Process Exited',
  '4696': 'Primary Token Assigned',
  // Account management
  '4720': 'User Account Created',     '4722': 'User Account Enabled',
  '4723': 'Password Change Attempt',  '4724': 'Password Reset',
  '4725': 'User Account Disabled',    '4726': 'User Account Deleted',
  '4728': 'Added to Security Group',  '4729': 'Removed from Security Group',
  '4732': 'Added to Local Group',     '4733': 'Removed from Local Group',
  '4738': 'User Account Changed',     '4740': 'Account Locked Out',
  '4767': 'Account Unlocked',
  // Scheduled tasks
  '4698': 'Scheduled Task Created',   '4699': 'Scheduled Task Deleted',
  '4700': 'Scheduled Task Enabled',   '4701': 'Scheduled Task Disabled',
  '4702': 'Scheduled Task Updated',
  // Policy
  '4719': 'Audit Policy Changed',
  // Object / File access
  '4656': 'Object Handle Requested',  '4657': 'Registry Value Modified',
  '4658': 'Object Handle Closed',     '4660': 'Object Deleted',
  '4663': 'Object Access Attempt',    '4670': 'Object Permissions Changed',
  '4673': 'Privileged Service Called','4674': 'Privileged Object Operation',
  // Network / Firewall
  '4946': 'Firewall Rule Added',      '4947': 'Firewall Rule Modified',
  '4948': 'Firewall Rule Deleted',    '4950': 'Firewall Setting Changed',
  '5140': 'Network Share Accessed',   '5142': 'Network Share Added',
  '5144': 'Network Share Deleted',    '5145': 'Network Share Object Check',
  '5152': 'Packet Blocked by WFP',    '5154': 'Listening Port Allowed',
  '5156': 'Connection Allowed',       '5157': 'Connection Blocked',
  '5158': 'Bind to Local Port',
  // Services
  '7045': 'New Service Installed',    '7036': 'Service State Changed',
  '7040': 'Service Start Type Changed',
  // PowerShell
  '4103': 'PowerShell Pipeline Execute','4104': 'PowerShell Script Block',
  '4105': 'PowerShell Command Start',   '4106': 'PowerShell Command End',
  // Audit log
  '1102': 'Security Audit Log Cleared','1104': 'Security Log Full',
  // WMI
  '5858': 'WMI Activity Error',       '5859': 'WMI Subscription Timer',
  '5860': 'WMI Temporary Subscription','5861': 'WMI Permanent Subscription',
  // SSPI / Authentication providers
  '40960': 'SSPI Negotiate Request',  '40961': 'SSPI Auth Request',
  '40962': 'SSPI Auth Completed',
  // AppLocker
  '8003': 'AppLocker Execution Blocked','8004': 'AppLocker Execution Audited',
  '8006': 'AppLocker DLL Blocked',
  // Misc
  '4616': 'System Time Changed',      '4697': 'Service Installed in System',
  '5379': 'Credential Manager Read',  '5382': 'Credential Manager Backup',
  '53504': 'Security Auth Package',
}

// ─── Build human-readable summary ────────────────────────────────────────────

function buildSummary(event: EventResponse): string {
  const process = event.process as Record<string, unknown> | null
  const network = event.network as Record<string, unknown> | null
  const file    = event.file    as Record<string, unknown> | null
  const user    = event.user    as Record<string, unknown> | null
  const raw     = event.raw    as Record<string, unknown> | null

  // Process events — most informative
  if (event.process_name) {
    const cmdRaw = process?.command_line ?? raw?.CommandLine ?? raw?.command_line
    const cmd = typeof cmdRaw === 'string' && cmdRaw.length > 2
      ? ` — ${cmdRaw.slice(0, 110)}`
      : ''
    const parent = process?.parent_name
      ? ` (via ${process.parent_name})`
      : ''
    return `${event.process_name}${cmd || parent}`
  }

  // Network events
  if (event.dest_ip || event.source_ip) {
    const src   = event.source_ip ?? '?'
    const dst   = event.dest_ip   ?? '?'
    const port  = (network?.dst_port ?? network?.dest_port)
      ? `:${network?.dst_port ?? network?.dest_port}`
      : ''
    const proto = typeof network?.protocol === 'string'
      ? ` [${network.protocol.toUpperCase()}]`
      : ''
    const bytes = typeof network?.bytes_out === 'number' && network.bytes_out > 0
      ? ` · ${Math.round(network.bytes_out / 1024)}KB out`
      : ''
    return `${src} → ${dst}${port}${proto}${bytes}`
  }

  // File events
  const filePath = file?.path ?? file?.file_path
  if (typeof filePath === 'string') {
    const op = String(file?.action ?? file?.operation ?? file?.event_type ?? 'ACCESS').toUpperCase()
    const hash = typeof file?.hash_sha256 === 'string'
      ? ` [${(file.hash_sha256 as string).slice(0, 8)}…]`
      : ''
    return `${op}: ${filePath.slice(-90)}${hash}`
  }

  // Windows Event ID lookup — check every possible field name
  const rawAny = raw as Record<string, unknown> | null
  const winId = (
    rawAny?.windows_event_id ?? rawAny?.EventID ?? rawAny?.event_id ??
    rawAny?.EventId ?? rawAny?.event_id_windows ?? rawAny?.Id
  )
  const winIdStr = winId != null ? String(winId) : null

  if (winIdStr) {
    const label = WIN_EVENT_IDS[winIdStr]
    const username = event.username ?? (typeof user?.name === 'string' ? user.name : null)
    const domain   = typeof user?.domain === 'string' ? user.domain : null
    const account  = domain && username ? `${domain}\\${username}` : username
    const logonType = raw?.LogonType ? ` · Logon Type ${raw.LogonType}` : ''
    const targetSvc = raw?.TargetServerName
      ? ` → ${raw.TargetServerName}`
      : ''

    if (label) {
      return `${label}${account ? ` — ${account}` : ''}${logonType}${targetSvc}`
    }
    // Unknown ID — try raw message first
    const msg = raw?.Message ?? raw?.message ?? raw?.Description ?? raw?.description
    if (typeof msg === 'string' && msg.length > 5) {
      return msg.split('\n')[0].trim().slice(0, 110)
    }
    return account ? `Event ${winIdStr} — ${account}` : `Windows Event ${winIdStr}`
  }

  // DNS
  const dnsQuery = raw?.query_name ?? raw?.dns_query ?? raw?.QueryName
  if (typeof dnsQuery === 'string') return `DNS Query: ${dnsQuery}`

  // Registry
  const regKey = (event.registry as Record<string, unknown> | null)?.key
  if (typeof regKey === 'string') return `Registry: ${regKey.slice(-80)}`

  // Username fallback
  const username = event.username ?? (typeof user?.name === 'string' ? user.name : null)
  if (username) return `Auth — ${username}`

  // Any raw message
  const rawMsg = raw?.Message ?? raw?.message ?? raw?.event_type ?? raw?.action
  if (typeof rawMsg === 'string' && rawMsg.length > 3) return rawMsg.slice(0, 120)

  return categoryConfig[event.category]?.label ?? 'Security Event'
}

// ─── Extract key fields for inline expanded row ───────────────────────────────

function buildKeyFields(event: EventResponse) {
  const fields: Array<{ key: string; value: string; mono?: boolean }> = []
  const process = event.process as Record<string, unknown> | null
  const network = event.network as Record<string, unknown> | null
  const file    = event.file    as Record<string, unknown> | null
  const user    = event.user    as Record<string, unknown> | null
  const raw     = event.raw    as Record<string, unknown> | null

  const push = (key: string, value: unknown, mono = false) => {
    if (value != null && String(value).length > 0) {
      fields.push({ key, value: String(value), mono })
    }
  }

  push('host',      event.host_name)
  push('user',      event.username ?? user?.name)
  push('src_ip',    event.source_ip,  true)
  push('dest_ip',   event.dest_ip,    true)
  push('process',   event.process_name, true)
  push('cmd_line',  process?.command_line ?? raw?.CommandLine, true)
  push('pid',       process?.pid, true)
  push('parent',    process?.parent_name ?? process?.parent_process_name, true)
  push('dst_port',  network?.dst_port ?? network?.dest_port, true)
  push('protocol',  typeof network?.protocol === 'string' ? network.protocol.toUpperCase() : null)
  push('file_path', file?.path ?? file?.file_path, true)
  push('sha256',    file?.hash_sha256, true)
  push('reg_key',   (event.registry as Record<string, unknown> | null)?.key, true)
  push('dns_query', raw?.query_name ?? raw?.dns_query ?? raw?.QueryName)
  push('event_id',  raw?.windows_event_id ?? raw?.EventID ?? raw?.event_id, true)
  push('domain',    typeof user?.domain === 'string' ? user.domain : null)
  push('geo',       [event.geo_city, event.geo_country].filter(Boolean).join(', '))
  push('isp',       event.geo_isp)

  return fields.slice(0, 14)
}

// ─── Risk intel badge ─────────────────────────────────────────────────────────

function RiskBadge({ event }: { event: EventResponse }) {
  if (event.is_threat_ip) return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 3,
      padding: '1px 6px', borderRadius: 3, fontSize: 9, fontWeight: 700,
      letterSpacing: '0.5px', whiteSpace: 'nowrap',
      background: 'rgba(248,113,113,0.12)', border: '1px solid rgba(248,113,113,0.35)',
      color: '#F87171',
    }}>
      <ShieldAlert size={8} /> THREAT IP
    </span>
  )
  if (event.is_anomaly) return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 3,
      padding: '1px 6px', borderRadius: 3, fontSize: 9, fontWeight: 700,
      letterSpacing: '0.5px', whiteSpace: 'nowrap',
      background: 'rgba(251,191,36,0.10)', border: '1px solid rgba(251,191,36,0.30)',
      color: '#FBBF24',
    }}>
      ◆ ANOMALY
    </span>
  )
  if (event.abuse_confidence >= 25) return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 3,
      padding: '1px 6px', borderRadius: 3, fontSize: 9, fontWeight: 600,
      background: 'rgba(251,146,60,0.10)', border: '1px solid rgba(251,146,60,0.22)',
      color: '#FB923C', whiteSpace: 'nowrap',
    }}>
      {event.abuse_confidence}% abuse
    </span>
  )
  if (event.geo_country_code && event.source_ip) return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 3,
      padding: '1px 6px', borderRadius: 3, fontSize: 9,
      background: 'rgba(52,211,153,0.07)', border: '1px solid rgba(52,211,153,0.15)',
      color: '#34D399', whiteSpace: 'nowrap',
    }}>
      <MapPin size={8} /> {event.geo_country_code}
    </span>
  )
  return null
}

// ─── Section / DetailRow for drawer ──────────────────────────────────────────

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
        {accent && <span style={{ display: 'inline-block', width: 3, height: 10, borderRadius: 2, background: accent, flexShrink: 0 }} />}
        {title}
      </div>
      <div style={{
        background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)',
        borderRadius: 6, padding: '8px 10px', display: 'flex', flexDirection: 'column', gap: 6,
      }}>
        {children}
      </div>
    </div>
  )
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
      <span style={{ fontSize: 10, color: '#4A5366', minWidth: 90, flexShrink: 0, paddingTop: 1 }}>{label}</span>
      <span style={{ fontSize: 11, color: '#B8C0CC', wordBreak: 'break-all', fontFamily: mono ? "'JetBrains Mono', monospace" : "'Inter', sans-serif" }}>
        {value}
      </span>
    </div>
  )
}

// ─── Fields Sidebar (Splunk-style) ────────────────────────────────────────────

function FieldsSidebar({
  events,
  onFilter,
}: {
  events: EventResponse[]
  onFilter: (field: string, value: string) => void
}) {
  const [open, setOpen] = useState<Record<string, boolean>>({
    category: true, host_name: true, username: false, source_ip: false, process_name: false,
  })

  const fieldDefs = useMemo(() => [
    { key: 'category',     label: 'category',     qField: 'category', get: (e: EventResponse) => e.category },
    { key: 'host_name',    label: 'host',         qField: 'host',     get: (e: EventResponse) => e.host_name },
    { key: 'username',     label: 'username',     qField: 'user',     get: (e: EventResponse) => e.username },
    { key: 'source_ip',    label: 'src_ip',       qField: 'ip',       get: (e: EventResponse) => e.source_ip },
    { key: 'process_name', label: 'process_name', qField: 'process',  get: (e: EventResponse) => e.process_name },
  ], [])

  const fieldCounts = useMemo(() => {
    const result: Record<string, Array<{ value: string; count: number }>> = {}
    for (const fd of fieldDefs) {
      const counts: Record<string, number> = {}
      for (const e of events) {
        const v = fd.get(e)
        if (v) counts[v] = (counts[v] ?? 0) + 1
      }
      result[fd.key] = Object.entries(counts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([value, count]) => ({ value, count }))
    }
    return result
  }, [events, fieldDefs])

  return (
    <div style={{
      width: 210, flexShrink: 0,
      borderRight: '1px solid rgba(255,255,255,0.05)',
      overflowY: 'auto', background: 'rgba(0,0,0,0.2)',
    }}>
      <div style={{
        padding: '8px 12px 6px',
        fontSize: 8, fontWeight: 800, textTransform: 'uppercase',
        letterSpacing: '1.2px', color: '#2F3A4A',
        borderBottom: '1px solid rgba(255,255,255,0.04)',
      }}>
        Interesting Fields
      </div>

      {fieldDefs.map(fd => {
        const values = fieldCounts[fd.key] ?? []
        if (values.length === 0) return null
        const isOpen = open[fd.key] ?? false
        const maxCount = values[0]?.count ?? 1

        return (
          <div key={fd.key} style={{ borderBottom: '1px solid rgba(255,255,255,0.025)' }}>
            <button
              onClick={() => setOpen(s => ({ ...s, [fd.key]: !s[fd.key] }))}
              style={{
                width: '100%', display: 'flex', alignItems: 'center',
                justifyContent: 'space-between', padding: '6px 12px',
                background: 'none', border: 'none', cursor: 'pointer',
              }}
            >
              <span style={{ fontSize: 11, color: '#60A5FA', fontFamily: "'JetBrains Mono', monospace" }}>
                {fd.label}
              </span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ fontSize: 9, color: '#2F3A4A', fontFamily: "'JetBrains Mono', monospace" }}>
                  {values.length}
                </span>
                {isOpen
                  ? <ChevronDown size={10} style={{ color: '#3A4150' }} />
                  : <ChevronRight size={10} style={{ color: '#2F3A4A' }} />
                }
              </div>
            </button>
            {isOpen && (
              <div style={{ padding: '2px 10px 8px' }}>
                {values.map(({ value, count }) => (
                  <button
                    key={value}
                    onClick={() => onFilter(fd.qField, value)}
                    title={`Add filter: ${fd.qField}:${value}`}
                    style={{
                      width: '100%', display: 'block', background: 'none',
                      border: 'none', cursor: 'pointer', padding: '3px 0', textAlign: 'left',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                      <span style={{
                        fontSize: 10, color: '#8B95A7',
                        fontFamily: "'JetBrains Mono', monospace",
                        overflow: 'hidden', textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap', maxWidth: 140,
                        transition: 'color 0.1s',
                      }}>
                        {value.length > 22 ? value.slice(0, 20) + '…' : value}
                      </span>
                      <span style={{ fontSize: 9, color: '#3A4150', flexShrink: 0, marginLeft: 4 }}>
                        {count}
                      </span>
                    </div>
                    <div style={{ height: 2, borderRadius: 1, background: 'rgba(255,255,255,0.05)' }}>
                      <div style={{
                        height: '100%', borderRadius: 1,
                        width: `${Math.round((count / maxCount) * 100)}%`,
                        background: 'rgba(59,130,246,0.45)',
                        transition: 'width 0.2s',
                      }} />
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

// ─── EventRow (expandable inline, no SEV badge) ───────────────────────────────

function EventRow({
  event,
  isExpanded,
  onToggle,
  onOpenDetail,
  onFilter,
}: {
  event: EventResponse
  isExpanded: boolean
  onToggle: () => void
  onOpenDetail: () => void
  onFilter: (field: string, value: string) => void
}) {
  const cat = categoryConfig[event.category] ?? categoryConfig.other
  const CatIcon = cat.icon
  const summary = buildSummary(event)
  const keyFields = isExpanded ? buildKeyFields(event) : []

  // Left border = severity indicator (replaces the SEV column badge)
  const borderColor =
    event.is_threat_ip ? '#EF4444' :
    event.is_anomaly   ? '#F59E0B' :
    event.severity >= 4 ? 'rgba(239,68,68,0.6)' :
    event.severity >= 3 ? 'rgba(249,115,22,0.5)' :
    event.severity >= 2 ? 'rgba(245,158,11,0.35)' :
    'transparent'

  const rowBg = isExpanded ? 'rgba(255,255,255,0.02)' : 'transparent'

  return (
    <>
      <tr
        onClick={onToggle}
        style={{
          cursor: 'pointer',
          borderLeft: `3px solid ${borderColor}`,
          borderBottom: `1px solid rgba(255,255,255,${isExpanded ? '0.05' : '0.025'})`,
          background: rowBg,
          transition: 'background 80ms',
        }}
      >
        {/* Expand chevron */}
        <td style={{ padding: '5px 4px 5px 6px', width: 18 }}>
          {isExpanded
            ? <ChevronDown size={11} style={{ color: '#60A5FA', display: 'block' }} />
            : <ChevronRight size={11} style={{ color: '#2F3A4A', display: 'block' }} />
          }
        </td>

        {/* Time */}
        <td style={{ padding: '5px 8px', width: 135, whiteSpace: 'nowrap' }}>
          <span style={{ fontSize: 10, color: '#4A5566', fontFamily: "'JetBrains Mono', monospace" }}>
            {formatDateTime(event.event_timestamp)}
          </span>
        </td>

        {/* Category */}
        <td style={{ padding: '5px 6px', width: 88 }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 10, color: cat.color, fontWeight: 500 }}>
            <CatIcon size={10} /> {cat.label}
          </span>
        </td>

        {/* Host */}
        <td style={{ padding: '5px 6px', width: 140 }}>
          <span style={{
            fontSize: 10, color: '#6B7A8D',
            fontFamily: "'JetBrains Mono', monospace",
            overflow: 'hidden', textOverflow: 'ellipsis',
            display: 'block', whiteSpace: 'nowrap', maxWidth: 130,
          }}>
            {event.host_name ?? '—'}
          </span>
        </td>

        {/* Risk intel */}
        <td style={{ padding: '5px 6px', width: 100 }}>
          <RiskBadge event={event} />
        </td>

        {/* Summary — the main content */}
        <td style={{ padding: '5px 10px' }}>
          <span style={{
            fontSize: 11,
            color: event.is_threat_ip ? '#FCA5A5' : event.is_anomaly ? '#FCD34D' : '#9AA5B4',
            fontFamily: event.category === 'process' ? "'JetBrains Mono', monospace" : 'inherit',
            display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>
            {summary}
          </span>
        </td>
      </tr>

      {/* ── Inline expanded detail ── */}
      {isExpanded && (
        <tr style={{ background: 'rgba(15,23,42,0.6)', borderLeft: `3px solid ${borderColor}` }}>
          <td colSpan={6} style={{ padding: '10px 14px 14px 26px' }}>
            {/* Key-value chips */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginBottom: 10 }}>
              {keyFields.map(f => (
                <div key={f.key} style={{
                  padding: '3px 9px', borderRadius: 4,
                  background: 'rgba(255,255,255,0.03)',
                  border: '1px solid rgba(255,255,255,0.07)',
                  display: 'flex', alignItems: 'center', gap: 6,
                }}>
                  <span style={{
                    fontSize: 8, color: '#3A4A5C', textTransform: 'uppercase',
                    letterSpacing: '0.5px', fontWeight: 700, flexShrink: 0,
                  }}>
                    {f.key}
                  </span>
                  <span style={{
                    fontSize: 10, color: '#A8B5C2',
                    fontFamily: f.mono ? "'JetBrains Mono', monospace" : 'inherit',
                    maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>
                    {f.value}
                  </span>
                </div>
              ))}
            </div>

            {/* Action row */}
            <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
              <button
                onClick={e => { e.stopPropagation(); onOpenDetail() }}
                style={{
                  display: 'flex', alignItems: 'center', gap: 5,
                  padding: '4px 10px', borderRadius: 5, fontSize: 10,
                  background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.2)',
                  color: '#60A5FA', cursor: 'pointer',
                }}
              >
                <FolderSearch size={10} /> Open Full Details
              </button>
              {event.host_name && (
                <button
                  onClick={e => { e.stopPropagation(); onFilter('host', event.host_name!) }}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 4,
                    padding: '4px 10px', borderRadius: 5, fontSize: 10,
                    background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)',
                    color: '#5C6373', cursor: 'pointer',
                  }}
                >
                  + host:{event.host_name}
                </button>
              )}
              {event.source_ip && (
                <button
                  onClick={e => { e.stopPropagation(); onFilter('ip', event.source_ip!) }}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 4,
                    padding: '4px 10px', borderRadius: 5, fontSize: 10,
                    background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)',
                    color: '#5C6373', cursor: 'pointer',
                  }}
                >
                  + ip:{event.source_ip}
                </button>
              )}
              {event.category && (
                <button
                  onClick={e => { e.stopPropagation(); onFilter('category', event.category) }}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 4,
                    padding: '4px 10px', borderRadius: 5, fontSize: 10,
                    background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)',
                    color: '#5C6373', cursor: 'pointer',
                  }}
                >
                  + category:{event.category}
                </button>
              )}
              <button
                onClick={e => {
                  e.stopPropagation()
                  navigator.clipboard.writeText(JSON.stringify(event, null, 2))
                }}
                style={{
                  display: 'flex', alignItems: 'center', gap: 4,
                  padding: '4px 10px', borderRadius: 5, fontSize: 10,
                  background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)',
                  color: '#3A4150', cursor: 'pointer',
                }}
              >
                <Copy size={9} /> Copy JSON
              </button>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ─── EventDrawer (full detail panel) ─────────────────────────────────────────

function EventDrawer({ event, onClose }: { event: EventResponse; onClose: () => void }) {
  const [showCreateInv, setShowCreateInv] = useState(false)
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
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, zIndex: 49, background: 'rgba(0,0,0,0.45)' }} />
      <div style={{
        position: 'fixed', right: 0, top: 50,
        height: 'calc(100vh - 50px)', width: 490,
        background: '#070A0F', borderLeft: '1px solid rgba(255,255,255,0.07)',
        display: 'flex', flexDirection: 'column', zIndex: 50,
        animation: 'slideInRight 200ms ease both',
      }}>

        {/* Header */}
        <div style={{
          padding: '14px 16px',
          borderBottom: '1px solid rgba(255,255,255,0.06)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          flexShrink: 0,
          background: event.is_threat_ip ? 'rgba(248,113,113,0.03)' : event.is_anomaly ? 'rgba(251,191,36,0.02)' : 'transparent',
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
                <span style={{ fontSize: 13, fontWeight: 700, color: '#F5F7FA' }}>{cat.label} Event</span>
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
              <div style={{ fontSize: 9, color: '#2F3A4A', marginTop: 3, fontFamily: "'JetBrains Mono', monospace" }}>
                {event.id}
              </div>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#4A5366', cursor: 'pointer', padding: 4 }}>
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>

          {/* Meta grid */}
          <div style={{
            display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px 14px', marginBottom: 18,
            background: 'rgba(255,255,255,0.015)', border: '1px solid rgba(255,255,255,0.05)',
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
                <div style={{ fontSize: 8, color: '#2F3A4A', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 3, fontWeight: 700 }}>
                  {label}
                </div>
                <div style={{ fontSize: 11, color: '#7A8699', fontFamily: "'JetBrains Mono', monospace", overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {value}
                </div>
              </div>
            ))}
          </div>

          {/* Threat Intel */}
          {(hasExternalIp || event.is_threat_ip || event.threat_intel_flags.length > 0) && (
            <Section title="Threat Intelligence" accent={threatColor}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{
                  padding: '2px 8px', borderRadius: 4, fontSize: 9, fontWeight: 700,
                  background: `${threatColor}18`, color: threatColor,
                  border: `1px solid ${threatColor}30`,
                }}>
                  {threatLevel === 'threat' ? '⚠ KNOWN THREAT' : threatLevel === 'high' ? '⚠ HIGH RISK' : threatLevel === 'suspicious' ? '◆ SUSPICIOUS' : '✓ CLEAN'}
                </span>
                {event.abuse_confidence > 0 && (
                  <span style={{ fontSize: 10, color: '#5C6880' }}>
                    Abuse confidence: <span style={{ color: threatColor, fontWeight: 600 }}>{event.abuse_confidence}%</span>
                  </span>
                )}
              </div>
              {event.threat_intel_flags.length > 0 && (() => {
                const flags = (event.threat_intel_flags as unknown) as Array<{ flag: string; level: string; reason?: string }>
                return flags.map((f, i) => {
                  const fc = f.level === 'critical' || f.level === 'high' ? '#F87171' : f.level === 'medium' ? '#FB923C' : '#FBBF24'
                  return (
                    <div key={i} style={{ background: `${fc}08`, border: `1px solid ${fc}22`, borderRadius: 5, padding: '6px 8px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                        <span style={{ fontSize: 9, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", color: fc, textTransform: 'uppercase' }}>{f.flag}</span>
                        <span style={{ fontSize: 8, padding: '1px 5px', borderRadius: 2, background: `${fc}18`, color: fc }}>{f.level}</span>
                      </div>
                      {f.reason && <p style={{ margin: '4px 0 0', fontSize: 10, color: '#7A8699', lineHeight: 1.5 }}>{f.reason}</p>}
                    </div>
                  )
                })
              })()}
            </Section>
          )}

          {/* Geo */}
          {(event.geo_country || event.geo_city) && (
            <Section title="Geolocation" accent="#34D399">
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <MapPin size={12} style={{ color: '#34D399' }} />
                <span style={{ fontSize: 12, color: '#F5F7FA', fontWeight: 600 }}>
                  {[event.geo_city, event.geo_country].filter(Boolean).join(', ')}
                  {event.geo_country_code && (
                    <span style={{ marginLeft: 8, fontSize: 9, padding: '1px 5px', background: 'rgba(52,211,153,0.10)', border: '1px solid rgba(52,211,153,0.20)', borderRadius: 3, color: '#34D399' }}>
                      {event.geo_country_code}
                    </span>
                  )}
                </span>
              </div>
              {[['ISP', event.geo_isp], ['Lat', event.geo_latitude != null ? String(event.geo_latitude) : null], ['Lon', event.geo_longitude != null ? String(event.geo_longitude) : null]].filter(([, v]) => v).map(([k, v]) => (
                <DetailRow key={String(k)} label={String(k)} value={String(v)} />
              ))}
            </Section>
          )}

          {/* Process */}
          {(event.process_name || process) && (
            <Section title="Process">
              {[
                ['Name',         event.process_name],
                ['PID',          process?.pid != null ? String(process.pid) : null],
                ['Parent',       process?.parent_name as string | null],
                ['Command Line', process?.command_line as string | null],
              ].filter(([, v]) => v).map(([k, v]) => (
                <DetailRow key={String(k)} label={String(k)} value={String(v)} mono={k === 'Command Line' || k === 'PID'} />
              ))}
            </Section>
          )}

          {/* Network */}
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

          {/* File */}
          {file && (
            <Section title="File">
              {[
                ['Path',      file.path as string | null],
                ['Operation', file.operation as string | null],
                ['SHA-256',   file.hash_sha256 as string | null],
                ['Size',      file.size != null ? String(file.size) : null],
              ].filter(([, v]) => v).map(([k, v]) => (
                <DetailRow key={String(k)} label={String(k)} value={String(v)} mono />
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

          {/* Correlation */}
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

          {/* Raw JSON */}
          <Section title="Raw Event">
            <pre style={{
              margin: 0, fontSize: 9, color: '#3A4A5C', overflowX: 'auto',
              fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.6,
              maxHeight: 200,
            }}>
              {JSON.stringify(event.raw, null, 2)}
            </pre>
          </Section>
        </div>

        {/* Footer */}
        <div style={{
          padding: '12px 16px', borderTop: '1px solid rgba(255,255,255,0.06)',
          display: 'flex', gap: 8, flexShrink: 0,
        }}>
          <Button variant="secondary" size="sm" style={{ flex: 1 }}
            onClick={() => {
              navigator.clipboard.writeText(JSON.stringify(event, null, 2)).catch(e => toastError(extractApiError(e), 'Copy failed'))
            }}>
            <Copy size={12} /> Copy JSON
          </Button>
          <Button variant="primary" size="sm" onClick={() => setShowCreateInv(true)}>
            <FolderSearch size={12} /> Investigate
          </Button>
        </div>
      </div>
      {showCreateInv && (
        <CreateInvestigationModal
          open={showCreateInv}
          onClose={() => setShowCreateInv(false)}
          prefillTitle={event.process_name
            ? `Investigate ${event.process_name} on ${event.host_name ?? 'unknown host'}`
            : `Investigate ${event.category} event on ${event.host_name ?? 'unknown host'}`}
        />
      )}
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
  { label: 'Registry Changes', query: 'category:registry earliest:24h'              },
  { label: 'WMI Activity',     query: 'process:wmiprvse.exe earliest:24h'           },
]

type ViewFilter = 'all' | 'threats' | 'anomalies' | 'critical'

// ─── EventsPage ───────────────────────────────────────────────────────────────

export function EventsPage() {
  const [searchParams]  = useSearchParams()
  const [queryText,     setQueryText]    = useState('')
  const [parsedSearch,  setParsedSearch] = useState<Partial<EventSearchRequest>>({})
  const [agentId,       setAgentId]      = useState(searchParams.get('agent_id') ?? '')
  const [selectedEvent, setSelectedEvent] = useState<EventResponse | null>(null)
  const [viewFilter,    setViewFilter]   = useState<ViewFilter>('all')
  const [expandedIds,   setExpandedIds]  = useState<Set<string>>(new Set())

  useEffect(() => {
    const aid = searchParams.get('agent_id')
    if (aid) setAgentId(aid)
  }, [searchParams])

  const applySearch = useCallback((text: string) => {
    setQueryText(text)
    setParsedSearch(parseSearchQuery(text))
    setExpandedIds(new Set())
  }, [])

  const clearSearch = useCallback(() => {
    setQueryText('')
    setParsedSearch({})
    setAgentId('')
    setExpandedIds(new Set())
  }, [])

  const { data, isLoading, refetch } = useEvents({
    searchRequest: parsedSearch,
    agent_id: agentId || undefined,
    limit: 200,
  })

  const allEvents   = data?.items ?? []
  const total       = data?.total_estimate ?? 0
  const threatCount  = useMemo(() => allEvents.filter(e => e.is_threat_ip).length, [allEvents])
  const anomalyCount = useMemo(() => allEvents.filter(e => e.is_anomaly).length,   [allEvents])
  const criticalCount= useMemo(() => allEvents.filter(e => e.severity >= 3).length,[allEvents])

  // 30-bucket time histogram
  const histogram = useMemo(() => {
    const N = 30
    if (allEvents.length < 2) return [] as number[]
    const times = allEvents.map(e => new Date(e.event_timestamp).getTime()).filter(t => !isNaN(t))
    if (times.length < 2) return Array(N).fill(0) as number[]
    const mn = Math.min(...times), mx = Math.max(...times)
    const span = mx - mn || 1
    const counts = Array(N).fill(0) as number[]
    for (const t of times) counts[Math.min(Math.floor(((t - mn) / span) * N), N - 1)]++
    return counts
  }, [allEvents])

  const maxBucket = Math.max(...histogram, 1)

  const events = useMemo(() => {
    if (viewFilter === 'threats')   return allEvents.filter(e => e.is_threat_ip)
    if (viewFilter === 'anomalies') return allEvents.filter(e => e.is_anomaly)
    if (viewFilter === 'critical')  return allEvents.filter(e => e.severity >= 3)
    return allEvents
  }, [allEvents, viewFilter])

  const toggleExpand = useCallback((id: string) => {
    setExpandedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }, [])

  const addFieldFilter = useCallback((field: string, value: string) => {
    const q = queryText.trim() ? `${queryText.trim()} ${field}:${value}` : `${field}:${value}`
    applySearch(q)
  }, [queryText, applySearch])

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
      a.href = url; a.download = `events.${format}`; a.click()
      URL.revokeObjectURL(url)
    } catch (e) { toastError(extractApiError(e), 'Export failed') }
  }

  const hasSearch = !!(queryText || agentId)

  return (
    <div
      className="page-in"
      style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 50px - 40px)', overflow: 'hidden' }}
    >

      {/* ── Search bar — hero element ── */}
      <div style={{
        paddingBottom: 8, borderBottom: '1px solid rgba(255,255,255,0.05)', flexShrink: 0,
      }}>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 6 }}>
          <div style={{ flex: 1 }}>
            <SearchAutocomplete
              value={queryText}
              onChange={setQueryText}
              onSearch={() => applySearch(queryText)}
            />
          </div>
          {hasSearch && (
            <button onClick={clearSearch} style={{
              display: 'flex', alignItems: 'center', gap: 4,
              padding: '0 10px', height: 32, borderRadius: 5, flexShrink: 0,
              fontSize: 11, color: '#5C6373',
              background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)',
              cursor: 'pointer',
            }}>
              <X size={11} /> Clear
            </button>
          )}
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

        {/* Saved searches */}
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ fontSize: 9, color: '#2F3A4A', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', marginRight: 2 }}>
            Saved:
          </span>
          {QUICK_SEARCHES.map(t => (
            <button
              key={t.label}
              onClick={() => applySearch(t.query)}
              style={{
                padding: '2px 8px', borderRadius: 4, fontSize: 9, fontWeight: 600,
                background: queryText === t.query ? 'rgba(59,130,246,0.12)' : 'rgba(255,255,255,0.025)',
                border: queryText === t.query ? '1px solid rgba(59,130,246,0.3)' : '1px solid rgba(255,255,255,0.06)',
                color: queryText === t.query ? '#60A5FA' : '#3A4150',
                cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace",
                transition: 'all 0.1s',
              }}
            >
              {t.label}
            </button>
          ))}
          {agentId && (
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: 4,
              padding: '2px 8px', borderRadius: 4, fontSize: 9,
              background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.2)',
              color: '#60A5FA', fontFamily: "'JetBrains Mono', monospace",
            }}>
              agent:{agentId.slice(0, 8)}
              <button onClick={() => setAgentId('')} style={{ background: 'none', border: 'none', color: '#60A5FA', cursor: 'pointer', padding: 0 }}>
                <X size={9} />
              </button>
            </span>
          )}
        </div>
      </div>

      {/* ── Stats bar + Histogram ── */}
      {(allEvents.length > 0 || isLoading) && (
        <div style={{ padding: '8px 0 6px', borderBottom: '1px solid rgba(255,255,255,0.04)', flexShrink: 0 }}>
          {/* Stats row */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: histogram.length > 0 ? 6 : 0 }}>
            <span style={{ fontSize: 18, fontWeight: 800, color: '#F5F7FA', fontFamily: "'Space Grotesk', sans-serif", lineHeight: 1 }}>
              {total.toLocaleString()}
            </span>
            <span style={{ fontSize: 11, color: '#3A4150' }}>events</span>

            <span style={{ width: 1, height: 14, background: 'rgba(255,255,255,0.08)' }} />

            {/* View filter pills */}
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
              {[
                { id: 'all'       as const, label: `All · ${allEvents.length}`,          color: '#8B95A7' },
                { id: 'threats'   as const, label: `⚠ Threats · ${threatCount}`,          color: '#F87171', hide: threatCount === 0 },
                { id: 'anomalies' as const, label: `◆ Anomalies · ${anomalyCount}`,       color: '#FBBF24', hide: anomalyCount === 0 },
                { id: 'critical'  as const, label: `↑ High/Critical · ${criticalCount}`,  color: '#FB923C', hide: criticalCount === 0 },
              ].filter(p => !('hide' in p && p.hide)).map(pill => (
                <button
                  key={pill.id}
                  onClick={() => setViewFilter(pill.id)}
                  style={{
                    padding: '2px 9px', borderRadius: 4, cursor: 'pointer',
                    fontSize: 9, fontWeight: 700, whiteSpace: 'nowrap',
                    border: viewFilter === pill.id ? `1px solid ${pill.color}45` : '1px solid rgba(255,255,255,0.05)',
                    background: viewFilter === pill.id ? `${pill.color}12` : 'rgba(255,255,255,0.02)',
                    color: viewFilter === pill.id ? pill.color : '#3A4150',
                    transition: 'all 100ms',
                  }}
                >
                  {pill.label}
                </button>
              ))}
            </div>

            {threatCount === 0 && anomalyCount === 0 && allEvents.length > 0 && (
              <span style={{ fontSize: 10, color: '#34D399', marginLeft: 4 }}>
                ✓ No threats in view
              </span>
            )}
          </div>

          {/* Histogram */}
          {histogram.length > 0 && (
            <div>
              <svg
                width="100%" height={36}
                viewBox={`0 0 ${histogram.length * 12} 36`}
                preserveAspectRatio="none"
                style={{ display: 'block', cursor: 'default' }}
              >
                {histogram.map((cnt, i) => {
                  const h = cnt === 0 ? 2 : Math.max(3, Math.round((cnt / maxBucket) * 32))
                  const isHigh = cnt >= maxBucket * 0.7
                  return (
                    <rect
                      key={i}
                      x={i * 12} y={34 - h} width={10} height={h} rx={1.5}
                      fill={
                        cnt === 0  ? 'rgba(255,255,255,0.04)' :
                        isHigh && threatCount > 0 ? 'rgba(248,113,113,0.6)' :
                        isHigh     ? 'rgba(59,130,246,0.7)' :
                                     'rgba(59,130,246,0.35)'
                      }
                    />
                  )
                })}
              </svg>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 1 }}>
                <span style={{ fontSize: 8, color: '#2A3140' }}>older ←</span>
                <span style={{ fontSize: 8, color: '#2A3140' }}>→ newest</span>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Main area: Fields sidebar + Events table ── */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden', minHeight: 0 }}>

        {/* Fields sidebar — only when there's data */}
        {allEvents.length > 0 && (
          <FieldsSidebar events={allEvents} onFilter={addFieldFilter} />
        )}

        {/* Events table */}
        <div style={{ flex: 1, overflowY: 'auto', minWidth: 0 }}>

          {/* Skeleton */}
          {isLoading && (
            <div style={{ padding: '8px 0' }}>
              {Array.from({ length: 14 }).map((_, i) => (
                <div key={i} style={{
                  display: 'flex', gap: 10, padding: '7px 12px',
                  borderBottom: '1px solid rgba(255,255,255,0.025)',
                  borderLeft: '3px solid transparent',
                }}>
                  <span className="skel" style={{ width: 12, height: 12, flexShrink: 0 }} />
                  <span className="skel" style={{ width: 120, height: 10 }} />
                  <span className="skel" style={{ width: 70,  height: 10 }} />
                  <span className="skel" style={{ width: 110, height: 10 }} />
                  <span className="skel" style={{ width: 280, height: 10, flex: 1 }} />
                </div>
              ))}
            </div>
          )}

          {/* Empty state */}
          {!isLoading && events.length === 0 && (
            <div style={{ textAlign: 'center', padding: '80px 20px' }}>
              <Activity size={36} style={{ color: '#2A3140', display: 'block', margin: '0 auto 14px' }} />
              <div style={{ fontSize: 14, fontWeight: 600, color: '#4A5366', marginBottom: 8 }}>
                {viewFilter !== 'all'
                  ? `No ${viewFilter} events in current view`
                  : hasSearch
                    ? 'No events match your search'
                    : 'No events found'}
              </div>
              <div style={{ fontSize: 12, color: '#2F3A4A' }}>
                {viewFilter !== 'all' ? (
                  <button onClick={() => setViewFilter('all')} style={{ color: '#60A5FA', background: 'none', border: 'none', cursor: 'pointer', fontSize: 12 }}>
                    ← Show all events
                  </button>
                ) : hasSearch
                  ? 'Try a different search or clear filters'
                  : 'Events appear here as agents report telemetry'
                }
              </div>
              {!hasSearch && (
                <div style={{ marginTop: 20, display: 'flex', gap: 6, justifyContent: 'center', flexWrap: 'wrap' }}>
                  {QUICK_SEARCHES.slice(0, 4).map(t => (
                    <button
                      key={t.label}
                      onClick={() => applySearch(t.query)}
                      style={{
                        padding: '5px 12px', borderRadius: 5, fontSize: 10,
                        background: 'rgba(59,130,246,0.06)', border: '1px solid rgba(59,130,246,0.15)',
                        color: '#60A5FA', cursor: 'pointer',
                      }}
                    >
                      {t.label}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Events table */}
          {!isLoading && events.length > 0 && (
            <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
              <thead style={{ position: 'sticky', top: 0, background: '#050505', zIndex: 5 }}>
                <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                  <th style={{ width: 20, padding: '6px 4px' }} />
                  <th style={{ width: 135, padding: '6px 8px', textAlign: 'left', fontSize: 8, fontWeight: 800, color: '#2F3A4A', textTransform: 'uppercase', letterSpacing: '1px' }}>TIME</th>
                  <th style={{ width: 90,  padding: '6px 6px', textAlign: 'left', fontSize: 8, fontWeight: 800, color: '#2F3A4A', textTransform: 'uppercase', letterSpacing: '1px' }}>CATEGORY</th>
                  <th style={{ width: 140, padding: '6px 6px', textAlign: 'left', fontSize: 8, fontWeight: 800, color: '#2F3A4A', textTransform: 'uppercase', letterSpacing: '1px' }}>HOST</th>
                  <th style={{ width: 100, padding: '6px 6px', textAlign: 'left', fontSize: 8, fontWeight: 800, color: '#2F3A4A', textTransform: 'uppercase', letterSpacing: '1px' }}>RISK INTEL</th>
                  <th style={{ padding: '6px 10px', textAlign: 'left', fontSize: 8, fontWeight: 800, color: '#2F3A4A', textTransform: 'uppercase', letterSpacing: '1px' }}>SUMMARY</th>
                </tr>
              </thead>
              <tbody>
                {events.map(evt => (
                  <EventRow
                    key={evt.id}
                    event={evt}
                    isExpanded={expandedIds.has(evt.id)}
                    onToggle={() => toggleExpand(evt.id)}
                    onOpenDetail={() => setSelectedEvent(evt)}
                    onFilter={addFieldFilter}
                  />
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Full detail drawer */}
      {selectedEvent && (
        <EventDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} />
      )}
    </div>
  )
}
