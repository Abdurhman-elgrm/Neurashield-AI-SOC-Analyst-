import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, Search, Monitor, Terminal, Activity, Trash2, X } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { formatRelativeTime } from '@/lib/utils'
import { formatDateTime } from '@/lib/timezone'
import { useAgents, useDeleteAgent } from './hooks/useAgents'
import type { Agent } from '@/api/agents'

// ─── Status badge (shared) ────────────────────────────────────────────────────

function AgentStatusBadge({ status }: { status: string }) {
  const cfg =
    status === 'online'   ? { color: '#10B981', bg: 'rgba(16,185,129,0.1)',  label: 'ONLINE'   } :
    status === 'degraded' ? { color: '#F59E0B', bg: 'rgba(245,158,11,0.1)', label: 'DEGRADED' } :
                            { color: '#4B5563', bg: 'rgba(75,85,99,0.1)',    label: 'OFFLINE'  }

  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '2px 7px', borderRadius: 4,
      fontSize: 9, fontWeight: 700,
      fontFamily: "'JetBrains Mono', monospace",
      textTransform: 'uppercase',
      color: cfg.color, background: cfg.bg,
    }}>
      <span style={{
        width: 5, height: 5, borderRadius: '50%',
        background: cfg.color, flexShrink: 0,
        boxShadow: status === 'online' ? `0 0 6px ${cfg.color}` : 'none',
      }} />
      {cfg.label}
    </span>
  )
}

// ─── AgentRow ─────────────────────────────────────────────────────────────────

function AgentRow({ agent, onClick, onDelete }: {
  agent: Agent
  onClick: () => void
  onDelete: () => void
}) {
  const navigate = useNavigate()
  const [hovered, setHovered] = useState(false)

  const osIcon = agent.os_type === 'windows'
    ? <Monitor size={13} />
    : <Terminal size={13} />

  return (
    <tr
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        borderLeft: '3px solid transparent',
        borderBottom: '1px solid rgba(255,255,255,0.04)',
        background: hovered ? 'rgba(255,255,255,0.025)' : 'transparent',
        cursor: 'pointer', transition: 'background 120ms',
      }}
    >
      {/* Status */}
      <td style={{ padding: '9px 12px' }}>
        <AgentStatusBadge status={agent.status} />
      </td>

      {/* Hostname */}
      <td style={{ padding: '9px 12px' }}>
        <span style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 12, fontWeight: 600, color: '#F5F7FA',
        }}>
          {agent.hostname}
        </span>
      </td>

      {/* OS */}
      <td style={{ padding: '9px 12px' }}>
        <span style={{
          display: 'inline-flex', alignItems: 'center', gap: 5,
          fontSize: 12, color: '#8B95A7',
        }}>
          {osIcon}
          {agent.os_type === 'windows' ? 'Windows' :
           agent.os_type === 'linux'   ? 'Linux'   :
           agent.os_type === 'macos'   ? 'macOS'   : agent.os_type}
        </span>
      </td>

      {/* IP */}
      <td style={{ padding: '9px 12px' }}>
        <span style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11, color: '#8B95A7',
        }}>
          {agent.ip_address || '—'}
        </span>
      </td>

      {/* Version */}
      <td style={{ padding: '9px 12px' }}>
        <span style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11, color: '#5C6373',
        }}>
          {agent.agent_version ? `v${agent.agent_version}` : '—'}
        </span>
      </td>

      {/* Last seen */}
      <td style={{ padding: '9px 12px' }}>
        <span style={{ fontSize: 11, color: '#5C6373' }}>
          {agent.last_seen_at ? formatRelativeTime(agent.last_seen_at) : '—'}
        </span>
      </td>

      {/* Actions */}
      <td style={{ padding: '9px 12px' }} onClick={e => e.stopPropagation()}>
        <div style={{
          display: 'flex', gap: 4,
          opacity: hovered ? 1 : 0, transition: 'opacity 120ms',
        }}>
          <Button
            variant="ghost" size="icon-sm"
            title="View events"
            onClick={() => navigate(`/events?agent_id=${agent.id}`)}
          >
            <Activity size={13} />
          </Button>
          <Button
            variant="ghost" size="icon-sm"
            title="Delete agent"
            onClick={onDelete}
            style={{ color: '#F87171' }}
          >
            <Trash2 size={13} />
          </Button>
        </div>
      </td>
    </tr>
  )
}

// ─── AgentDrawer ──────────────────────────────────────────────────────────────

function AgentDrawer({ agent, onClose, onDelete }: {
  agent: Agent
  onClose: () => void
  onDelete: () => void
}) {
  const navigate = useNavigate()

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0, zIndex: 49,
          background: 'rgba(0,0,0,0.4)',
        }}
      />

      {/* Drawer */}
      <div style={{
        position: 'fixed', right: 0,
        top: 50,
        height: 'calc(100vh - 50px)',
        width: 400,
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
          justifyContent: 'space-between',
          flexShrink: 0,
        }}>
          <div>
            <div style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 14, fontWeight: 700, color: '#F5F7FA',
            }}>
              {agent.hostname}
            </div>
            <div style={{ marginTop: 4 }}>
              <AgentStatusBadge status={agent.status} />
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none', border: 'none',
              color: '#5C6373', cursor: 'pointer', padding: 4,
            }}
          >
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>

          <div style={{
            fontSize: 9, fontWeight: 700,
            textTransform: 'uppercase', letterSpacing: '1.5px',
            color: '#5C6373', marginBottom: 10,
          }}>
            Device Information
          </div>

          <div style={{
            display: 'grid', gridTemplateColumns: '1fr 1fr',
            gap: '10px 16px', marginBottom: 20,
          }}>
            {([
              ['OS',         agent.os_type],
              ['IP Address', agent.ip_address || '—'],
              ['Version',    agent.agent_version ? `v${agent.agent_version}` : '—'],
              ['Enrolled',   formatDateTime(agent.created_at)],
              ['Last Seen',  agent.last_seen_at ? formatRelativeTime(agent.last_seen_at) : '—'],
              ['Agent ID',   agent.id.slice(0, 8) + '...'],
            ] as [string, string][]).map(([label, value]) => (
              <div key={label}>
                <div style={{
                  fontSize: 9, color: '#5C6373',
                  textTransform: 'uppercase',
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

          {agent.tags?.length > 0 && (
            <>
              <div style={{
                fontSize: 9, fontWeight: 700,
                textTransform: 'uppercase', letterSpacing: '1.5px',
                color: '#5C6373', marginBottom: 8,
              }}>
                Tags
              </div>
              <div style={{
                display: 'flex', flexWrap: 'wrap', gap: 5, marginBottom: 20,
              }}>
                {agent.tags.map(tag => (
                  <span key={tag} style={{
                    padding: '2px 8px', borderRadius: 4,
                    fontSize: 10, color: '#8B95A7',
                    background: 'rgba(255,255,255,0.05)',
                    border: '1px solid rgba(255,255,255,0.08)',
                    fontFamily: "'JetBrains Mono', monospace",
                  }}>
                    {tag}
                  </span>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div style={{
          padding: '12px 16px',
          borderTop: '1px solid rgba(255,255,255,0.06)',
          display: 'flex', gap: 8, flexShrink: 0,
        }}>
          <Button
            variant="secondary" size="sm"
            style={{ flex: 1 }}
            onClick={() => navigate(`/events?agent_id=${agent.id}`)}
          >
            <Activity size={12} /> View Events
          </Button>
          <Button variant="danger" size="sm" onClick={onDelete}>
            <Trash2 size={12} /> Remove
          </Button>
        </div>
      </div>
    </>
  )
}

// ─── DeleteConfirmModal ───────────────────────────────────────────────────────

function DeleteConfirmModal({ onConfirm, onCancel, loading }: {
  onConfirm: () => void
  onCancel: () => void
  loading: boolean
}) {
  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 100,
      background: 'rgba(0,0,0,0.7)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        width: 380, background: '#111111',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: 10, padding: 24,
      }}>
        <div style={{
          fontSize: 14, fontWeight: 700,
          fontFamily: "'Space Grotesk', sans-serif",
          color: '#F5F7FA', marginBottom: 8,
        }}>
          Remove Agent
        </div>
        <div style={{
          fontSize: 12, color: '#8B95A7', marginBottom: 20, lineHeight: 1.6,
        }}>
          This agent will stop reporting. The device won't be monitored
          until re-enrolled. This action cannot be undone.
        </div>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <Button variant="ghost" onClick={onCancel}>Cancel</Button>
          <Button variant="danger" loading={loading} onClick={onConfirm}>
            Remove Agent
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── AgentsPage ───────────────────────────────────────────────────────────────

export function AgentsPage() {
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)

  const { data, isLoading } = useAgents({
    status: statusFilter || undefined,
    search: search || undefined,
  })

  const deleteAgent = useDeleteAgent()

  const agents = data?.items ?? []
  const total = data?.total ?? 0
  const onlineCount = agents.filter(a => a.status === 'online').length

  return (
    <div className="page-in" style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 50px - 40px)', overflow: 'hidden' }}>

      {/* Page header */}
      <div style={{
        display: 'flex', alignItems: 'flex-start',
        justifyContent: 'space-between',
        paddingBottom: 12,
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        flexShrink: 0,
      }}>
        <div>
          <h1 style={{
            fontSize: 17, fontWeight: 800, color: '#F5F7FA',
            fontFamily: "'Space Grotesk', sans-serif",
          }}>
            Agents
          </h1>
          <p style={{ fontSize: 12, color: '#5C6373', marginTop: 3 }}>
            <span style={{ color: '#10B981', fontWeight: 600 }}>
              {onlineCount} online
            </span>
            {' · '}
            {total} total
          </p>
        </div>
        <Button variant="primary" size="sm" onClick={() => navigate('/installer')}>
          <Plus size={13} /> Connect Device
        </Button>
      </div>

      {/* Filter bar */}
      <div style={{
        display: 'flex', gap: 8, padding: '8px 0',
        borderBottom: '1px solid rgba(255,255,255,0.04)',
        alignItems: 'center', flexShrink: 0,
      }}>
        <div style={{ position: 'relative' }}>
          <Search size={12} style={{
            position: 'absolute', left: 9, top: '50%',
            transform: 'translateY(-50%)', color: '#5C6373',
            pointerEvents: 'none',
          }} />
          <input
            className="inp"
            style={{ width: 240, paddingLeft: 28 }}
            placeholder="Search hostname..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        <select
          className="inp"
          style={{ width: 130 }}
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
        >
          <option value="">All Status</option>
          <option value="online">Online</option>
          <option value="offline">Offline</option>
          <option value="degraded">Degraded</option>
        </select>
      </div>

      {/* Table */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        <table className="data-table">
          <thead style={{ position: 'sticky', top: 0, background: '#050505', zIndex: 10 }}>
            <tr>
              <th style={{ width: 100 }}>STATUS</th>
              <th>HOSTNAME</th>
              <th style={{ width: 100 }}>OS</th>
              <th style={{ width: 130 }}>IP ADDRESS</th>
              <th style={{ width: 90 }}>VERSION</th>
              <th style={{ width: 110 }}>LAST SEEN</th>
              <th style={{ width: 80 }}></th>
            </tr>
          </thead>
          <tbody>
            {/* Skeleton */}
            {isLoading && Array.from({ length: 6 }).map((_, i) => (
              <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                {[100, 160, 80, 120, 60, 80, 60].map((w, j) => (
                  <td key={j} style={{ padding: '9px 12px' }}>
                    <span className="skel" style={{ width: w, height: 14, display: 'block' }} />
                  </td>
                ))}
              </tr>
            ))}

            {/* Rows */}
            {!isLoading && agents.map(agent => (
              <AgentRow
                key={agent.id}
                agent={agent}
                onClick={() => setSelectedAgent(agent)}
                onDelete={() => setDeleteConfirm(agent.id)}
              />
            ))}

            {/* Empty */}
            {!isLoading && agents.length === 0 && (
              <tr>
                <td colSpan={7}>
                  <div style={{ textAlign: 'center', padding: '60px 0' }}>
                    <Monitor size={36} style={{ color: '#3A4150', marginBottom: 12, display: 'block', margin: '0 auto 12px' }} />
                    <div style={{
                      fontSize: 14, fontWeight: 600,
                      color: '#5C6373', marginBottom: 6,
                    }}>
                      No agents deployed
                    </div>
                    <div style={{
                      fontSize: 12, color: '#3A4150', marginBottom: 20,
                    }}>
                      Connect your first device to start monitoring
                    </div>
                    <Button variant="primary" onClick={() => navigate('/installer')}>
                      Connect Device
                    </Button>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Agent detail drawer */}
      {selectedAgent && (
        <AgentDrawer
          agent={selectedAgent}
          onClose={() => setSelectedAgent(null)}
          onDelete={() => {
            setDeleteConfirm(selectedAgent.id)
            setSelectedAgent(null)
          }}
        />
      )}

      {/* Delete confirm modal */}
      {deleteConfirm && (
        <DeleteConfirmModal
          loading={deleteAgent.isPending}
          onConfirm={async () => {
            await deleteAgent.mutateAsync(deleteConfirm)
            setDeleteConfirm(null)
            if (selectedAgent?.id === deleteConfirm) setSelectedAgent(null)
          }}
          onCancel={() => setDeleteConfirm(null)}
        />
      )}
    </div>
  )
}
