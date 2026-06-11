import { useState, useEffect } from 'react'
import {
  User, Building2, Key, Users,
  Plus, Copy, Check, Trash2, CheckCircle,
} from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { formatRelativeTime } from '@/lib/utils'
import { useAuthStore } from '@/stores/authStore'
import { settingsApi } from '@/api/settings'
import type { UserProfile, TenantInfo, Member, ApiKey, ApiKeyCreateResponse } from '@/api/settings'
import { TIMEZONE_OPTIONS } from '@/lib/timezone'

// ─── Shared helpers ───────────────────────────────────────────────────────────

function SectionHeader({ title, description }: { title: string; description: string }) {
  return (
    <div style={{ marginBottom: 24, paddingBottom: 16, borderBottom: '1px solid rgba(255,255,255,0.06)', marginTop: 24 }}>
      <h2 style={{ fontSize: 16, fontWeight: 700, fontFamily: "'Space Grotesk', sans-serif", color: '#F5F7FA', marginBottom: 4 }}>
        {title}
      </h2>
      <p style={{ fontSize: 12, color: '#5C6373' }}>{description}</p>
    </div>
  )
}

function FormField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <label style={{
        display: 'block', fontSize: 9, fontWeight: 700,
        textTransform: 'uppercase', letterSpacing: '1.5px',
        color: '#5C6373', marginBottom: 6,
      }}>
        {label}
      </label>
      {children}
    </div>
  )
}

// ─── Profile Tab ─────────────────────────────────────────────────────────────

function ProfileTab() {
  const setUser    = useAuthStore(s => s.setUser)
  const storeUser  = useAuthStore(s => s.user)

  const [profile,  setProfile]  = useState<UserProfile | null>(null)
  const [fullName, setFullName] = useState('')
  const [timezone, setTimezone] = useState('UTC')
  const [saving,   setSaving]   = useState(false)
  const [saved,    setSaved]    = useState(false)

  useEffect(() => {
    settingsApi.getProfile().then(p => {
      setProfile(p)
      setFullName(p.full_name ?? '')
      setTimezone(p.timezone ?? storeUser?.timezone ?? 'UTC')
    }).catch(console.error)
  }, [])

  const handleSave = async () => {
    setSaving(true)
    try {
      const updated = await settingsApi.updateProfile({ full_name: fullName, timezone })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
      // Update auth store so timezone takes effect immediately
      if (storeUser) {
        setUser({ ...storeUser, full_name: updated.full_name, timezone: updated.timezone ?? 'UTC' })
      }
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{ maxWidth: 480 }}>
      <SectionHeader title="Profile" description="Update your personal information" />

      <FormField label="Email">
        <input
          className="inp"
          style={{ width: '100%', opacity: 0.5, cursor: 'not-allowed' }}
          value={profile?.email ?? ''}
          disabled
          readOnly
        />
      </FormField>

      <FormField label="Display Name">
        <input
          className="inp"
          style={{ width: '100%' }}
          placeholder="Your name"
          value={fullName}
          onChange={e => setFullName(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSave()}
        />
      </FormField>

      <FormField label="Timezone">
        <select
          className="inp"
          style={{ width: '100%' }}
          value={timezone}
          onChange={e => setTimezone(e.target.value)}
        >
          {TIMEZONE_OPTIONS.map(opt => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
        <span style={{ fontSize: 11, color: '#3A4150', marginTop: 4, display: 'block' }}>
          All timestamps in the app will display in this timezone
        </span>
      </FormField>

      <Button variant="primary" loading={saving} onClick={handleSave}>
        {saved ? <><Check size={13} /> Saved</> : 'Save Changes'}
      </Button>
    </div>
  )
}

// ─── Organization Tab ─────────────────────────────────────────────────────────

function OrgTab() {
  const activeTenantId = useAuthStore(s => s.activeTenantId)
  const [tenant, setTenant] = useState<TenantInfo | null>(null)
  const [name,   setName]   = useState('')
  const [saving, setSaving] = useState(false)
  const [saved,  setSaved]  = useState(false)

  useEffect(() => {
    if (!activeTenantId) return
    settingsApi.getTenant(activeTenantId).then(t => {
      setTenant(t)
      setName(t.name ?? '')
    }).catch(console.error)
  }, [activeTenantId])

  const handleSave = async () => {
    if (!activeTenantId) return
    setSaving(true)
    try {
      await settingsApi.updateTenant(activeTenantId, { name })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{ maxWidth: 480 }}>
      <SectionHeader title="Organization" description="Manage your workspace settings" />

      <FormField label="Organization Name">
        <input
          className="inp"
          style={{ width: '100%' }}
          placeholder="Your organization name"
          value={name}
          onChange={e => setName(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSave()}
        />
      </FormField>

      {tenant?.slug && (
        <FormField label="Slug">
          <input
            className="inp"
            style={{ width: '100%', opacity: 0.5, cursor: 'not-allowed' }}
            value={tenant.slug}
            disabled
            readOnly
          />
        </FormField>
      )}

      <Button variant="primary" loading={saving} onClick={handleSave}>
        {saved ? <><Check size={13} /> Saved</> : 'Save Changes'}
      </Button>
    </div>
  )
}

// ─── API Keys Tab ─────────────────────────────────────────────────────────────

function ApiKeysTab() {
  const [keys,       setKeys]       = useState<ApiKey[]>([])
  const [loading,    setLoading]    = useState(true)
  const [loadError,  setLoadError]  = useState<string | null>(null)
  const [creating,   setCreating]   = useState(false)
  const [createError,setCreateError]= useState<string | null>(null)
  const [newKeyName, setNewKeyName] = useState('')
  const [createdKey, setCreatedKey] = useState<ApiKeyCreateResponse | null>(null)
  const [copied,     setCopied]     = useState(false)

  useEffect(() => {
    settingsApi.listApiKeys()
      .then(setKeys)
      .catch((err) => {
        const status = (err as { response?: { status?: number } })?.response?.status
        if (status === 403) {
          setLoadError('You need Owner or Admin role to manage API keys.')
        } else {
          setLoadError('Failed to load API keys. Please try again.')
        }
      })
      .finally(() => setLoading(false))
  }, [])

  const handleCreate = async () => {
    if (!newKeyName.trim()) return
    setCreating(true)
    setCreateError(null)
    try {
      const key = await settingsApi.createApiKey(newKeyName.trim())
      setCreatedKey(key)
      setKeys(prev => [key, ...prev])
      setNewKeyName('')
    } catch (err) {
      const status = (err as { response?: { status?: number } })?.response?.status
      if (status === 403) {
        setCreateError('Insufficient permissions. Owner or Admin role required.')
      } else {
        setCreateError('Failed to create API key. Please try again.')
      }
    } finally {
      setCreating(false)
    }
  }

  const handleRevoke = async (id: string) => {
    try {
      await settingsApi.revokeApiKey(id)
      setKeys(prev => prev.filter(k => k.id !== id))
      if (createdKey?.id === id) setCreatedKey(null)
    } catch {
      // Revoke errors are rare — silently ignore
    }
  }

  const copyKey = (key: string) => {
    navigator.clipboard.writeText(key)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div style={{ maxWidth: 680 }}>
      <SectionHeader
        title="API Keys"
        description="Use API keys to authenticate the NEURASHIELD agent on your devices"
      />

      {/* Load error */}
      {loadError && (
        <div style={{ padding: '10px 14px', marginBottom: 16, borderRadius: 8,
          background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)',
          fontSize: 12, color: '#FCA5A5' }}>
          {loadError}
        </div>
      )}

      {/* Create */}
      <div className="card" style={{ padding: 16, marginBottom: 24 }}>
        <div style={{ fontSize: 11, fontWeight: 600, color: '#B8C0CC', marginBottom: 10 }}>
          Create new API key
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            className="inp"
            style={{ flex: 1 }}
            placeholder="Key name (e.g. Production Server)"
            value={newKeyName}
            onChange={e => { setNewKeyName(e.target.value); setCreateError(null); }}
            onKeyDown={e => e.key === 'Enter' && handleCreate()}
          />
          <Button variant="primary" disabled={!newKeyName.trim()} loading={creating} onClick={handleCreate}>
            <Plus size={13} /> Generate
          </Button>
        </div>
        {createError && (
          <p style={{ margin: '8px 0 0', fontSize: 12, color: '#FCA5A5' }}>{createError}</p>
        )}
      </div>

      {/* Newly created — show once */}
      {createdKey && (
        <div style={{
          padding: 16, marginBottom: 20, borderRadius: 8,
          background: 'rgba(16,185,129,0.06)',
          border: '1px solid rgba(16,185,129,0.2)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
            <CheckCircle size={14} style={{ color: '#10B981' }} />
            <span style={{ fontSize: 12, fontWeight: 600, color: '#10B981' }}>
              Key created — copy it now, it won't be shown again
            </span>
          </div>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '10px 12px', borderRadius: 6,
            background: 'rgba(0,0,0,0.4)',
            border: '1px solid rgba(255,255,255,0.08)',
          }}>
            <code style={{
              flex: 1, fontFamily: "'JetBrains Mono', monospace",
              fontSize: 12, color: '#F5F7FA',
              overflowX: 'auto', whiteSpace: 'nowrap',
            }}>
              {createdKey.raw_key}
            </code>
            <button
              onClick={() => copyKey(createdKey.raw_key)}
              style={{
                display: 'flex', alignItems: 'center', gap: 4,
                padding: '4px 10px', borderRadius: 5,
                fontSize: 11, fontWeight: 600, flexShrink: 0, cursor: 'pointer',
                background: copied ? 'rgba(16,185,129,0.15)' : 'rgba(255,255,255,0.06)',
                border: `1px solid ${copied ? 'rgba(16,185,129,0.3)' : 'rgba(255,255,255,0.1)'}`,
                color: copied ? '#10B981' : '#B8C0CC',
                transition: 'all 120ms',
              }}
            >
              {copied ? <Check size={12} /> : <Copy size={12} />}
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <button
            onClick={() => setCreatedKey(null)}
            style={{ marginTop: 8, fontSize: 11, color: '#5C6373', background: 'none', border: 'none', cursor: 'pointer' }}
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Keys table */}
      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {[1, 2, 3].map(i => <div key={i} className="skel" style={{ height: 52, borderRadius: 8 }} />)}
        </div>
      ) : keys.length === 0 && !createdKey ? (
        <div style={{ textAlign: 'center', padding: '40px 0', color: '#5C6373' }}>
          <Key size={32} style={{ display: 'block', margin: '0 auto 10px', opacity: 0.4 }} />
          <div style={{ fontSize: 13 }}>No API keys yet</div>
        </div>
      ) : keys.length > 0 ? (
        <div className="card" style={{ overflow: 'hidden' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>NAME</th>
                <th style={{ width: 130 }}>KEY PREFIX</th>
                <th style={{ width: 120 }}>CREATED</th>
                <th style={{ width: 120 }}>LAST USED</th>
                <th style={{ width: 50 }}></th>
              </tr>
            </thead>
            <tbody>
              {keys.map(key => (
                <tr key={key.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  <td style={{ padding: '9px 12px' }}>
                    <span style={{ fontSize: 12, fontWeight: 600, color: '#F5F7FA' }}>{key.name}</span>
                  </td>
                  <td style={{ padding: '9px 12px' }}>
                    <code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#8B95A7' }}>
                      {key.key_prefix}••••••••
                    </code>
                  </td>
                  <td style={{ padding: '9px 12px' }}>
                    <span style={{ fontSize: 11, color: '#5C6373' }}>
                      {formatRelativeTime(key.created_at)}
                    </span>
                  </td>
                  <td style={{ padding: '9px 12px' }}>
                    <span style={{ fontSize: 11, color: '#5C6373' }}>
                      {key.last_used_at ? formatRelativeTime(key.last_used_at) : 'Never'}
                    </span>
                  </td>
                  <td style={{ padding: '9px 12px' }}>
                    <Button variant="ghost" size="icon-sm" title="Revoke" onClick={() => handleRevoke(key.id)} style={{ color: '#F87171' }}>
                      <Trash2 size={12} />
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {/* Usage instructions */}
      <div style={{
        marginTop: 24, padding: 16, borderRadius: 8,
        background: 'rgba(59,130,246,0.05)',
        border: '1px solid rgba(59,130,246,0.15)',
      }}>
        <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', color: '#60A5FA', marginBottom: 10 }}>
          How to use
        </div>
        <div style={{ fontSize: 12, color: '#8B95A7', lineHeight: 1.8, fontFamily: "'JetBrains Mono', monospace" }}>
          <div>1. Copy the API key above</div>
          <div>2. Open the agent config file:</div>
          <div style={{ paddingLeft: 16 }}>
            <div><code style={{ color: '#93C5FD' }}>Windows: C:\ProgramData\SOCAnalyst\agent_config.py</code></div>
            <div><code style={{ color: '#93C5FD' }}>Linux &nbsp;: /opt/soc-analyst/agent_config.py</code></div>
          </div>
          <div>3. Set <code style={{ color: '#93C5FD' }}>API_KEY</code> = the copied key</div>
          <div>4. Set <code style={{ color: '#93C5FD' }}>API_ENDPOINT</code> = your backend URL</div>
        </div>
      </div>
    </div>
  )
}

// ─── Members Tab ─────────────────────────────────────────────────────────────

function MembersTab() {
  const activeTenantId = useAuthStore(s => s.activeTenantId)
  const [members, setMembers] = useState<Member[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!activeTenantId) return
    settingsApi.getMembers(activeTenantId)
      .then(setMembers)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [activeTenantId])

  return (
    <div style={{ maxWidth: 600 }}>
      <SectionHeader title="Members" description="People with access to this workspace" />

      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {[1, 2, 3].map(i => <div key={i} className="skel" style={{ height: 52, borderRadius: 8 }} />)}
        </div>
      ) : members.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '40px 0', color: '#5C6373' }}>
          <Users size={32} style={{ display: 'block', margin: '0 auto 10px', opacity: 0.4 }} />
          <div style={{ fontSize: 13 }}>No members found</div>
        </div>
      ) : (
        <div className="card" style={{ overflow: 'hidden' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>MEMBER</th>
                <th style={{ width: 100 }}>ROLE</th>
                <th style={{ width: 110 }}>JOINED</th>
              </tr>
            </thead>
            <tbody>
              {members.map(m => {
                const displayName = m.full_name || m.email || 'Unknown'
                const initial = displayName[0]?.toUpperCase() ?? '?'
                return (
                  <tr key={m.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <td style={{ padding: '9px 12px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <div style={{
                          width: 28, height: 28, borderRadius: '50%',
                          background: 'linear-gradient(135deg, #2563EB, #38BDF8)',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          fontSize: 11, fontWeight: 700, color: '#fff', flexShrink: 0,
                        }}>
                          {initial}
                        </div>
                        <div>
                          <div style={{ fontSize: 12, fontWeight: 600, color: '#F5F7FA' }}>
                            {m.full_name || '—'}
                          </div>
                          <div style={{ fontSize: 11, color: '#5C6373' }}>{m.email}</div>
                        </div>
                      </div>
                    </td>
                    <td style={{ padding: '9px 12px' }}>
                      <span style={{
                        fontSize: 9, fontWeight: 700,
                        textTransform: 'uppercase', letterSpacing: '0.08em',
                        padding: '2px 7px', borderRadius: 4,
                        fontFamily: "'JetBrains Mono', monospace",
                        background: 'rgba(59,130,246,0.1)', color: '#93C5FD',
                      }}>
                        {m.role}
                      </span>
                    </td>
                    <td style={{ padding: '9px 12px' }}>
                      <span style={{ fontSize: 11, color: '#5C6373' }}>
                        {m.created_at ? formatRelativeTime(m.created_at) : '—'}
                      </span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ─── SettingsPage ─────────────────────────────────────────────────────────────

const TABS = [
  { id: 'profile',  label: 'Profile',      icon: User      },
  { id: 'org',      label: 'Organization', icon: Building2 },
  { id: 'api-keys', label: 'API Keys',     icon: Key       },
  { id: 'members',  label: 'Members',      icon: Users     },
] as const

type TabId = typeof TABS[number]['id']

export function SettingsPage() {
  const [activeTab, setActiveTab] = useState<TabId>('api-keys')

  return (
    <div
      className="page-in"
      style={{ display: 'flex', gap: 0, height: 'calc(100vh - 50px - 40px)', overflow: 'hidden' }}
    >
      {/* Left nav */}
      <div style={{
        width: 200, flexShrink: 0,
        borderRight: '1px solid rgba(255,255,255,0.06)',
        paddingTop: 4,
      }}>
        <div style={{
          padding: '0 14px 12px',
          fontSize: 9, fontWeight: 700,
          textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373',
        }}>
          Settings
        </div>
        {TABS.map(tab => {
          const Icon = tab.icon
          const active = activeTab === tab.id
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                display: 'flex', alignItems: 'center', gap: 9,
                width: '100%', padding: '8px 14px',
                fontSize: 13, cursor: 'pointer',
                background: active ? 'rgba(59,130,246,0.08)' : 'transparent',
                borderLeft: `2px solid ${active ? '#3B82F6' : 'transparent'}`,
                border: 'none',
                color: active ? '#93C5FD' : '#8B95A7',
                transition: 'all 120ms', textAlign: 'left',
              }}
            >
              <Icon size={14} style={{ opacity: active ? 0.9 : 0.45, flexShrink: 0 }} />
              {tab.label}
            </button>
          )
        })}
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '0 32px 32px' }}>
        {activeTab === 'profile'  && <ProfileTab  />}
        {activeTab === 'org'      && <OrgTab      />}
        {activeTab === 'api-keys' && <ApiKeysTab  />}
        {activeTab === 'members'  && <MembersTab  />}
      </div>
    </div>
  )
}
