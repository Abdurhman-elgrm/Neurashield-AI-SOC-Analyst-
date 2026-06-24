import { useState, useEffect, useRef } from 'react'
import {
  User, Building2, Key, Users, Bell, Bot,
  Plus, Copy, Check, Trash2, CheckCircle,
  Mail, ChevronDown, ChevronUp, Shield, X, AlertCircle, Lock, Camera, Loader,
  Zap, Ticket, Gauge, BarChart3, BellRing, Monitor,
} from 'lucide-react'
import { NotificationRulesSection } from './NotificationRulesSection'
import { SeverityThresholdsSection } from './SeverityThresholdsSection'
import { QuotaDashboardSection } from './QuotaDashboardSection'
import { TicketingConfigSection } from './TicketingConfigSection'
import { Button } from '@/components/ui/Button'
import { formatRelativeTime } from '@/lib/utils'
import { useAuthStore } from '@/stores/authStore'
import { useTenantStore } from '@/stores/tenantStore'
import { settingsApi } from '@/api/settings'
import type { UserProfile, TenantInfo, Member, ApiKey, ApiKeyCreateResponse, NotificationPreferences } from '@/api/settings'
import { authApi } from '@/api/auth'
import { invitationsApi } from '@/api/invitations'
import type { Invitation } from '@/api/invitations'
import { extractApiError } from '@/lib/utils'
import { toastError, toastSuccess } from '@/lib/toast'
import { TIMEZONE_OPTIONS } from '@/lib/timezone'
import { playbookAutoApi } from '@/api/reports'
import type { AutoPlaybookConfig } from '@/api/reports'

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

// ─── Avatar helpers ───────────────────────────────────────────────────────────

function resizeToDataUrl(file: File, size = 96, quality = 0.82): Promise<string> {
  return new Promise((resolve, reject) => {
    const img = new Image()
    const url = URL.createObjectURL(file)
    img.onload = () => {
      const canvas = document.createElement('canvas')
      canvas.width = size
      canvas.height = size
      const ctx = canvas.getContext('2d')
      if (!ctx) { reject(new Error('Canvas not supported')); return }
      const s = Math.min(img.naturalWidth, img.naturalHeight)
      const sx = (img.naturalWidth - s) / 2
      const sy = (img.naturalHeight - s) / 2
      ctx.drawImage(img, sx, sy, s, s, 0, 0, size, size)
      URL.revokeObjectURL(url)
      resolve(canvas.toDataURL('image/jpeg', quality))
    }
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('Failed to load image')) }
    img.src = url
  })
}

function AvatarEditor({ src, initials, onChange }: {
  src?: string | null; initials: string; onChange: (dataUrl: string) => void
}) {
  const inputRef            = useRef<HTMLInputElement>(null)
  const [preview, setPreview] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [hovered, setHovered] = useState(false)
  const [error,   setError]   = useState<string | null>(null)

  const displaySrc = preview ?? src ?? null

  const handleFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setLoading(true); setError(null)
    try {
      const dataUrl = await resizeToDataUrl(file)
      setPreview(dataUrl)
      onChange(dataUrl)
    } catch {
      setError('Could not process image — try a different file.')
    } finally {
      setLoading(false)
      if (inputRef.current) inputRef.current.value = ''
    }
  }

  return (
    <div>
      <div
        onClick={() => !loading && inputRef.current?.click()}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        title="Click to change profile picture"
        style={{ position: 'relative', display: 'inline-block', cursor: loading ? 'default' : 'pointer', borderRadius: '50%' }}
      >
        {/* Avatar */}
        <div style={{ width: 80, height: 80, borderRadius: '50%', overflow: 'hidden', border: '2px solid rgba(59,130,246,0.3)', flexShrink: 0 }}>
          {displaySrc ? (
            <img
              src={displaySrc}
              alt="Profile"
              style={{ width: '100%', height: '100%', objectFit: 'cover', display: 'block' }}
              onError={e => { (e.target as HTMLImageElement).style.display = 'none' }}
            />
          ) : (
            <div style={{
              width: '100%', height: '100%',
              background: 'rgba(59,130,246,0.15)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 26, fontWeight: 800, color: '#60A5FA',
              fontFamily: "'Space Grotesk', sans-serif",
            }}>
              {initials}
            </div>
          )}
        </div>

        {/* Hover overlay */}
        <div style={{
          position: 'absolute', inset: 0, borderRadius: '50%',
          background: 'rgba(0,0,0,0.55)',
          display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 4,
          opacity: (hovered || loading) ? 1 : 0,
          transition: 'opacity 150ms',
          pointerEvents: 'none',
        }}>
          {loading
            ? <Loader size={18} style={{ color: '#fff', animation: 'spin 1s linear infinite' }} />
            : <>
                <Camera size={16} style={{ color: '#fff' }} />
                <span style={{ fontSize: 9, color: '#fff', fontWeight: 700, letterSpacing: '0.5px' }}>EDIT</span>
              </>
          }
        </div>
      </div>

      {error && (
        <p style={{ marginTop: 6, fontSize: 11, color: '#FCA5A5' }}>{error}</p>
      )}

      <input
        ref={inputRef}
        type="file"
        accept="image/jpeg,image/png,image/webp,image/gif"
        style={{ display: 'none' }}
        onChange={handleFile}
      />
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
  const [jobTitle, setJobTitle] = useState('')
  const [bio,      setBio]      = useState('')
  const [avatarUrl, setAvatarUrl] = useState('')
  const [saving,   setSaving]   = useState(false)
  const [saved,    setSaved]    = useState(false)
  const [verifySent, setVerifySent] = useState(false)
  const [verifyLoading, setVerifyLoading] = useState(false)

  // Change password
  const [currentPw, setCurrentPw] = useState('')
  const [newPw,     setNewPw]     = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [pwLoading, setPwLoading] = useState(false)
  const [pwMsg,     setPwMsg]     = useState<{ type: 'ok' | 'err'; text: string } | null>(null)

  useEffect(() => {
    settingsApi.getProfile().then(p => {
      setProfile(p)
      setFullName(p.full_name ?? '')
      setTimezone(p.timezone ?? storeUser?.timezone ?? 'UTC')
      setJobTitle(p.job_title ?? '')
      setBio(p.bio ?? '')
      setAvatarUrl(p.avatar_url ?? '')
    }).catch(e => toastError(extractApiError(e), 'Failed to load profile'))
  }, [])

  const handleSave = async () => {
    setSaving(true)
    try {
      const updated = await settingsApi.updateProfile({
        full_name: fullName,
        timezone,
        job_title: jobTitle || null,
        bio: bio || null,
        avatar_url: avatarUrl || null,
      })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
      if (storeUser) {
        setUser({ ...storeUser, full_name: updated.full_name, timezone: updated.timezone ?? 'UTC', avatar_url: updated.avatar_url ?? null })
      }
    } finally {
      setSaving(false)
    }
  }

  async function resendVerification() {
    if (!profile?.email) return
    setVerifyLoading(true)
    try {
      await authApi.resendVerification(profile.email)
      setVerifySent(true)
    } finally {
      setVerifyLoading(false)
    }
  }

  async function handlePasswordChange(e: React.FormEvent) {
    e.preventDefault()
    if (newPw !== confirmPw) { setPwMsg({ type: 'err', text: 'Passwords do not match' }); return }
    setPwLoading(true); setPwMsg(null)
    try {
      await authApi.changePassword(currentPw, newPw)
      setCurrentPw(''); setNewPw(''); setConfirmPw('')
      setPwMsg({ type: 'ok', text: 'Password changed successfully.' })
      setTimeout(() => setPwMsg(null), 4000)
    } catch (err) {
      setPwMsg({ type: 'err', text: extractApiError(err) })
    } finally {
      setPwLoading(false)
    }
  }

  const initials = profile?.full_name?.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2) ?? '?'
  const avatarSrc = profile?.avatar_url || profile?.gravatar_url

  return (
    <div style={{ maxWidth: 520 }}>
      <SectionHeader title="Profile" description="Update your personal information" />

      {/* Avatar + identity */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20,
        padding: '14px 16px', borderRadius: 8,
        background: '#111111', border: '1px solid rgba(255,255,255,0.06)',
      }}>
        <AvatarEditor
          src={avatarUrl || avatarSrc}
          initials={initials}
          onChange={url => setAvatarUrl(url)}
        />
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: '#F5F7FA' }}>{profile?.full_name}</div>
          <div style={{ fontSize: 11, color: '#8B95A7', marginTop: 2 }}>{profile?.email}</div>
          {profile?.job_title && (
            <div style={{ fontSize: 10, color: '#5C6373', marginTop: 1 }}>{profile.job_title}</div>
          )}
          <div style={{ fontSize: 10, color: '#3A4150', marginTop: 4 }}>Click avatar to upload a new photo</div>
        </div>
        <div>
          {profile?.email_verified ? (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 5,
              fontSize: 10, color: '#10B981',
              padding: '3px 8px', borderRadius: 5,
              background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.2)',
            }}>
              <CheckCircle size={11} />
              Verified
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
              <div style={{
                display: 'flex', alignItems: 'center', gap: 5,
                fontSize: 10, color: '#F59E0B',
                padding: '3px 8px', borderRadius: 5,
                background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)',
              }}>
                <AlertCircle size={11} />
                Not verified
              </div>
              {!verifySent ? (
                <button
                  onClick={resendVerification}
                  disabled={verifyLoading}
                  style={{ fontSize: 10, color: '#60A5FA', background: 'none', border: 'none', cursor: 'pointer', textDecoration: 'underline' }}
                >
                  {verifyLoading ? 'Sending…' : 'Resend email'}
                </button>
              ) : (
                <span style={{ fontSize: 10, color: '#10B981' }}>Email sent!</span>
              )}
            </div>
          )}
        </div>
      </div>

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

      <FormField label="Job Title">
        <input
          className="inp"
          style={{ width: '100%' }}
          placeholder="e.g. Senior SOC Analyst"
          value={jobTitle}
          onChange={e => setJobTitle(e.target.value)}
        />
      </FormField>

      <FormField label="Bio">
        <textarea
          className="inp"
          style={{ width: '100%', resize: 'vertical', minHeight: 64 }}
          placeholder="A short bio about yourself..."
          value={bio}
          onChange={e => setBio(e.target.value)}
          maxLength={2000}
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

      {/* ── Change Password ────────────────────────────────────────────────── */}
      <SectionHeader title="Change Password" description="Update your account password" />

      <form onSubmit={handlePasswordChange}>
        <FormField label="Current Password">
          <div style={{ position: 'relative' }}>
            <Lock size={12} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: '#5C6373', pointerEvents: 'none' }} />
            <input
              type="password"
              className="inp"
              style={{ width: '100%', paddingLeft: 28 }}
              placeholder="Your current password"
              value={currentPw}
              onChange={e => setCurrentPw(e.target.value)}
              required
              disabled={pwLoading}
              autoComplete="current-password"
            />
          </div>
        </FormField>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <FormField label="New Password">
            <input
              type="password"
              className="inp"
              style={{ width: '100%' }}
              placeholder="Min. 8 characters"
              minLength={8}
              value={newPw}
              onChange={e => setNewPw(e.target.value)}
              required
              disabled={pwLoading}
              autoComplete="new-password"
            />
          </FormField>
          <FormField label="Confirm New Password">
            <input
              type="password"
              className="inp"
              style={{
                width: '100%',
                borderColor: confirmPw && confirmPw !== newPw ? 'rgba(248,113,113,0.5)' : undefined,
              }}
              placeholder="Repeat new password"
              value={confirmPw}
              onChange={e => setConfirmPw(e.target.value)}
              required
              disabled={pwLoading}
              autoComplete="new-password"
            />
          </FormField>
        </div>

        {pwMsg && (
          <div style={{
            marginBottom: 12, padding: '8px 12px', borderRadius: 6, fontSize: 12,
            background: pwMsg.type === 'ok' ? 'rgba(16,185,129,0.08)' : 'rgba(248,113,113,0.08)',
            border: `1px solid ${pwMsg.type === 'ok' ? 'rgba(16,185,129,0.2)' : 'rgba(248,113,113,0.2)'}`,
            color: pwMsg.type === 'ok' ? '#10B981' : '#F87171',
          }}>
            {pwMsg.text}
          </div>
        )}

        <Button type="submit" variant="primary" loading={pwLoading}>
          Update Password
        </Button>
      </form>
    </div>
  )
}

// ─── Organization Tab ─────────────────────────────────────────────────────────

const RETENTION_OPTIONS = [
  { label: '7 days',    value: 7 },
  { label: '30 days',   value: 30 },
  { label: '60 days',   value: 60 },
  { label: '90 days',   value: 90 },
  { label: '180 days',  value: 180 },
  { label: '1 year',    value: 365 },
  { label: '2 years',   value: 730 },
  { label: '10 years',  value: 3650 },
]

function OrgTab() {
  const activeTenantId   = useAuthStore(s => s.activeTenantId)
  const memberRole       = useTenantStore(s => s.memberRole)
  const isOwner          = memberRole === 'owner'

  const [tenant, setTenant] = useState<TenantInfo | null>(null)
  const [name,          setName]          = useState('')
  const [timezone,      setTimezone]      = useState('UTC')
  const [eventRetention,setEventRetention]= useState(90)
  const [alertRetention,setAlertRetention]= useState(365)
  const [logoUrl,       setLogoUrl]       = useState<string | null>(null)
  const [saving,   setSaving]   = useState(false)
  const [saved,    setSaved]    = useState(false)
  const [saveErr,  setSaveErr]  = useState<string | null>(null)

  // Logo upload state
  const logoInputRef    = useRef<HTMLInputElement>(null)
  const [logoUploading, setLogoUploading] = useState(false)

  // Danger zone state
  const [showDanger,   setShowDanger]   = useState(false)
  const [deleteConfirm,setDeleteConfirm]= useState('')
  const [deleting,     setDeleting]     = useState(false)
  const [deleteErr,    setDeleteErr]    = useState<string | null>(null)

  useEffect(() => {
    if (!activeTenantId) return
    settingsApi.getTenant(activeTenantId).then(t => {
      setTenant(t)
      setName(t.name ?? '')
      setTimezone(t.timezone ?? 'UTC')
      setEventRetention(t.event_retention_days ?? 90)
      setAlertRetention(t.alert_retention_days ?? 365)
      setLogoUrl(t.logo_url ?? null)
    }).catch(e => toastError(extractApiError(e), 'Failed to load organization'))
  }, [activeTenantId])

  const handleSave = async () => {
    if (!activeTenantId) return
    setSaving(true)
    setSaveErr(null)
    try {
      const updated = await settingsApi.updateTenant(activeTenantId, {
        name,
        timezone,
        logo_url: logoUrl,
        event_retention_days: eventRetention,
        alert_retention_days: alertRetention,
      })
      setTenant(updated)
      setSaved(true)
      setTimeout(() => setSaved(false), 2500)
    } catch (err) {
      setSaveErr(extractApiError(err))
    } finally {
      setSaving(false)
    }
  }

  // Convert uploaded image to base64 data-URL and store as logo_url
  const handleLogoFile = (file: File) => {
    if (!file.type.startsWith('image/')) return
    setLogoUploading(true)
    const reader = new FileReader()
    reader.onload = (e) => {
      setLogoUrl(e.target?.result as string ?? null)
      setLogoUploading(false)
    }
    reader.readAsDataURL(file)
  }

  const handleDeleteWorkspace = async () => {
    if (!activeTenantId || !isOwner) return
    if (deleteConfirm !== tenant?.slug) return
    setDeleting(true)
    setDeleteErr(null)
    try {
      await settingsApi.deleteTenant(activeTenantId)
      window.location.href = '/setup'
    } catch (err) {
      setDeleteErr(extractApiError(err))
      setDeleting(false)
    }
  }

  return (
    <div style={{ maxWidth: 600 }}>
      <SectionHeader title="Organization" description="Manage your workspace identity, data policies, and settings" />

      {/* ── Workspace Identity ─────────────────────────────────────────────── */}
      <div style={{
        background: 'rgba(255,255,255,0.015)', border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: 10, padding: '20px 24px', marginBottom: 20,
      }}>
        <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 16 }}>
          Workspace Identity
        </div>

        {/* Logo row */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20 }}>
          <div
            onClick={() => !logoUploading && logoInputRef.current?.click()}
            style={{
              width: 64, height: 64, borderRadius: 12, flexShrink: 0,
              background: logoUrl ? 'transparent' : 'rgba(59,130,246,0.08)',
              border: `1px solid ${logoUrl ? 'rgba(255,255,255,0.1)' : 'rgba(59,130,246,0.25)'}`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              cursor: 'pointer', overflow: 'hidden', position: 'relative',
            }}
          >
            {logoUploading ? (
              <Loader size={18} style={{ color: '#60A5FA', animation: 'spin 1s linear infinite' }} />
            ) : logoUrl ? (
              <img src={logoUrl} alt="logo" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
            ) : (
              <Building2 size={22} style={{ color: '#3B82F6', opacity: 0.5 }} />
            )}
          </div>
          <div>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#B8C0CC', marginBottom: 4 }}>
              Workspace Logo
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                onClick={() => logoInputRef.current?.click()}
                style={{
                  fontSize: 11, padding: '4px 12px', borderRadius: 6,
                  background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
                  color: '#B8C0CC', cursor: 'pointer',
                }}
              >
                <Camera size={11} style={{ display: 'inline', marginRight: 5 }} />
                Upload
              </button>
              {logoUrl && (
                <button
                  onClick={() => setLogoUrl(null)}
                  style={{
                    fontSize: 11, padding: '4px 12px', borderRadius: 6,
                    background: 'rgba(239,68,68,0.07)', border: '1px solid rgba(239,68,68,0.2)',
                    color: '#FCA5A5', cursor: 'pointer',
                  }}
                >
                  Remove
                </button>
              )}
            </div>
            <div style={{ fontSize: 10, color: '#3A4150', marginTop: 4 }}>
              PNG or SVG recommended. Max 2MB. Stored as base64.
            </div>
          </div>
          <input
            ref={logoInputRef}
            type="file"
            accept="image/*"
            style={{ display: 'none' }}
            onChange={e => { const f = e.target.files?.[0]; if (f) handleLogoFile(f) }}
          />
        </div>

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
              disabled readOnly
            />
            <div style={{ fontSize: 10, color: '#3A4150', marginTop: 4 }}>
              Used in API paths and sharing links. Cannot be changed after creation.
            </div>
          </FormField>
        )}

        <FormField label="Workspace Timezone">
          <select
            className="inp"
            style={{ width: '100%' }}
            value={timezone}
            onChange={e => setTimezone(e.target.value)}
          >
            {TIMEZONE_OPTIONS.map(tz => (
              <option key={tz.value} value={tz.value}>{tz.label}</option>
            ))}
          </select>
          <div style={{ fontSize: 10, color: '#3A4150', marginTop: 4 }}>
            Used for report timestamps, scheduled jobs, and alert display times.
          </div>
        </FormField>
      </div>

      {/* ── Data Retention Policies ──────────────────────────────────────────── */}
      <div style={{
        background: 'rgba(255,255,255,0.015)', border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: 10, padding: '20px 24px', marginBottom: 20,
      }}>
        <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 4 }}>
          Data Retention Policies
        </div>
        <div style={{ fontSize: 11, color: '#3A4150', marginBottom: 16 }}>
          Raw events and alerts older than these thresholds are automatically purged. Changes take effect at the next nightly purge window.
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          <FormField label="Raw Event Retention">
            <select
              className="inp"
              style={{ width: '100%' }}
              value={eventRetention}
              onChange={e => setEventRetention(Number(e.target.value))}
            >
              {RETENTION_OPTIONS.map(o => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </FormField>
          <FormField label="Alert Retention">
            <select
              className="inp"
              style={{ width: '100%' }}
              value={alertRetention}
              onChange={e => setAlertRetention(Number(e.target.value))}
            >
              {RETENTION_OPTIONS.map(o => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </FormField>
        </div>

        <div style={{
          display: 'flex', alignItems: 'center', gap: 8,
          padding: '10px 14px', borderRadius: 8, marginTop: 8,
          background: 'rgba(251,191,36,0.05)', border: '1px solid rgba(251,191,36,0.15)',
          fontSize: 11, color: '#FCD34D',
        }}>
          <AlertCircle size={12} />
          Shortening retention will permanently delete historical data beyond the new threshold.
        </div>
      </div>

      {/* Save */}
      {saveErr && (
        <div style={{ padding: '10px 14px', marginBottom: 12, borderRadius: 8,
          background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)',
          fontSize: 12, color: '#FCA5A5' }}>
          {saveErr}
        </div>
      )}
      <Button variant="primary" loading={saving} onClick={handleSave}>
        {saved ? <><Check size={13} /> Saved</> : 'Save Changes'}
      </Button>

      {/* ── Danger Zone ─────────────────────────────────────────────────────── */}
      {isOwner && (
        <div style={{
          marginTop: 40, borderRadius: 10,
          border: '1px solid rgba(239,68,68,0.25)',
          background: 'rgba(239,68,68,0.03)',
          overflow: 'hidden',
        }}>
          <button
            onClick={() => setShowDanger(v => !v)}
            style={{
              display: 'flex', alignItems: 'center', gap: 8,
              width: '100%', padding: '14px 20px',
              background: 'none', border: 'none', cursor: 'pointer',
              color: '#F87171', fontSize: 12, fontWeight: 700,
            }}
          >
            <AlertCircle size={14} />
            Danger Zone
            {showDanger
              ? <ChevronUp size={13} style={{ marginLeft: 'auto' }} />
              : <ChevronDown size={13} style={{ marginLeft: 'auto' }} />}
          </button>

          {showDanger && (
            <div style={{ padding: '0 20px 20px', borderTop: '1px solid rgba(239,68,68,0.15)' }}>
              <div style={{ fontSize: 12, color: '#8B95A7', margin: '14px 0 16px' }}>
                Deleting this workspace is permanent and irreversible. All agents, alerts, investigations,
                events, and members will be permanently removed.
              </div>

              <div style={{ fontSize: 11, color: '#F87171', marginBottom: 8, fontWeight: 600 }}>
                Type <code style={{ fontFamily: "'JetBrains Mono', monospace", background: 'rgba(239,68,68,0.1)', padding: '1px 6px', borderRadius: 4 }}>{tenant?.slug}</code> to confirm
              </div>
              <input
                className="inp"
                style={{ width: '100%', marginBottom: 12, borderColor: 'rgba(239,68,68,0.3)' }}
                placeholder={tenant?.slug ?? ''}
                value={deleteConfirm}
                onChange={e => { setDeleteConfirm(e.target.value); setDeleteErr(null) }}
              />

              {deleteErr && (
                <div style={{ fontSize: 12, color: '#FCA5A5', marginBottom: 10 }}>{deleteErr}</div>
              )}

              <Button
                variant="danger"
                disabled={deleteConfirm !== tenant?.slug || deleting}
                loading={deleting}
                onClick={handleDeleteWorkspace}
              >
                <Trash2 size={13} />
                Permanently Delete Workspace
              </Button>
            </div>
          )}
        </div>
      )}
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
      .catch((err) => setLoadError(extractApiError(err)))
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
      setCreateError(extractApiError(err))
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

// ─── Members Tab constants ────────────────────────────────────────────────────

const PERMISSION_GROUPS: Record<string, string[]> = {
  'Alerts':          ['alerts:read', 'alerts:update', 'alerts:delete'],
  'Events':          ['events:read', 'events:export'],
  'Agents':          ['agents:read', 'agents:manage', 'agents:view_token'],
  'Detection Rules': ['rules:read', 'rules:manage'],
  'Team':            ['members:read', 'members:manage', 'invitations:manage'],
  'Tenant':          ['tenant:settings', 'tenant:delete'],
  'Audit':           ['audit:read'],
  'Investigations':  ['investigations:read', 'investigations:update', 'investigations:manage', 'hunt:query'],
}

const VIEWER_PERMS  = new Set(['alerts:read', 'events:read', 'agents:read', 'rules:read', 'members:read'])
const ANALYST_PERMS = new Set([...VIEWER_PERMS, 'alerts:update', 'events:export', 'investigations:read', 'investigations:update', 'hunt:query'])
const ADMIN_PERMS   = new Set([...ANALYST_PERMS, 'alerts:delete', 'agents:manage', 'agents:view_token', 'rules:manage', 'members:manage', 'invitations:manage', 'tenant:settings', 'audit:read', 'investigations:manage'])
const OWNER_PERMS   = new Set([...ADMIN_PERMS, 'tenant:delete'])

function getRolePerms(role: string): Set<string> {
  if (role === 'owner')   return OWNER_PERMS
  if (role === 'admin')   return ADMIN_PERMS
  if (role === 'analyst') return ANALYST_PERMS
  return VIEWER_PERMS
}

const ROLE_COLORS: Record<string, { bg: string; color: string }> = {
  owner:   { bg: 'rgba(168,85,247,0.1)',  color: '#C084FC' },
  admin:   { bg: 'rgba(59,130,246,0.1)',  color: '#93C5FD' },
  analyst: { bg: 'rgba(16,185,129,0.1)',  color: '#6EE7B7' },
  viewer:  { bg: 'rgba(156,163,175,0.1)', color: '#9CA3AF' },
}

// ─── Permission Editor ────────────────────────────────────────────────────────

function PermissionEditor({ member, tenantId, onSaved }: {
  member: Member
  tenantId: string
  onSaved: (userId: string, grant: string[], revoke: string[]) => void
}) {
  const rolePerms = getRolePerms(member.role)
  const [grant,   setGrant]   = useState<string[]>(member.custom_permissions?.grant  ?? [])
  const [revoke,  setRevoke]  = useState<string[]>(member.custom_permissions?.revoke ?? [])
  const [saving,  setSaving]  = useState(false)
  const [saveErr, setSaveErr] = useState<string | null>(null)

  const toggle = (perm: string) => {
    const inRole    = rolePerms.has(perm)
    const isGranted = grant.includes(perm)
    const isRevoked = revoke.includes(perm)

    if (inRole) {
      // Currently active (from role): add to revoke to disable
      // Currently revoked: remove from revoke to re-enable
      setRevoke(isRevoked ? revoke.filter(p => p !== perm) : [...revoke, perm])
    } else {
      // Not in role: add to grant to enable, remove from grant to disable
      setGrant(isGranted ? grant.filter(p => p !== perm) : [...grant, perm])
    }
  }

  const handleSave = async () => {
    setSaving(true)
    setSaveErr(null)
    try {
      await settingsApi.updateMemberPermissions(tenantId, member.user_id, grant, revoke)
      onSaved(member.user_id, grant, revoke)
    } catch (err) {
      setSaveErr(extractApiError(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{ padding: '12px 16px 16px', background: 'rgba(0,0,0,0.3)', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
      <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 6 }}>
        <Shield size={11} />
        Permission Overrides
        <span style={{ fontSize: 9, color: '#3A4150', fontWeight: 400, textTransform: 'none', letterSpacing: 0 }}>
          (role: {member.role})
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 16 }}>
        {Object.entries(PERMISSION_GROUPS).map(([group, perms]) => (
          <div key={group}>
            <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', color: '#5C6373', marginBottom: 8 }}>
              {group}
            </div>
            {perms.map(perm => {
              const inRole    = rolePerms.has(perm)
              const isGranted = grant.includes(perm)
              const isRevoked = revoke.includes(perm)
              const isActive  = inRole ? !isRevoked : isGranted
              const isCustom  = (!inRole && isGranted) || (inRole && isRevoked)

              return (
                <label
                  key={perm}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '4px 0', cursor: member.role === 'owner' ? 'default' : 'pointer',
                    opacity: member.role === 'owner' ? 0.4 : 1,
                  }}
                >
                  {/* Toggle */}
                  <div
                    onClick={() => member.role !== 'owner' && toggle(perm)}
                    style={{
                      width: 28, height: 16, borderRadius: 8, flexShrink: 0,
                      background: isActive
                        ? (isCustom ? 'rgba(99,102,241,0.7)' : 'rgba(16,185,129,0.5)')
                        : 'rgba(255,255,255,0.1)',
                      border: isCustom ? '1px solid rgba(99,102,241,0.5)' : '1px solid rgba(255,255,255,0.1)',
                      position: 'relative', transition: 'all 150ms', cursor: 'inherit',
                    }}
                  >
                    <div style={{
                      position: 'absolute', top: 2, left: isActive ? 12 : 2,
                      width: 10, height: 10, borderRadius: '50%',
                      background: isActive ? '#fff' : 'rgba(255,255,255,0.4)',
                      transition: 'left 150ms',
                    }} />
                  </div>
                  <span style={{
                    fontSize: 10,
                    fontFamily: "'JetBrains Mono', monospace",
                    color: isActive ? '#B8C0CC' : '#3A4150',
                  }}>
                    {perm}
                  </span>
                  {isCustom && (
                    <span style={{
                      fontSize: 8, padding: '1px 4px', borderRadius: 3,
                      background: isGranted && !inRole ? 'rgba(99,102,241,0.15)' : 'rgba(239,68,68,0.12)',
                      color: isGranted && !inRole ? '#818CF8' : '#F87171',
                      fontWeight: 700,
                    }}>
                      {isGranted && !inRole ? '+' : '−'}
                    </span>
                  )}
                </label>
              )
            })}
          </div>
        ))}
      </div>

      <div style={{ marginTop: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
        <Button variant="primary" size="sm" loading={saving} onClick={handleSave} disabled={member.role === 'owner'}>
          Save Permissions
        </Button>
        {saveErr && <span style={{ fontSize: 11, color: '#FCA5A5' }}>{saveErr}</span>}
      </div>
    </div>
  )
}

// ─── Invite Modal ─────────────────────────────────────────────────────────────

function InviteModal({ onClose, onSent }: { onClose: () => void; onSent: (inv: Invitation) => void }) {
  const [email,   setEmail]   = useState('')
  const [role,    setRole]    = useState('analyst')
  const [sending, setSending] = useState(false)
  const [error,   setError]   = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  const handleSend = async () => {
    if (!email.trim()) return
    setSending(true)
    setError(null)
    try {
      const resp = await invitationsApi.send(email.trim().toLowerCase(), role)
      const inv  = resp.data.data
      setSuccess(`Invitation sent to ${email}`)
      onSent(inv)
      setTimeout(onClose, 1500)
    } catch (err) {
      setError(extractApiError(err))
    } finally {
      setSending(false)
    }
  }

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 49 }}
      />
      {/* Panel */}
      <div style={{
        position: 'fixed', top: '50%', left: '50%',
        transform: 'translate(-50%, -50%)',
        width: 400, zIndex: 50,
        background: '#0D0D0D',
        border: '1px solid rgba(59,130,246,0.2)',
        borderRadius: 12,
        boxShadow: '0 0 40px rgba(59,130,246,0.1)',
        padding: 24,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700, fontFamily: "'Space Grotesk', sans-serif", color: '#F5F7FA' }}>
              Invite Member
            </div>
            <div style={{ fontSize: 12, color: '#5C6373', marginTop: 2 }}>
              They'll receive an email with instructions
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#5C6373', cursor: 'pointer' }}>
            <X size={16} />
          </button>
        </div>

        {success ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '12px 14px', borderRadius: 8, background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.2)', color: '#6EE7B7', fontSize: 13 }}>
            <CheckCircle size={15} />
            {success}
          </div>
        ) : (
          <>
            <FormField label="Email Address">
              <input
                className="inp"
                style={{ width: '100%' }}
                type="email"
                placeholder="colleague@company.com"
                value={email}
                onChange={e => { setEmail(e.target.value); setError(null) }}
                onKeyDown={e => e.key === 'Enter' && handleSend()}
                autoFocus
              />
            </FormField>
            <FormField label="Role">
              <select className="inp" style={{ width: '100%' }} value={role} onChange={e => setRole(e.target.value)}>
                <option value="analyst">Analyst</option>
                <option value="viewer">Viewer</option>
                <option value="admin">Admin</option>
              </select>
            </FormField>

            {error && (
              <div style={{ marginBottom: 12, padding: '8px 12px', borderRadius: 6, background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', fontSize: 12, color: '#FCA5A5' }}>
                {error}
              </div>
            )}

            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <Button variant="ghost" onClick={onClose}>Cancel</Button>
              <Button variant="primary" loading={sending} disabled={!email.trim()} onClick={handleSend}>
                <Mail size={13} />
                Send Invite
              </Button>
            </div>
          </>
        )}
      </div>
    </>
  )
}

// ─── Members Tab ─────────────────────────────────────────────────────────────

function MembersTab() {
  const activeTenantId = useAuthStore(s => s.activeTenantId)
  const currentUserId  = useAuthStore(s => s.user?.id)
  const memberRole     = useTenantStore(s => s.memberRole)
  const hasRole        = useTenantStore(s => s.hasRole)
  const canInvite      = hasRole('admin')

  const [members,      setMembers]      = useState<Member[]>([])
  const [invitations,  setInvitations]  = useState<Invitation[]>([])
  const [loading,      setLoading]      = useState(true)
  const [showInvite,   setShowInvite]   = useState(false)
  const [expandedPerm, setExpandedPerm] = useState<string | null>(null)
  const [roleChanging, setRoleChanging] = useState<string | null>(null)

  const ROLE_HIERARCHY_FRONTEND: Record<string, number> = {
    viewer: 0, analyst: 1, admin: 2, owner: 3
  }
  const myLevel = ROLE_HIERARCHY_FRONTEND[memberRole ?? 'viewer'] ?? 0

  const handleRoleChange = async (userId: string, newRole: string) => {
    if (!activeTenantId) return
    setRoleChanging(userId)
    try {
      await settingsApi.updateMemberRole(activeTenantId, userId, newRole)
      setMembers(prev => prev.map(m => m.user_id === userId ? { ...m, role: newRole } : m))
    } catch (err) {
      alert(extractApiError(err))
    } finally {
      setRoleChanging(null)
    }
  }

  useEffect(() => {
    if (!activeTenantId) return
    Promise.all([
      settingsApi.getMembers(activeTenantId),
      invitationsApi.list().then(r => r.data.data ?? []),
    ]).then(([m, inv]) => {
      setMembers(m)
      setInvitations(inv)
    }).catch(e => toastError(extractApiError(e), 'Failed to load members')).finally(() => setLoading(false))
  }, [activeTenantId])

  const handleRevoke = async (invId: string) => {
    try {
      await invitationsApi.revoke(invId)
      setInvitations(prev => prev.filter(i => i.id !== invId))
    } catch (e) { toastError(extractApiError(e), 'Failed to revoke invitation') }
  }

  const handlePermSaved = (userId: string, grant: string[], revoke: string[]) => {
    setMembers(prev => prev.map(m =>
      m.user_id === userId
        ? { ...m, custom_permissions: { grant, revoke } }
        : m
    ))
    setExpandedPerm(null)
  }

  const getRoleBadge = (role: string) => {
    const c = ROLE_COLORS[role] ?? ROLE_COLORS.viewer
    return (
      <span style={{
        fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em',
        padding: '2px 7px', borderRadius: 4, fontFamily: "'JetBrains Mono', monospace",
        background: c.bg, color: c.color,
      }}>
        {role}
      </span>
    )
  }

  return (
    <div style={{ maxWidth: 700 }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        marginBottom: 24, paddingBottom: 16, borderBottom: '1px solid rgba(255,255,255,0.06)', marginTop: 24,
      }}>
        <div>
          <h2 style={{ fontSize: 16, fontWeight: 700, fontFamily: "'Space Grotesk', sans-serif", color: '#F5F7FA', marginBottom: 4 }}>
            Members
          </h2>
          <p style={{ fontSize: 12, color: '#5C6373' }}>Manage team access and permissions</p>
        </div>
        {canInvite && (
          <Button variant="primary" size="sm" onClick={() => setShowInvite(true)}>
            <Plus size={13} />
            Invite Member
          </Button>
        )}
      </div>

      {showInvite && (
        <InviteModal
          onClose={() => setShowInvite(false)}
          onSent={inv => setInvitations(prev => [inv, ...prev])}
        />
      )}

      {/* Pending invitations */}
      {invitations.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 10 }}>
            Pending Invitations
          </div>
          <div className="card" style={{ overflow: 'hidden' }}>
            {invitations.map((inv, i) => (
              <div
                key={inv.id}
                style={{
                  display: 'flex', alignItems: 'center', gap: 12, padding: '10px 14px',
                  borderBottom: i < invitations.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none',
                }}
              >
                <Mail size={13} style={{ color: '#5C6373', flexShrink: 0 }} />
                <span style={{ flex: 1, fontSize: 12, color: '#B8C0CC' }}>{inv.email}</span>
                {getRoleBadge(inv.role)}
                <span style={{ fontSize: 10, color: '#5C6373' }}>
                  expires {formatRelativeTime(inv.expires_at)}
                </span>
                <Button variant="ghost" size="icon-sm" title="Revoke" onClick={() => handleRevoke(inv.id)} style={{ color: '#F87171' }}>
                  <X size={12} />
                </Button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Members table */}
      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {[1, 2, 3].map(i => <div key={i} className="skel" style={{ height: 54, borderRadius: 8 }} />)}
        </div>
      ) : members.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '40px 0', color: '#5C6373' }}>
          <Users size={32} style={{ display: 'block', margin: '0 auto 10px', opacity: 0.4 }} />
          <div style={{ fontSize: 13 }}>No members found</div>
        </div>
      ) : (
        <div className="card" style={{ overflow: 'hidden' }}>
          {members.map((m, i) => {
            const displayName = m.full_name || m.email || 'Unknown'
            const initial = displayName[0]?.toUpperCase() ?? '?'
            const isExpanded = expandedPerm === m.user_id
            const hasCustom = (m.custom_permissions?.grant?.length ?? 0) + (m.custom_permissions?.revoke?.length ?? 0) > 0

            return (
              <div key={m.id} style={{ borderBottom: i < members.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none' }}>
                {/* Row */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 0, padding: '10px 14px' }}>
                  {/* Avatar + name */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
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
                      <div style={{ fontSize: 10, color: '#5C6373' }}>{m.email}</div>
                    </div>
                  </div>

                  {/* Role — dropdown if actor can manage this member's role */}
                  <div style={{ marginRight: 16 }}>
                    {canInvite && m.user_id !== currentUserId && (ROLE_HIERARCHY_FRONTEND[m.role] ?? 0) < myLevel ? (
                      <select
                        value={m.role}
                        disabled={roleChanging === m.user_id}
                        onChange={e => handleRoleChange(m.user_id, e.target.value)}
                        style={{
                          fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
                          padding: '2px 20px 2px 7px', borderRadius: 4,
                          fontFamily: "'JetBrains Mono', monospace",
                          background: ROLE_COLORS[m.role]?.bg ?? 'rgba(255,255,255,0.06)',
                          color: ROLE_COLORS[m.role]?.color ?? '#B8C0CC',
                          border: `1px solid ${ROLE_COLORS[m.role]?.color ?? '#5C6373'}30`,
                          cursor: 'pointer', appearance: 'none',
                          backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='10' viewBox='0 0 24 24' fill='none' stroke='%235C6373' stroke-width='2'%3E%3Cpolyline points='6 9 12 15 18 9'/%3E%3C/svg%3E")`,
                          backgroundRepeat: 'no-repeat',
                          backgroundPosition: 'right 4px center',
                        }}
                      >
                        {(['viewer', 'analyst', 'admin'] as const)
                          .filter(r => (ROLE_HIERARCHY_FRONTEND[r] ?? 0) < myLevel)
                          .map(r => (
                            <option key={r} value={r}>{r}</option>
                          ))
                        }
                      </select>
                    ) : (
                      getRoleBadge(m.role)
                    )}
                  </div>

                  {/* Custom perms indicator */}
                  {hasCustom && (
                    <div style={{
                      marginRight: 10, fontSize: 9, padding: '1px 6px', borderRadius: 3,
                      background: 'rgba(99,102,241,0.12)', color: '#818CF8',
                      border: '1px solid rgba(99,102,241,0.2)', fontWeight: 600,
                    }}>
                      CUSTOM
                    </div>
                  )}

                  {/* Joined */}
                  <span style={{ fontSize: 10, color: '#5C6373', marginRight: 14, minWidth: 80, textAlign: 'right' }}>
                    {m.created_at ? formatRelativeTime(m.created_at) : '—'}
                  </span>

                  {/* Edit permissions button — admins only */}
                  {canInvite && <button
                    onClick={() => setExpandedPerm(isExpanded ? null : m.user_id)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 4,
                      padding: '4px 8px', borderRadius: 5, fontSize: 10, cursor: 'pointer',
                      background: isExpanded ? 'rgba(99,102,241,0.15)' : 'rgba(255,255,255,0.04)',
                      border: `1px solid ${isExpanded ? 'rgba(99,102,241,0.3)' : 'rgba(255,255,255,0.08)'}`,
                      color: isExpanded ? '#818CF8' : '#5C6373',
                      fontWeight: 600, transition: 'all 120ms',
                    }}
                  >
                    <Shield size={11} />
                    Permissions
                    {isExpanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
                  </button>}
                </div>

                {/* Permission editor (expandable) */}
                {isExpanded && activeTenantId && (
                  <PermissionEditor
                    member={m}
                    tenantId={activeTenantId}
                    onSaved={handlePermSaved}
                  />
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ─── Notifications Tab ────────────────────────────────────────────────────────

function NotifToggle({ on, onChange }: { on: boolean; onChange: () => void }) {
  return (
    <div
      onClick={onChange}
      style={{
        width: 36, height: 20, borderRadius: 10, flexShrink: 0,
        background: on ? '#3B82F6' : 'rgba(255,255,255,0.1)',
        border: `1px solid ${on ? '#2563EB' : 'rgba(255,255,255,0.1)'}`,
        position: 'relative', cursor: 'pointer',
        transition: 'background 150ms, border 150ms',
      }}
    >
      <div style={{
        position: 'absolute', top: 3, left: on ? 17 : 3,
        width: 14, height: 14, borderRadius: '50%', background: '#fff',
        transition: 'left 150ms',
        boxShadow: '0 1px 3px rgba(0,0,0,0.3)',
      }} />
    </div>
  )
}

const NOTIF_ITEMS: Array<{
  key: keyof NotificationPreferences
  label: string
  description: string
}> = [
  {
    key: 'email_high_critical_alerts',
    label: 'High / Critical Alerts',
    description: 'Get notified when a HIGH or CRITICAL alert fires',
  },
  {
    key: 'email_agent_offline',
    label: 'Agent Offline',
    description: 'Get notified when a monitored device goes offline',
  },
  {
    key: 'email_new_investigation',
    label: 'New Investigations',
    description: 'Get notified when a new investigation is created',
  },
]

function NotificationsTab() {
  const user = useAuthStore(s => s.user)
  const [prefs,   setPrefs]   = useState<NotificationPreferences | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving,  setSaving]  = useState(false)
  const [saved,   setSaved]   = useState(false)
  const [error,   setError]   = useState<string | null>(null)

  useEffect(() => {
    settingsApi.getNotificationPrefs()
      .then(p => setPrefs(p))
      .catch(() => setPrefs({
        email_high_critical_alerts: true,
        email_agent_offline: true,
        email_new_investigation: false,
      }))
      .finally(() => setLoading(false))
  }, [])

  const toggle = (key: keyof NotificationPreferences) => {
    if (!prefs) return
    setPrefs({ ...prefs, [key]: !prefs[key] })
  }

  const handleSave = async () => {
    if (!prefs) return
    setSaving(true)
    setError(null)
    try {
      await settingsApi.updateNotificationPrefs(prefs)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (err) {
      setError(extractApiError(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{ maxWidth: 480 }}>
      <SectionHeader
        title="Email Notifications"
        description="Configure which events trigger email alerts"
      />

      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {[1, 2, 3].map(i => <div key={i} className="skel" style={{ height: 56, borderRadius: 8 }} />)}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 24 }}>
          {NOTIF_ITEMS.map(item => (
            <div
              key={item.key}
              className="card"
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '14px 16px', cursor: 'pointer',
              }}
              onClick={() => toggle(item.key)}
            >
              <div style={{ flex: 1, paddingRight: 16 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#F5F7FA', marginBottom: 2 }}>
                  {item.label}
                </div>
                <div style={{ fontSize: 11, color: '#5C6373' }}>
                  {item.description}
                </div>
              </div>
              <NotifToggle
                on={prefs?.[item.key] ?? false}
                onChange={() => toggle(item.key)}
              />
            </div>
          ))}
        </div>
      )}

      {/* SMTP info bar */}
      <div style={{
        padding: '10px 14px', marginBottom: 20, borderRadius: 8,
        background: 'rgba(245,158,11,0.06)',
        border: '1px solid rgba(245,158,11,0.15)',
        display: 'flex', alignItems: 'flex-start', gap: 8,
      }}>
        <Mail size={13} style={{ color: '#F59E0B', marginTop: 2, flexShrink: 0 }} />
        <div>
          <div style={{ fontSize: 12, color: '#FCD34D', fontWeight: 600, marginBottom: 2 }}>
            Emails sent to: {user?.email ?? '—'}
          </div>
          <div style={{ fontSize: 11, color: '#8B95A7' }}>
            Configure SMTP_HOST, SMTP_USER, and SMTP_PASSWORD in Railway Variables
            to enable email delivery
          </div>
        </div>
      </div>

      {error && (
        <div style={{ marginBottom: 12, fontSize: 12, color: '#FCA5A5' }}>{error}</div>
      )}

      <Button variant="primary" loading={saving} onClick={handleSave} disabled={loading}>
        {saved ? <><Check size={13} /> Saved</> : 'Save Preferences'}
      </Button>
    </div>
  )
}

// ─── Automation Tab ───────────────────────────────────────────────────────────

const SEVERITY_OPTIONS: { value: AutoPlaybookConfig['min_severity']; label: string; color: string; desc: string }[] = [
  { value: 'critical', label: 'Critical only',         color: '#EF4444', desc: 'Only generate for CRITICAL severity alerts' },
  { value: 'high',     label: 'High & Critical',       color: '#F97316', desc: 'Generate for HIGH and CRITICAL alerts' },
  { value: 'medium',   label: 'Medium, High & Critical', color: '#F59E0B', desc: 'Generate for MEDIUM, HIGH, and CRITICAL alerts' },
  { value: 'low',      label: 'All severities',        color: '#6B7280', desc: 'Generate a playbook for every alert' },
]

function AutomationTab() {
  const [cfg,     setCfg]     = useState<AutoPlaybookConfig>({ enabled: false, min_severity: 'critical' })
  const [loading, setLoading] = useState(true)
  const [saving,  setSaving]  = useState(false)
  const [saved,   setSaved]   = useState(false)
  const [error,   setError]   = useState<string | null>(null)

  useEffect(() => {
    playbookAutoApi.getConfig()
      .then(c => setCfg(c))
      .catch(e => toastError(extractApiError(e), 'Failed to load automation config'))
      .finally(() => setLoading(false))
  }, [])

  const handleSave = async () => {
    setSaving(true); setError(null)
    try {
      const updated = await playbookAutoApi.updateConfig(cfg)
      setCfg(updated)
      setSaved(true)
      toastSuccess('Automation configuration saved', 'Saved')
      setTimeout(() => setSaved(false), 2500)
    } catch (err) {
      setError(extractApiError(err))
    } finally {
      setSaving(false)
    }
  }

  const activeSeverity = SEVERITY_OPTIONS.find(s => s.value === cfg.min_severity)!

  return (
    <div style={{ maxWidth: 520 }}>
      <SectionHeader
        title="Automation"
        description="Configure AI-powered automatic responses to security events"
      />

      {/* Auto Playbook card */}
      <div style={{
        borderRadius: 10, border: `1px solid ${cfg.enabled ? 'rgba(139,92,246,0.25)' : 'rgba(255,255,255,0.06)'}`,
        background: cfg.enabled ? 'rgba(139,92,246,0.04)' : '#0D0D0D',
        transition: 'all 200ms', overflow: 'hidden', marginBottom: 20,
      }}>
        {/* Card header + master toggle */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '16px 18px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          <div style={{ width: 36, height: 36, borderRadius: 10, background: 'rgba(139,92,246,0.12)', border: '1px solid rgba(139,92,246,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <Zap size={18} style={{ color: '#8B5CF6' }} />
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#F5F7FA', fontFamily: "'Space Grotesk', sans-serif" }}>
              Auto-Generate Playbooks
            </div>
            <div style={{ fontSize: 11, color: '#5C6373', marginTop: 2 }}>
              Automatically create an AI response playbook when an alert fires
            </div>
          </div>
          {/* Toggle */}
          <div
            onClick={() => setCfg(c => ({ ...c, enabled: !c.enabled }))}
            style={{
              width: 44, height: 24, borderRadius: 12, flexShrink: 0, cursor: 'pointer',
              background: cfg.enabled ? '#8B5CF6' : 'rgba(255,255,255,0.1)',
              border: `1px solid ${cfg.enabled ? '#7C3AED' : 'rgba(255,255,255,0.1)'}`,
              position: 'relative', transition: 'all 200ms',
            }}
          >
            <div style={{
              position: 'absolute', top: 3, left: cfg.enabled ? 22 : 3,
              width: 18, height: 18, borderRadius: '50%', background: '#fff',
              transition: 'left 200ms', boxShadow: '0 1px 4px rgba(0,0,0,0.3)',
            }} />
          </div>
        </div>

        {/* Severity selector — only visible when enabled */}
        {cfg.enabled && (
          <div style={{ padding: '16px 18px' }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '1.5px', marginBottom: 12 }}>
              Minimum Severity Threshold
            </div>
            <div style={{ display: 'grid', gap: 8 }}>
              {SEVERITY_OPTIONS.map(opt => (
                <button
                  key={opt.value}
                  onClick={() => setCfg(c => ({ ...c, min_severity: opt.value }))}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 12, padding: '10px 14px',
                    borderRadius: 8, cursor: 'pointer', textAlign: 'left',
                    background: cfg.min_severity === opt.value ? `${opt.color}12` : 'rgba(255,255,255,0.03)',
                    border: `1px solid ${cfg.min_severity === opt.value ? opt.color + '40' : 'rgba(255,255,255,0.06)'}`,
                    transition: 'all 120ms',
                  }}
                >
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: opt.color, flexShrink: 0 }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: cfg.min_severity === opt.value ? '#F5F7FA' : '#8B95A7' }}>{opt.label}</div>
                    <div style={{ fontSize: 10, color: '#5C6373', marginTop: 1 }}>{opt.desc}</div>
                  </div>
                  {cfg.min_severity === opt.value && <CheckCircle size={13} style={{ color: opt.color }} />}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Current status info */}
      <div style={{ padding: '10px 14px', borderRadius: 8, marginBottom: 20, fontSize: 12, lineHeight: 1.6,
        background: cfg.enabled ? 'rgba(16,185,129,0.06)' : 'rgba(255,255,255,0.03)',
        border: `1px solid ${cfg.enabled ? 'rgba(16,185,129,0.15)' : 'rgba(255,255,255,0.06)'}`,
        color: cfg.enabled ? '#6EE7B7' : '#5C6373',
      }}>
        {cfg.enabled
          ? `Active — playbooks will be generated automatically for ${activeSeverity.label.toLowerCase()} alerts using AI analysis.`
          : 'Disabled — playbooks will only be generated manually by analysts.'}
      </div>

      {error && (
        <div style={{ marginBottom: 12, padding: '8px 12px', borderRadius: 6, fontSize: 12,
          background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)', color: '#F87171' }}>
          {error}
        </div>
      )}

      {loading ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#5C6373', fontSize: 12 }}>
          <Loader size={14} className="animate-spin" /> Loading configuration…
        </div>
      ) : (
        <Button variant="primary" loading={saving} onClick={handleSave}>
          {saved ? <><Check size={13} /> Saved</> : 'Save Configuration'}
        </Button>
      )}

      {/* Info callout */}
      <div style={{ marginTop: 24, padding: '14px 16px', borderRadius: 8, background: 'rgba(59,130,246,0.05)', border: '1px solid rgba(59,130,246,0.12)' }}>
        <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', color: '#60A5FA', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
          <Bot size={12} /> How it works
        </div>
        <ul style={{ margin: 0, paddingLeft: 16, fontSize: 12, color: '#8B95A7', lineHeight: 1.8 }}>
          <li>When a detection rule fires and creates an alert, the system checks this configuration</li>
          <li>If enabled and the alert severity meets the threshold, an AI playbook is generated in the background</li>
          <li>The playbook appears in the Playbooks section tagged as "Auto-Generated"</li>
          <li>Analysts can then review, execute, and track each step</li>
        </ul>
      </div>
    </div>
  )
}

// ─── Display section ──────────────────────────────────────────────────────────

type Density = 'compact' | 'default' | 'comfortable'

function DisplaySection() {
  const [density, setDensity] = useState<Density>(() => {
    return (localStorage.getItem('neurashield-density') as Density) || 'default'
  })

  const applyDensity = (d: Density) => {
    setDensity(d)
    localStorage.setItem('neurashield-density', d)
    if (d === 'default') {
      document.documentElement.removeAttribute('data-density')
    } else {
      document.documentElement.setAttribute('data-density', d)
    }
  }

  useEffect(() => {
    const saved = (localStorage.getItem('neurashield-density') as Density) || 'default'
    if (saved !== 'default') document.documentElement.setAttribute('data-density', saved)
  }, [])

  const options: Array<{ value: Density; label: string; description: string }> = [
    { value: 'compact',     label: 'Compact',     description: 'Smaller rows and cards — fits more data on screen' },
    { value: 'default',     label: 'Default',     description: 'Balanced density for everyday use'                },
    { value: 'comfortable', label: 'Comfortable', description: 'More whitespace — easier to scan individual rows'  },
  ]

  return (
    <div>
      <SectionHeader title="Display" description="Customize the visual density and appearance of the interface" />
      <div style={{ marginBottom: 28 }}>
        <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', color: '#5C6373', marginBottom: 12 }}>
          Data Density
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxWidth: 420 }}>
          {options.map(({ value, label, description }) => (
            <button
              key={value}
              onClick={() => applyDensity(value)}
              style={{
                display: 'flex', alignItems: 'center', gap: 12,
                padding: '12px 14px', borderRadius: 8, cursor: 'pointer', textAlign: 'left',
                background: density === value ? 'rgba(59,130,246,0.08)' : 'rgba(255,255,255,0.02)',
                border: `1px solid ${density === value ? 'rgba(59,130,246,0.35)' : 'rgba(255,255,255,0.06)'}`,
                transition: 'all 120ms',
              }}
            >
              <div style={{
                width: 18, height: 18, borderRadius: '50%', flexShrink: 0,
                background: density === value ? '#3B82F6' : 'rgba(255,255,255,0.06)',
                border: `2px solid ${density === value ? '#3B82F6' : 'rgba(255,255,255,0.12)'}`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                {density === value && <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#fff' }} />}
              </div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: density === value ? '#F5F7FA' : '#8B95A7' }}>{label}</div>
                <div style={{ fontSize: 11, color: '#5C6373', marginTop: 2 }}>{description}</div>
              </div>
            </button>
          ))}
        </div>
      </div>

      <div style={{ padding: '12px 16px', borderRadius: 8, background: 'rgba(59,130,246,0.05)', border: '1px solid rgba(59,130,246,0.15)', maxWidth: 420 }}>
        <div style={{ fontSize: 11, color: '#8B95A7', lineHeight: 1.6 }}>
          Density setting is saved locally and applies immediately across all pages. Changes take effect without reloading.
        </div>
      </div>
    </div>
  )
}

// ─── SettingsPage ─────────────────────────────────────────────────────────────

import type { MemberRole } from '@/types/tenant'

const ALL_TABS = [
  { id: 'profile',              label: 'Profile',             icon: User,      minRole: 'viewer'  as MemberRole },
  { id: 'org',                  label: 'Organization',        icon: Building2, minRole: 'admin'   as MemberRole },
  { id: 'api-keys',             label: 'API Keys',            icon: Key,       minRole: 'admin'   as MemberRole },
  { id: 'members',              label: 'Members',             icon: Users,     minRole: 'viewer'  as MemberRole },
  { id: 'notifications',        label: 'Notifications',       icon: Bell,      minRole: 'viewer'  as MemberRole },
  { id: 'notification-rules',   label: 'Alert Routing',       icon: BellRing,  minRole: 'admin'   as MemberRole },
  { id: 'severity-thresholds',  label: 'Severity Thresholds', icon: BarChart3, minRole: 'admin'   as MemberRole },
  { id: 'ticketing',            label: 'Integrations',        icon: Ticket,    minRole: 'admin'   as MemberRole },
  { id: 'quota',                label: 'Quota & Usage',       icon: Gauge,     minRole: 'admin'   as MemberRole },
  { id: 'automation',           label: 'Automation',          icon: Zap,       minRole: 'admin'   as MemberRole },
  { id: 'display',              label: 'Display',             icon: Monitor,   minRole: 'viewer'  as MemberRole },
] as const

type TabId = typeof ALL_TABS[number]['id']

const TAB_GROUPS: Array<{ label: string; ids: TabId[] }> = [
  { label: 'Account',        ids: ['profile', 'notifications', 'display'] },
  { label: 'Administration', ids: ['org', 'members', 'api-keys', 'members'] },
  { label: 'Operations',     ids: ['notification-rules', 'severity-thresholds', 'automation'] },
  { label: 'Platform',       ids: ['ticketing', 'quota'] },
]

export function SettingsPage() {
  const hasRole = useTenantStore(s => s.hasRole)
  const TABS = ALL_TABS.filter(t => hasRole(t.minRole))
  const [activeTab, setActiveTab] = useState<TabId>('profile')

  const renderNavItem = (tab: (typeof ALL_TABS)[number]) => {
    const Icon = tab.icon
    const active = activeTab === tab.id
    return (
      <button
        key={tab.id}
        onClick={() => setActiveTab(tab.id)}
        style={{
          display: 'flex', alignItems: 'center', gap: 9,
          width: '100%', padding: '7px 14px',
          fontSize: 12, cursor: 'pointer',
          background: active ? 'rgba(59,130,246,0.08)' : 'transparent',
          borderLeft: `2px solid ${active ? '#3B82F6' : 'transparent'}`,
          border: 'none',
          color: active ? '#93C5FD' : '#8B95A7',
          fontWeight: active ? 600 : 400,
          transition: 'all 120ms', textAlign: 'left',
        }}
      >
        <Icon size={13} style={{ opacity: active ? 1 : 0.45, flexShrink: 0 }} />
        {tab.label}
      </button>
    )
  }

  // Build grouped nav — skip empty groups
  const groupedTabs = TAB_GROUPS.map(g => ({
    label: g.label,
    tabs: TABS.filter(t => g.ids.includes(t.id)),
  })).filter(g => g.tabs.length > 0)

  // Any tab not in a group goes at the top ungrouped (fallback)
  const groupedIds = new Set(TAB_GROUPS.flatMap(g => g.ids))
  const ungrouped  = TABS.filter(t => !groupedIds.has(t.id))

  return (
    <div
      className="page-in"
      style={{ display: 'flex', gap: 0, height: 'calc(100vh - 50px - 40px)', overflow: 'hidden' }}
    >
      {/* Left nav */}
      <div style={{
        width: 200, flexShrink: 0,
        borderRight: '1px solid rgba(255,255,255,0.06)',
        paddingTop: 4, overflowY: 'auto',
      }}>
        {ungrouped.map(renderNavItem)}
        {groupedTabs.map(group => (
          <div key={group.label} style={{ marginBottom: 4 }}>
            <div style={{
              padding: '10px 14px 4px',
              fontSize: 9, fontWeight: 700,
              textTransform: 'uppercase', letterSpacing: '1.5px', color: '#3A4150',
            }}>
              {group.label}
            </div>
            {group.tabs.map(renderNavItem)}
          </div>
        ))}
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '0 32px 32px' }}>
        {activeTab === 'profile'             && <ProfileTab              />}
        {activeTab === 'org'                 && <OrgTab                  />}
        {activeTab === 'api-keys'            && <ApiKeysTab              />}
        {activeTab === 'members'             && <MembersTab              />}
        {activeTab === 'notifications'       && <NotificationsTab        />}
        {activeTab === 'notification-rules'  && <NotificationRulesSection />}
        {activeTab === 'severity-thresholds' && <SeverityThresholdsSection />}
        {activeTab === 'ticketing'           && <TicketingConfigSection  />}
        {activeTab === 'quota'               && <QuotaDashboardSection   />}
        {activeTab === 'automation'          && <AutomationTab           />}
        {activeTab === 'display'             && <DisplaySection          />}
      </div>
    </div>
  )
}
