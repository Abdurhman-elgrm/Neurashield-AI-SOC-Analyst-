import { useState, FormEvent } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { User, Briefcase, FileText, Lock, CheckCircle, AlertCircle, Camera } from 'lucide-react'
import { settingsApi, type UpdateProfilePayload } from '@/api/settings'
import { authApi } from '@/api/auth'
import { Button } from '@/components/ui/Button'
import { extractApiError } from '@/lib/utils'

// ─── Gravatar helper ──────────────────────────────────────────────────────────

function gravatarUrl(email: string, size = 96) {
  // Use MD5-like hash via built-in TextEncoder (we approximate with btoa for simple fallback)
  // The backend computes the real gravatar_url — we just display it
  return `https://www.gravatar.com/avatar/${email}?s=${size}&d=identicon`
}

function AvatarDisplay({ profile }: { profile: { email: string; full_name: string; avatar_url?: string | null; gravatar_url?: string | null } }) {
  const src = profile.avatar_url || profile.gravatar_url || gravatarUrl(profile.email)
  const initials = profile.full_name?.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2) || '?'

  return (
    <div style={{ position: 'relative', display: 'inline-block' }}>
      {src ? (
        <img
          src={src}
          alt={profile.full_name}
          onError={(e) => { (e.target as HTMLImageElement).style.display = 'none' }}
          style={{
            width: 80, height: 80, borderRadius: '50%',
            border: '2px solid rgba(59,130,246,0.3)',
            objectFit: 'cover',
          }}
        />
      ) : (
        <div style={{
          width: 80, height: 80, borderRadius: '50%',
          background: 'rgba(59,130,246,0.15)',
          border: '2px solid rgba(59,130,246,0.3)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 24, fontWeight: 800, color: '#60A5FA',
          fontFamily: "'Space Grotesk', sans-serif",
        }}>
          {initials}
        </div>
      )}
    </div>
  )
}

// ─── Section header ───────────────────────────────────────────────────────────

function SectionHeader({ label }: { label: string }) {
  return (
    <div style={{
      fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
      letterSpacing: '1.5px', color: '#5C6373', marginBottom: 14,
    }}>
      {label}
    </div>
  )
}

// ─── Field ────────────────────────────────────────────────────────────────────

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label style={{
        display: 'block', fontSize: 11, fontWeight: 500,
        color: '#8B95A7', marginBottom: 6,
      }}>
        {label}
      </label>
      {children}
    </div>
  )
}

// ─── Status banner ────────────────────────────────────────────────────────────

function EmailVerificationBanner({ email, verified }: { email: string; verified: boolean }) {
  const [sent, setSent] = useState(false)
  const [loading, setLoading] = useState(false)

  async function resend() {
    setLoading(true)
    try {
      await authApi.resendVerification(email)
      setSent(true)
    } finally {
      setLoading(false)
    }
  }

  if (verified) {
    return (
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '10px 14px', borderRadius: 8,
        background: 'rgba(16,185,129,0.08)',
        border: '1px solid rgba(16,185,129,0.2)',
      }}>
        <CheckCircle size={14} style={{ color: '#10B981', flexShrink: 0 }} />
        <span style={{ fontSize: 12, color: '#10B981' }}>Email verified</span>
      </div>
    )
  }

  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
      padding: '10px 14px', borderRadius: 8,
      background: 'rgba(245,158,11,0.08)',
      border: '1px solid rgba(245,158,11,0.2)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <AlertCircle size={14} style={{ color: '#F59E0B', flexShrink: 0 }} />
        <span style={{ fontSize: 12, color: '#F59E0B' }}>
          {sent ? 'Verification email sent — check your inbox' : 'Email not verified'}
        </span>
      </div>
      {!sent && (
        <button
          onClick={resend}
          disabled={loading}
          style={{
            fontSize: 11, fontWeight: 600, color: '#F59E0B',
            background: 'none', border: 'none', cursor: 'pointer',
            opacity: loading ? 0.5 : 1, whiteSpace: 'nowrap',
            textDecoration: 'underline',
          }}
        >
          {loading ? 'Sending…' : 'Resend'}
        </button>
      )}
    </div>
  )
}

// ─── ProfilePage ──────────────────────────────────────────────────────────────

export function ProfilePage() {
  const qc = useQueryClient()

  const { data: profile, isLoading } = useQuery({
    queryKey: ['profile'],
    queryFn: () => settingsApi.getProfile(),
  })

  const [fullName, setFullName] = useState('')
  const [jobTitle, setJobTitle] = useState('')
  const [bio, setBio] = useState('')
  const [timezone, setTimezone] = useState('UTC')
  const [avatarUrl, setAvatarUrl] = useState('')
  const [profileInited, setProfileInited] = useState(false)

  const [profileMsg, setProfileMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null)
  const [pwMsg, setPwMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null)
  const [currentPw, setCurrentPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [pwLoading, setPwLoading] = useState(false)

  if (profile && !profileInited) {
    setFullName(profile.full_name ?? '')
    setJobTitle(profile.job_title ?? '')
    setBio(profile.bio ?? '')
    setTimezone(profile.timezone ?? 'UTC')
    setAvatarUrl(profile.avatar_url ?? '')
    setProfileInited(true)
  }

  const updateProfile = useMutation({
    mutationFn: (payload: UpdateProfilePayload) => settingsApi.updateProfile(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['profile'] })
      setProfileMsg({ type: 'ok', text: 'Profile saved successfully.' })
      setTimeout(() => setProfileMsg(null), 4000)
    },
    onError: (err) => {
      setProfileMsg({ type: 'err', text: extractApiError(err) })
    },
  })

  async function handleProfileSave(e: FormEvent) {
    e.preventDefault()
    updateProfile.mutate({
      full_name: fullName,
      job_title: jobTitle || null,
      bio: bio || null,
      timezone,
      avatar_url: avatarUrl || null,
    })
  }

  async function handlePasswordChange(e: FormEvent) {
    e.preventDefault()
    if (newPw !== confirmPw) {
      setPwMsg({ type: 'err', text: 'Passwords do not match' })
      return
    }
    setPwLoading(true)
    setPwMsg(null)
    try {
      await authApi.changePassword(currentPw, newPw)
      setCurrentPw('')
      setNewPw('')
      setConfirmPw('')
      setPwMsg({ type: 'ok', text: 'Password changed successfully.' })
      setTimeout(() => setPwMsg(null), 4000)
    } catch (err) {
      setPwMsg({ type: 'err', text: extractApiError(err) })
    } finally {
      setPwLoading(false)
    }
  }

  const pageStyle: React.CSSProperties = {
    display: 'flex', flexDirection: 'column',
    height: 'calc(100vh - 50px - 40px)',
    overflow: 'hidden',
  }

  const cardStyle: React.CSSProperties = {
    background: '#0D0D0D',
    border: '1px solid rgba(255,255,255,0.06)',
    borderRadius: 10,
    padding: 20,
    marginBottom: 16,
  }

  return (
    <div className="page-in" style={pageStyle}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'flex-start',
        justifyContent: 'space-between', paddingBottom: 12,
        borderBottom: '1px solid rgba(255,255,255,0.06)', flexShrink: 0,
      }}>
        <div>
          <h1 style={{ fontSize: 17, fontWeight: 800, color: '#F5F7FA', fontFamily: "'Space Grotesk', sans-serif" }}>
            My Profile
          </h1>
          <p style={{ fontSize: 12, color: '#5C6373', marginTop: 3 }}>
            Manage your personal information and security settings
          </p>
        </div>
      </div>

      {/* Body */}
      <div style={{ flex: 1, overflowY: 'auto', paddingTop: 16 }}>
        {isLoading ? (
          <div style={{ display: 'grid', gap: 16 }}>
            {[120, 220, 200].map((h, i) => (
              <div key={i} className="skel" style={{ height: h, borderRadius: 10, display: 'block' }} />
            ))}
          </div>
        ) : profile ? (
          <>
            {/* Avatar + identity */}
            <div style={cardStyle}>
              <SectionHeader label="Identity" />
              <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20 }}>
                <AvatarDisplay profile={profile} />
                <div>
                  <div style={{ fontSize: 16, fontWeight: 700, color: '#F5F7FA', fontFamily: "'Space Grotesk', sans-serif" }}>
                    {profile.full_name}
                  </div>
                  <div style={{ fontSize: 12, color: '#8B95A7', marginTop: 2 }}>
                    {profile.email}
                  </div>
                  {profile.job_title && (
                    <div style={{ fontSize: 11, color: '#5C6373', marginTop: 4 }}>
                      {profile.job_title}
                    </div>
                  )}
                </div>
              </div>

              <EmailVerificationBanner
                email={profile.email}
                verified={profile.email_verified ?? false}
              />
            </div>

            {/* Profile form */}
            <div style={cardStyle}>
              <SectionHeader label="Profile Information" />
              <form onSubmit={handleProfileSave}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
                  <Field label="Full Name">
                    <div style={{ position: 'relative' }}>
                      <User size={12} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: '#5C6373', pointerEvents: 'none' }} />
                      <input
                        className="inp"
                        style={{ paddingLeft: 28 }}
                        value={fullName}
                        onChange={e => setFullName(e.target.value)}
                        placeholder="Your full name"
                        required
                      />
                    </div>
                  </Field>
                  <Field label="Job Title">
                    <div style={{ position: 'relative' }}>
                      <Briefcase size={12} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: '#5C6373', pointerEvents: 'none' }} />
                      <input
                        className="inp"
                        style={{ paddingLeft: 28 }}
                        value={jobTitle}
                        onChange={e => setJobTitle(e.target.value)}
                        placeholder="e.g. Senior SOC Analyst"
                      />
                    </div>
                  </Field>
                </div>

                <Field label="Timezone">
                  <select
                    className="inp"
                    value={timezone}
                    onChange={e => setTimezone(e.target.value)}
                    style={{ marginBottom: 12 }}
                  >
                    {[
                      'UTC', 'America/New_York', 'America/Chicago',
                      'America/Denver', 'America/Los_Angeles',
                      'Europe/London', 'Europe/Paris', 'Europe/Berlin',
                      'Asia/Tokyo', 'Asia/Shanghai', 'Asia/Dubai',
                      'Australia/Sydney', 'Africa/Cairo',
                    ].map(tz => (
                      <option key={tz} value={tz}>{tz}</option>
                    ))}
                  </select>
                </Field>

                <Field label="Bio">
                  <div style={{ position: 'relative' }}>
                    <FileText size={12} style={{ position: 'absolute', left: 9, top: 10, color: '#5C6373', pointerEvents: 'none' }} />
                    <textarea
                      className="inp"
                      style={{ paddingLeft: 28, resize: 'vertical', minHeight: 72 }}
                      value={bio}
                      onChange={e => setBio(e.target.value)}
                      placeholder="A short bio about yourself..."
                      maxLength={2000}
                    />
                  </div>
                </Field>

                <div style={{ marginTop: 12 }}>
                  <Field label="Avatar URL (optional)">
                    <div style={{ position: 'relative' }}>
                      <Camera size={12} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: '#5C6373', pointerEvents: 'none' }} />
                      <input
                        className="inp"
                        style={{ paddingLeft: 28 }}
                        value={avatarUrl}
                        onChange={e => setAvatarUrl(e.target.value)}
                        placeholder="https://example.com/avatar.png"
                        type="url"
                      />
                    </div>
                  </Field>
                  <p style={{ fontSize: 10, color: '#5C6373', marginTop: 4 }}>
                    Leave empty to use your Gravatar image
                  </p>
                </div>

                {profileMsg && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    style={{
                      marginTop: 12, padding: '8px 12px', borderRadius: 6, fontSize: 12,
                      background: profileMsg.type === 'ok' ? 'rgba(16,185,129,0.08)' : 'rgba(248,113,113,0.08)',
                      border: `1px solid ${profileMsg.type === 'ok' ? 'rgba(16,185,129,0.2)' : 'rgba(248,113,113,0.2)'}`,
                      color: profileMsg.type === 'ok' ? '#10B981' : '#F87171',
                    }}
                  >
                    {profileMsg.text}
                  </motion.div>
                )}

                <div style={{ marginTop: 14, display: 'flex', justifyContent: 'flex-end' }}>
                  <Button
                    type="submit"
                    variant="primary"
                    size="sm"
                    loading={updateProfile.isPending}
                  >
                    Save Changes
                  </Button>
                </div>
              </form>
            </div>

            {/* Change password */}
            <div style={cardStyle}>
              <SectionHeader label="Change Password" />
              <form onSubmit={handlePasswordChange}>
                <div style={{ display: 'grid', gap: 12 }}>
                  <Field label="Current Password">
                    <div style={{ position: 'relative' }}>
                      <Lock size={12} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: '#5C6373', pointerEvents: 'none' }} />
                      <input
                        type="password"
                        className="inp"
                        style={{ paddingLeft: 28 }}
                        value={currentPw}
                        onChange={e => setCurrentPw(e.target.value)}
                        placeholder="Your current password"
                        required
                        disabled={pwLoading}
                        autoComplete="current-password"
                      />
                    </div>
                  </Field>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                    <Field label="New Password">
                      <input
                        type="password"
                        className="inp"
                        value={newPw}
                        onChange={e => setNewPw(e.target.value)}
                        placeholder="Min. 8 characters"
                        minLength={8}
                        required
                        disabled={pwLoading}
                        autoComplete="new-password"
                      />
                    </Field>
                    <Field label="Confirm New Password">
                      <input
                        type="password"
                        className="inp"
                        value={confirmPw}
                        onChange={e => setConfirmPw(e.target.value)}
                        placeholder="Repeat new password"
                        required
                        disabled={pwLoading}
                        autoComplete="new-password"
                        style={{
                          borderColor: confirmPw && confirmPw !== newPw
                            ? 'rgba(248,113,113,0.5)' : undefined,
                        }}
                      />
                    </Field>
                  </div>
                </div>

                {pwMsg && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    style={{
                      marginTop: 12, padding: '8px 12px', borderRadius: 6, fontSize: 12,
                      background: pwMsg.type === 'ok' ? 'rgba(16,185,129,0.08)' : 'rgba(248,113,113,0.08)',
                      border: `1px solid ${pwMsg.type === 'ok' ? 'rgba(16,185,129,0.2)' : 'rgba(248,113,113,0.2)'}`,
                      color: pwMsg.type === 'ok' ? '#10B981' : '#F87171',
                    }}
                  >
                    {pwMsg.text}
                  </motion.div>
                )}

                <div style={{ marginTop: 14, display: 'flex', justifyContent: 'flex-end' }}>
                  <Button
                    type="submit"
                    variant="primary"
                    size="sm"
                    loading={pwLoading}
                  >
                    Update Password
                  </Button>
                </div>
              </form>
            </div>
          </>
        ) : (
          <div style={{ textAlign: 'center', padding: '60px 0', color: '#5C6373', fontSize: 13 }}>
            Unable to load profile.
          </div>
        )}
      </div>
    </div>
  )
}
