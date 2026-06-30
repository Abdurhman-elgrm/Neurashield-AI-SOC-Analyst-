import { useState, useEffect, FormEvent } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Eye, EyeOff, AlertCircle, CheckCircle2, Circle, UserPlus, LogIn } from 'lucide-react'
import { useAuthStore } from '@/stores/authStore'
import { invitationsApi } from '@/api/invitations'
import { authApi } from '@/api/auth'
import { cn, extractApiError } from '@/lib/utils'
import { LogoFull } from '@/components/ui/Logo'

function PasswordRule({ met, label }: { met: boolean; label: string }) {
  return (
    <div className={cn('flex items-center gap-1.5 text-xs transition-colors', met ? 'text-cyber-400' : 'text-text-muted')}>
      {met
        ? <CheckCircle2 className="w-3 h-3 flex-shrink-0" />
        : <Circle className="w-3 h-3 flex-shrink-0" />}
      {label}
    </div>
  )
}

type FlowMode = 'choose' | 'new' | 'existing'

export function AcceptInvitePage() {
  const navigate    = useNavigate()
  const [params]    = useSearchParams()
  const token       = params.get('token') ?? ''

  const setAuth         = useAuthStore(s => s.setAuth)
  const setUser         = useAuthStore(s => s.setUser)
  const setActiveTenant = useAuthStore(s => s.setActiveTenant)

  const [mode,         setMode]         = useState<FlowMode>('choose')
  const [isLoading,    setIsLoading]    = useState(false)
  const [error,        setError]        = useState<string | null>(null)

  // New user form
  const [fullName,     setFullName]     = useState('')
  const [newPassword,  setNewPassword]  = useState('')
  const [showNewPwd,   setShowNewPwd]   = useState(false)

  // Existing user form
  const [exEmail,      setExEmail]      = useState('')
  const [exPassword,   setExPassword]   = useState('')
  const [showExPwd,    setShowExPwd]    = useState(false)

  useEffect(() => {
    if (!token) {
      setError('No invitation token found. Please check the link in your email.')
    }
  }, [token])

  const pwdRules = {
    length:    newPassword.length >= 8,
    uppercase: /[A-Z]/.test(newPassword),
    lowercase: /[a-z]/.test(newPassword),
    digit:     /\d/.test(newPassword),
  }
  const allPwdRulesMet = Object.values(pwdRules).every(Boolean)

  async function handleNewAccount(e: FormEvent) {
    e.preventDefault()
    if (!allPwdRulesMet || !token) return
    setError(null)
    setIsLoading(true)
    try {
      const resp = await invitationsApi.accept({ token, full_name: fullName.trim(), password: newPassword })
      const data = resp.data.data
      setAuth(
        { id: '', email: '', full_name: fullName.trim(), is_active: true, created_at: '' },
        data.access_token,
      )
      setActiveTenant(data.tenant_id)
      const me = await authApi.me()
      setUser(me)
      navigate('/', { replace: true })
    } catch (err) {
      setError(extractApiError(err))
    } finally {
      setIsLoading(false)
    }
  }

  async function handleExistingAccount(e: FormEvent) {
    e.preventDefault()
    if (!exEmail || !exPassword || !token) return
    setError(null)
    setIsLoading(true)
    try {
      const resp = await invitationsApi.accept({ token, existing_email: exEmail.trim(), existing_password: exPassword })
      const data = resp.data.data
      setAuth(
        { id: '', email: exEmail.trim(), full_name: '', is_active: true, created_at: '' },
        data.access_token,
      )
      setActiveTenant(data.tenant_id)
      const me = await authApi.me()
      setUser(me)
      navigate('/', { replace: true })
    } catch (err) {
      setError(extractApiError(err))
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center p-4"
      style={{ background: '#000000' }}
    >
      {/* Ambient blobs */}
      <div className="fixed top-0 left-1/4 w-[500px] h-[500px] rounded-full pointer-events-none"
        style={{ background: 'radial-gradient(circle, rgba(59,130,246,0.08) 0%, transparent 70%)', filter: 'blur(40px)' }} />
      <div className="fixed bottom-0 right-1/4 w-[400px] h-[400px] rounded-full pointer-events-none"
        style={{ background: 'radial-gradient(circle, rgba(6,182,212,0.06) 0%, transparent 70%)', filter: 'blur(40px)' }} />

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25, ease: 'easeOut' }}
        className="relative w-full max-w-[420px]"
      >
        <div className="flex justify-center mb-8">
          <LogoFull size={40} showSubtitle />
        </div>

        <div
          className="rounded-2xl p-7 border"
          style={{
            background: 'rgba(13,13,13,0.9)',
            borderColor: 'rgba(59,130,246,0.2)',
            boxShadow: '0 0 40px rgba(59,130,246,0.1), inset 0 1px 0 rgba(255,255,255,0.04)',
            backdropFilter: 'blur(12px)',
          }}
        >
          {/* Header */}
          <div className="mb-6">
            <h1 className="font-display text-xl font-bold text-text-primary mb-1">
              You've been invited
            </h1>
            <p className="text-sm text-text-muted">
              Join NEURASHIELD SOC Platform
            </p>
          </div>

          {/* Token missing error */}
          {!token && (
            <div className="flex items-start gap-2.5 p-3 mb-4 rounded-lg"
              style={{ background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.25)' }}>
              <AlertCircle className="w-4 h-4 text-severity-critical mt-0.5 flex-shrink-0" />
              <p className="text-sm text-severity-critical">
                Invalid invitation link. Please check the link in your email.
              </p>
            </div>
          )}

          {/* Shared error */}
          {error && token && (
            <motion.div
              key={error}
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              className="flex items-start gap-2.5 p-3 mb-4 rounded-lg"
              style={{ background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.25)' }}
            >
              <AlertCircle className="w-4 h-4 text-severity-critical mt-0.5 flex-shrink-0" />
              <p className="text-sm text-severity-critical">{error}</p>
            </motion.div>
          )}

          {mode === 'choose' && token && (
            <div className="space-y-3">
              <button
                className="w-full flex items-center gap-3 p-4 rounded-xl border transition-all text-left"
                style={{
                  background: 'rgba(59,130,246,0.05)',
                  borderColor: 'rgba(59,130,246,0.25)',
                  color: '#F5F7FA',
                }}
                onClick={() => setMode('new')}
              >
                <div className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
                  style={{ background: 'rgba(59,130,246,0.15)' }}>
                  <UserPlus className="w-4 h-4 text-primary-400" />
                </div>
                <div>
                  <div className="text-sm font-semibold">Create New Account</div>
                  <div className="text-xs text-text-muted mt-0.5">Register with your invited email</div>
                </div>
              </button>

              <div className="flex items-center gap-3 my-1">
                <div className="flex-1 h-px" style={{ background: 'rgba(255,255,255,0.06)' }} />
                <span className="text-xs text-text-muted">or</span>
                <div className="flex-1 h-px" style={{ background: 'rgba(255,255,255,0.06)' }} />
              </div>

              <button
                className="w-full flex items-center gap-3 p-4 rounded-xl border transition-all text-left"
                style={{
                  background: 'rgba(255,255,255,0.02)',
                  borderColor: 'rgba(255,255,255,0.08)',
                  color: '#F5F7FA',
                }}
                onClick={() => setMode('existing')}
              >
                <div className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
                  style={{ background: 'rgba(255,255,255,0.06)' }}>
                  <LogIn className="w-4 h-4 text-text-secondary" />
                </div>
                <div>
                  <div className="text-sm font-semibold">Sign In to Existing Account</div>
                  <div className="text-xs text-text-muted mt-0.5">Use credentials you already have</div>
                </div>
              </button>
            </div>
          )}

          {/* New account form */}
          {mode === 'new' && token && (
            <form onSubmit={handleNewAccount} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-text-secondary mb-1.5">Full name</label>
                <input
                  type="text"
                  className="input-base"
                  placeholder="Jane Smith"
                  value={fullName}
                  onChange={e => setFullName(e.target.value)}
                  required
                  disabled={isLoading}
                  autoFocus
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-text-secondary mb-1.5">Password</label>
                <div className="relative">
                  <input
                    type={showNewPwd ? 'text' : 'password'}
                    className="input-base pr-10"
                    placeholder="••••••••"
                    value={newPassword}
                    onChange={e => setNewPassword(e.target.value)}
                    required
                    disabled={isLoading}
                  />
                  <button
                    type="button"
                    onClick={() => setShowNewPwd(!showNewPwd)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary transition-colors"
                    tabIndex={-1}
                  >
                    {showNewPwd ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {newPassword && (
                  <div className="mt-2.5 grid grid-cols-2 gap-1.5">
                    <PasswordRule met={pwdRules.length}    label="8+ characters" />
                    <PasswordRule met={pwdRules.uppercase} label="Uppercase letter" />
                    <PasswordRule met={pwdRules.lowercase} label="Lowercase letter" />
                    <PasswordRule met={pwdRules.digit}     label="Number" />
                  </div>
                )}
              </div>
              <button
                type="submit"
                className={cn('btn-primary w-full mt-2', (isLoading || !allPwdRulesMet || !fullName.trim()) && 'opacity-60 cursor-not-allowed')}
                disabled={isLoading || !allPwdRulesMet || !fullName.trim()}
              >
                {isLoading ? (
                  <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />Creating account…</>
                ) : 'Create Account & Join'}
              </button>
              <button
                type="button"
                className="w-full text-center text-xs text-text-muted hover:text-text-secondary transition-colors mt-1"
                onClick={() => { setMode('choose'); setError(null) }}
              >
                ← Back
              </button>
            </form>
          )}

          {/* Existing account form */}
          {mode === 'existing' && token && (
            <form onSubmit={handleExistingAccount} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-text-secondary mb-1.5">Email address</label>
                <input
                  type="email"
                  className="input-base"
                  placeholder="you@company.com"
                  value={exEmail}
                  onChange={e => setExEmail(e.target.value)}
                  required
                  disabled={isLoading}
                  autoFocus
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-text-secondary mb-1.5">Password</label>
                <div className="relative">
                  <input
                    type={showExPwd ? 'text' : 'password'}
                    className="input-base pr-10"
                    placeholder="••••••••"
                    value={exPassword}
                    onChange={e => setExPassword(e.target.value)}
                    required
                    disabled={isLoading}
                  />
                  <button
                    type="button"
                    onClick={() => setShowExPwd(!showExPwd)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary transition-colors"
                    tabIndex={-1}
                  >
                    {showExPwd ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
              <button
                type="submit"
                className={cn('btn-primary w-full mt-2', (isLoading || !exEmail || !exPassword) && 'opacity-60 cursor-not-allowed')}
                disabled={isLoading || !exEmail || !exPassword}
              >
                {isLoading ? (
                  <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />Signing in…</>
                ) : 'Sign In & Join'}
              </button>
              <button
                type="button"
                className="w-full text-center text-xs text-text-muted hover:text-text-secondary transition-colors mt-1"
                onClick={() => { setMode('choose'); setError(null) }}
              >
                ← Back
              </button>
            </form>
          )}
        </div>
      </motion.div>
    </div>
  )
}
