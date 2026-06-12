import { ShieldOff } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useTenantStore } from '@/stores/tenantStore'
import type { MemberRole } from '@/types/tenant'

const ROLE_LABELS: Record<string, string> = {
  viewer:  'Viewer',
  analyst: 'Analyst',
  admin:   'Admin',
  owner:   'Owner',
}

interface Props {
  min: MemberRole
  children: React.ReactNode
}

export function RequireRole({ min, children }: Props) {
  const hasRole    = useTenantStore(s => s.hasRole)
  const memberRole = useTenantStore(s => s.memberRole)

  if (!hasRole(min)) {
    return (
      <div style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center',
        justifyContent: 'center', minHeight: '60vh', textAlign: 'center', gap: 20,
      }}>
        <div style={{
          width: 60, height: 60, borderRadius: '50%',
          background: 'rgba(239,68,68,0.08)',
          border: '1px solid rgba(239,68,68,0.2)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <ShieldOff size={26} style={{ color: '#F87171' }} />
        </div>

        <div>
          <h2 style={{
            fontSize: 16, fontWeight: 700,
            fontFamily: "'Space Grotesk', sans-serif",
            color: '#F5F7FA', margin: '0 0 10px',
          }}>
            Access Restricted
          </h2>
          <p style={{ fontSize: 13, color: '#8B95A7', margin: '0 0 6px' }}>
            You need{' '}
            <strong style={{ color: '#F5F7FA' }}>
              {ROLE_LABELS[min] ?? min}
            </strong>{' '}
            role or higher to access this page.
          </p>
          <p style={{ fontSize: 12, color: '#5C6373', margin: 0 }}>
            Your role:{' '}
            <strong style={{ color: '#8B95A7', textTransform: 'capitalize' }}>
              {memberRole ? (ROLE_LABELS[memberRole] ?? memberRole) : '—'}
            </strong>
            {' '}· Contact your workspace admin to request access.
          </p>
        </div>

        <Link to="/dashboard" style={{
          padding: '8px 20px', borderRadius: 8, fontSize: 13, fontWeight: 600,
          background: 'rgba(59,130,246,0.08)',
          border: '1px solid rgba(59,130,246,0.2)',
          color: '#60A5FA', textDecoration: 'none',
        }}>
          ← Back to Dashboard
        </Link>
      </div>
    )
  }

  return <>{children}</>
}
