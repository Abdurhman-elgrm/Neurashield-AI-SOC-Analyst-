interface SevBadgeProps {
  sev: string | number
}

const SEV_CONFIG: Record<string, { color: string; bg: string; label: string }> = {
  critical: { color: '#FCA5A5', bg: 'rgba(239,68,68,0.12)',   label: 'CRITICAL' },
  high:     { color: '#FDB07A', bg: 'rgba(249,115,22,0.12)',  label: 'HIGH'     },
  medium:   { color: '#FCD34D', bg: 'rgba(245,158,11,0.12)',  label: 'MEDIUM'   },
  low:      { color: '#93C5FD', bg: 'rgba(59,130,246,0.12)',  label: 'LOW'      },
  info:     { color: '#9CA3AF', bg: 'rgba(107,114,128,0.1)',  label: 'INFO'     },
}

function normalise(sev: string | number): string {
  if (typeof sev === 'number') {
    if (sev >= 4) return 'critical'
    if (sev >= 3) return 'high'
    if (sev >= 2) return 'medium'
    return 'low'
  }
  return String(sev).toLowerCase()
}

export function SevBadge({ sev }: SevBadgeProps) {
  const key = normalise(sev)
  const cfg = SEV_CONFIG[key] ?? { color: '#9CA3AF', bg: 'rgba(107,114,128,0.1)', label: String(sev).toUpperCase() }

  return (
    <span style={{
      display: 'inline-flex',
      padding: '2px 7px',
      borderRadius: 4,
      fontSize: 9,
      fontWeight: 700,
      fontFamily: "'JetBrains Mono', monospace",
      textTransform: 'uppercase' as const,
      letterSpacing: '0.05em',
      color: cfg.color,
      background: cfg.bg,
    }}>
      {cfg.label}
    </span>
  )
}
