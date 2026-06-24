interface LogoProps {
  size?: number
  showText?: boolean
  showSubtitle?: boolean
  className?: string
}

// Uses the actual logo PNG placed in /public/neurashield.png
// size controls the HEIGHT of the icon; width scales automatically (img is square-ish)

export function LogoIcon({
  size = 44,
  className = '',
}: {
  size?: number
  className?: string
}) {
  return (
    <img
      src="/neurashield.png"
      alt="NEURASHIELD"
      height={size}
      width={size}
      style={{ objectFit: 'contain', display: 'block', flexShrink: 0, mixBlendMode: 'screen' }}
      className={className}
    />
  )
}

export function LogoFull({ size = 44, className = '' }: LogoProps) {
  return (
    <div className={className} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <LogoIcon size={size} />
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <span style={{
          fontFamily: "'Orbitron', sans-serif",
          fontSize: 16,
          fontWeight: 800,
          letterSpacing: '0.22em',
          textTransform: 'uppercase' as const,
          lineHeight: 1,
          background: 'linear-gradient(180deg, #FFFFFF 0%, #CBD5E1 40%, #475569 100%)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          backgroundClip: 'text',
        }}>
          NEURASHIELD
        </span>
        <span style={{
          fontFamily: "'Inter', system-ui, sans-serif",
          fontSize: 7,
          fontWeight: 400,
          letterSpacing: '0.28em',
          color: 'rgba(255,255,255,0.3)',
          textTransform: 'uppercase' as const,
          lineHeight: 1,
        }}>
          AI POWERED SOC ANALYST PLATFORM
        </span>
      </div>
    </div>
  )
}

// compact=true: icon-only (used by collapsed sidebar rail)
export function LogoCompact({ className = '', compact = false }: { className?: string; compact?: boolean }) {
  if (compact) {
    return <LogoIcon size={26} className={className} />
  }
  return (
    <div className={className} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <LogoIcon size={26} />
      <span style={{
        fontFamily: "'Orbitron', sans-serif",
        fontSize: 13,
        fontWeight: 800,
        letterSpacing: '0.18em',
        textTransform: 'uppercase' as const,
        lineHeight: 1,
        background: 'linear-gradient(180deg, #FFFFFF 0%, #CBD5E1 40%, #475569 100%)',
        WebkitBackgroundClip: 'text',
        WebkitTextFillColor: 'transparent',
        backgroundClip: 'text',
        whiteSpace: 'nowrap',
      }}>
        NEURASHIELD
      </span>
    </div>
  )
}

export default LogoFull
