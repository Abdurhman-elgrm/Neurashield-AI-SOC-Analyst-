interface LogoProps {
  size?: number
  showText?: boolean
  showSubtitle?: boolean
  className?: string
}

export function LogoIcon({
  size = 44,
  compact = false,
  className = '',
}: {
  size?: number
  compact?: boolean
  className?: string
}) {
  // size controls HEIGHT. compact mode clips long beams → ~square, fits sidebar.
  const vb    = compact ? '34 0 112 112' : '0 0 180 112'
  const ratio = compact ? 1.0 : (180 / 112)
  const w = size * ratio

  return (
    <svg
      width={w}
      height={size}
      viewBox={vb}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      <defs>
        {/* Atmospheric halo — wide, very faint, stays outside the ring stroke */}
        <filter id="logo-bloom-lg" x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur stdDeviation="5" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        {/* Medium glow */}
        <filter id="logo-bloom-md" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="2.5" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        {/* Tight near-core glow */}
        <filter id="logo-bloom-sm" x="-12%" y="-12%" width="124%" height="124%">
          <feGaussianBlur stdDeviation="1.1" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        {/* Dot glow */}
        <filter id="logo-dot" x="-200%" y="-200%" width="500%" height="500%">
          <feGaussianBlur stdDeviation="2.2" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        {/* Beam soft spread — blur only, no merge (just a haze behind the line) */}
        <filter id="logo-beam" x="-5%" y="-300%" width="110%" height="700%">
          <feGaussianBlur stdDeviation="1.8"/>
        </filter>

        {/* Beam gradients — fade in from edges toward ring */}
        <linearGradient id="logo-bl" x1="0" y1="0" x2="52" y2="0" gradientUnits="userSpaceOnUse">
          <stop offset="0%"   stopColor="white" stopOpacity="0"/>
          <stop offset="65%"  stopColor="white" stopOpacity="0.35"/>
          <stop offset="100%" stopColor="white" stopOpacity="0.7"/>
        </linearGradient>
        <linearGradient id="logo-br" x1="128" y1="0" x2="180" y2="0" gradientUnits="userSpaceOnUse">
          <stop offset="0%"   stopColor="white" stopOpacity="0.7"/>
          <stop offset="35%"  stopColor="white" stopOpacity="0.35"/>
          <stop offset="100%" stopColor="white" stopOpacity="0"/>
        </linearGradient>
      </defs>

      {/* ── BEAMS — 1px core + very subtle haze ──────────────────── */}
      <rect x="0"   y="53.5" width="52" height="5"
        fill="url(#logo-bl)" opacity="0.18" filter="url(#logo-beam)"/>
      <rect x="0"   y="55.3" width="52" height="1.4"
        fill="url(#logo-bl)" opacity="0.8"/>

      <rect x="128" y="53.5" width="52" height="5"
        fill="url(#logo-br)" opacity="0.18" filter="url(#logo-beam)"/>
      <rect x="128" y="55.3" width="52" height="1.4"
        fill="url(#logo-br)" opacity="0.8"/>

      {/* ── RING — 3 layers only, thin strokes keep center dark ───── */}
      {/* 1. Atmospheric outer halo (thin stroke = blur stays outside ring) */}
      <circle cx="90" cy="56" r="38"
        stroke="white" strokeWidth="7" fill="none"
        opacity="0.08" filter="url(#logo-bloom-lg)"/>
      {/* 2. Clean medium glow */}
      <circle cx="90" cy="56" r="38"
        stroke="white" strokeWidth="3.5" fill="none"
        opacity="0.28" filter="url(#logo-bloom-md)"/>
      {/* 3. Tight bright halo */}
      <circle cx="90" cy="56" r="38"
        stroke="white" strokeWidth="1.8" fill="none"
        opacity="0.65" filter="url(#logo-bloom-sm)"/>
      {/* 4. Crisp core line */}
      <circle cx="90" cy="56" r="38"
        stroke="white" strokeWidth="1.2" fill="none"
        opacity="1"/>

      {/* ── DOTS ─────────────────────────────────────────────────── */}
      <circle cx="90" cy="5"   r="2.2" fill="white" filter="url(#logo-dot)"/>
      <circle cx="90" cy="107" r="2.2" fill="white" filter="url(#logo-dot)"/>

      {/* Center mark — barely visible */}
      <circle cx="90" cy="56" r="1.1" fill="white" opacity="0.3"/>
    </svg>
  )
}

export function LogoFull({ size = 44, className = '' }: LogoProps) {
  return (
    <div className={className} style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
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

export function LogoCompact({ className = '' }: { className?: string }) {
  return (
    <div className={className} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
      <LogoIcon size={56} compact />
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
      }}>
        NEURASHIELD
      </span>
    </div>
  )
}

export default LogoFull
