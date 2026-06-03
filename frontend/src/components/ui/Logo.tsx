interface LogoProps {
  size?: number
  showText?: boolean
  showSubtitle?: boolean
  className?: string
}

// viewBox is 180×112 — wide to hold the horizontal light beams
// ring center: cx=90 cy=56 r=38
// beam zones: left 0→52, right 128→180
// dots: top cy=5, bottom cy=107

export function LogoIcon({
  size = 44,
  compact = false,
  className = '',
}: {
  size?: number
  compact?: boolean
  className?: string
}) {
  // compact=true crops the long beams → nearly-square, fits sidebar
  // compact=false shows the full wide composition with beams
  const vb   = compact ? '34 0 112 112' : '0 0 180 112'
  const ratio = compact ? (112 / 112)   : (180 / 112)
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
        {/* Ring bloom — 4 levels of glow, outermost to tightest */}
        <filter id="logo-bloom-xl" x="-60%" y="-60%" width="220%" height="220%">
          <feGaussianBlur stdDeviation="9" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <filter id="logo-bloom-lg" x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur stdDeviation="5" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <filter id="logo-bloom-md" x="-25%" y="-25%" width="150%" height="150%">
          <feGaussianBlur stdDeviation="2.5" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <filter id="logo-bloom-sm" x="-15%" y="-15%" width="130%" height="130%">
          <feGaussianBlur stdDeviation="1.2" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>

        {/* Dot glow */}
        <filter id="logo-dot-bloom" x="-250%" y="-250%" width="600%" height="600%">
          <feGaussianBlur stdDeviation="3" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>

        {/* Beam soft-glow layer (blur only, no merge — creates soft halo) */}
        <filter id="logo-beam-glow" x="-15%" y="-300%" width="130%" height="700%">
          <feGaussianBlur stdDeviation="2.5"/>
        </filter>

        {/* Beam gradients — fade transparent→bright toward ring edge */}
        <linearGradient id="logo-bl" x1="0" y1="0" x2="52" y2="0" gradientUnits="userSpaceOnUse">
          <stop offset="0%"   stopColor="white" stopOpacity="0"/>
          <stop offset="75%"  stopColor="white" stopOpacity="0.55"/>
          <stop offset="100%" stopColor="white" stopOpacity="0.85"/>
        </linearGradient>
        <linearGradient id="logo-br" x1="128" y1="0" x2="180" y2="0" gradientUnits="userSpaceOnUse">
          <stop offset="0%"   stopColor="white" stopOpacity="0.85"/>
          <stop offset="25%"  stopColor="white" stopOpacity="0.55"/>
          <stop offset="100%" stopColor="white" stopOpacity="0"/>
        </linearGradient>
      </defs>

      {/* ── LEFT BEAM ─────────────────────────────────────────────── */}
      {/* soft glow layer */}
      <rect x="0" y="50" width="52" height="12"
        fill="url(#logo-bl)" opacity="0.4" filter="url(#logo-beam-glow)"/>
      {/* bright core */}
      <rect x="0" y="54.5" width="52" height="3"
        fill="url(#logo-bl)" opacity="0.9"/>

      {/* ── RIGHT BEAM ────────────────────────────────────────────── */}
      <rect x="128" y="50" width="52" height="12"
        fill="url(#logo-br)" opacity="0.4" filter="url(#logo-beam-glow)"/>
      <rect x="128" y="54.5" width="52" height="3"
        fill="url(#logo-br)" opacity="0.9"/>

      {/* ── RING — outermost atmospheric halo ─────────────────────── */}
      <circle cx="90" cy="56" r="38"
        stroke="white" strokeWidth="28" fill="none"
        opacity="0.03" filter="url(#logo-bloom-xl)"/>
      {/* wide bloom */}
      <circle cx="90" cy="56" r="38"
        stroke="white" strokeWidth="14" fill="none"
        opacity="0.07" filter="url(#logo-bloom-lg)"/>
      {/* medium glow */}
      <circle cx="90" cy="56" r="38"
        stroke="white" strokeWidth="7" fill="none"
        opacity="0.2" filter="url(#logo-bloom-md)"/>
      {/* inner-edge glow (slightly inside — creates the inward-bright look) */}
      <circle cx="90" cy="56" r="35"
        stroke="white" strokeWidth="5" fill="none"
        opacity="0.22" filter="url(#logo-bloom-md)"/>
      {/* tight near-core glow */}
      <circle cx="90" cy="56" r="38"
        stroke="white" strokeWidth="2" fill="none"
        opacity="0.6" filter="url(#logo-bloom-sm)"/>
      {/* core line — thin, near-full opacity */}
      <circle cx="90" cy="56" r="38"
        stroke="white" strokeWidth="1.4" fill="none"
        opacity="0.95"/>

      {/* ── DOTS ──────────────────────────────────────────────────── */}
      {/* top dot (13px above ring edge at cy=18) */}
      <circle cx="90" cy="5"   r="2.5" fill="white" filter="url(#logo-dot-bloom)"/>
      {/* bottom dot (13px below ring edge at cy=94) */}
      <circle cx="90" cy="107" r="2.5" fill="white" filter="url(#logo-dot-bloom)"/>

      {/* center point — very subtle */}
      <circle cx="90" cy="56" r="1.4" fill="white" opacity="0.38"/>
    </svg>
  )
}

export function LogoFull({ size = 44, className = '' }: LogoProps) {
  return (
    <div className={className} style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
      <LogoIcon size={size} />
      <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        <span style={{
          fontFamily: "'Orbitron', sans-serif",
          fontSize: 16,
          fontWeight: 800,
          letterSpacing: '0.22em',
          textTransform: 'uppercase' as const,
          lineHeight: 1,
          background: 'linear-gradient(180deg, #E2E8F0 0%, #94A3B8 45%, #334155 100%)',
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
      <LogoIcon size={54} compact />
      <span style={{
        fontFamily: "'Orbitron', sans-serif",
        fontSize: 17,
        fontWeight: 800,
        letterSpacing: '0.16em',
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
