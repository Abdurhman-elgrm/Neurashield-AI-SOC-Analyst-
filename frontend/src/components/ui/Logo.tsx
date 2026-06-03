interface LogoProps {
  size?: number
  showText?: boolean
  showSubtitle?: boolean
  className?: string
}

// ─── Geometry ─────────────────────────────────────────────────────────────────
// viewBox  : 0 0 180 112   (full — with beams)
// Ring     : cx=90 cy=56 r=38
// Ring edges: x=52 (left)  x=128 (right)
// Beams    : 38px each side  — same length as ring radius
//            left  x=14→52   right x=128→166
// Dots     : cy=5 (top)  cy=107 (bottom)  — 13px outside ring edge
// compact  : clips viewBox to "34 0 112 112" → nearly-square for sidebar

export function LogoIcon({
  size = 44,
  compact = false,
  className = '',
}: {
  size?: number
  compact?: boolean
  className?: string
}) {
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
        {/* Wide atmospheric — stays near ring, centre stays dark */}
        <filter id="lg-halo" x="-35%" y="-35%" width="170%" height="170%">
          <feGaussianBlur stdDeviation="6" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        {/* Medium glow */}
        <filter id="lg-glow" x="-18%" y="-18%" width="136%" height="136%">
          <feGaussianBlur stdDeviation="2.8" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        {/* Tight edge-hug */}
        <filter id="lg-edge" x="-10%" y="-10%" width="120%" height="120%">
          <feGaussianBlur stdDeviation="1.0" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        {/* Dot bloom */}
        <filter id="lg-dot" x="-250%" y="-250%" width="600%" height="600%">
          <feGaussianBlur stdDeviation="2.0" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        {/* Beam haze — blur only (pure spread behind the 1px line) */}
        <filter id="lg-beam" x="-5%" y="-400%" width="110%" height="900%">
          <feGaussianBlur stdDeviation="1.4"/>
        </filter>

        {/* ── Beam gradients (38px length = ring radius) ── */}
        {/* Left:  transparent at x=14  →  bright at x=52 (ring edge) */}
        <linearGradient id="lg-bl" x1="14" y1="0" x2="52" y2="0" gradientUnits="userSpaceOnUse">
          <stop offset="0%"   stopColor="white" stopOpacity="0"/>
          <stop offset="100%" stopColor="white" stopOpacity="0.75"/>
        </linearGradient>
        {/* Right: bright at x=128 (ring edge)  →  transparent at x=166 */}
        <linearGradient id="lg-br" x1="128" y1="0" x2="166" y2="0" gradientUnits="userSpaceOnUse">
          <stop offset="0%"   stopColor="white" stopOpacity="0.75"/>
          <stop offset="100%" stopColor="white" stopOpacity="0"/>
        </linearGradient>
      </defs>

      {/* ── LEFT BEAM ─────────────────────────────────────────────── */}
      {/* soft spread */}
      <rect x="14" y="52.5" width="38" height="7"
        fill="url(#lg-bl)" opacity="0.22" filter="url(#lg-beam)"/>
      {/* 1 px bright line */}
      <rect x="14" y="55.3" width="38" height="1.4"
        fill="url(#lg-bl)" opacity="0.85"/>

      {/* ── RIGHT BEAM ────────────────────────────────────────────── */}
      <rect x="128" y="52.5" width="38" height="7"
        fill="url(#lg-br)" opacity="0.22" filter="url(#lg-beam)"/>
      <rect x="128" y="55.3" width="38" height="1.4"
        fill="url(#lg-br)" opacity="0.85"/>

      {/* ── RING ──────────────────────────────────────────────────── */}
      {/* Layer 1 — wide atmospheric halo (thin stroke: blur can't reach centre) */}
      <circle cx="90" cy="56" r="38"
        stroke="white" strokeWidth="9" fill="none"
        opacity="0.07" filter="url(#lg-halo)"/>
      {/* Layer 2 — medium glow */}
      <circle cx="90" cy="56" r="38"
        stroke="white" strokeWidth="4" fill="none"
        opacity="0.22" filter="url(#lg-glow)"/>
      {/* Layer 3 — tight edge glow */}
      <circle cx="90" cy="56" r="38"
        stroke="white" strokeWidth="2" fill="none"
        opacity="0.55" filter="url(#lg-edge)"/>
      {/* Layer 4 — crisp core line */}
      <circle cx="90" cy="56" r="38"
        stroke="white" strokeWidth="1.2" fill="none"
        opacity="1"/>

      {/* ── DOTS ──────────────────────────────────────────────────── */}
      {/* Top dot — 13 px above ring edge */}
      <circle cx="90" cy="5"   r="2.2" fill="white" filter="url(#lg-dot)"/>
      {/* Bottom dot — 13 px below ring edge */}
      <circle cx="90" cy="107" r="2.2" fill="white" filter="url(#lg-dot)"/>

      {/* Centre mark — barely perceptible */}
      <circle cx="90" cy="56" r="1.0" fill="white" opacity="0.28"/>
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
