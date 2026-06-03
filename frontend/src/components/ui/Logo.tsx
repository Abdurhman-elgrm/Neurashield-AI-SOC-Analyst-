// Shield logo — metallic N-mark inside a geometric shield
// viewBox 0 0 48 56  (natural shield proportions, portrait)
// width = size × (48/56),  height = size

interface LogoProps {
  size?: number
  showText?: boolean
  showSubtitle?: boolean
  className?: string
}

const SHIELD = "M24,1.5 L45,9 L45,32 Q45,46 24,54.5 Q3,46 3,32 L3,9 Z"
const FACE   = "M24,5.5 L41,12.5 L41,31.5 Q41,43 24,50.5 Q7,43 7,31.5 L7,12.5 Z"
const N_PATH = "M14.5,17 L19,17 L19,33.5 L29,17 L33.5,17 L33.5,41 L29,41 L29,24.5 L19,41 L14.5,41 Z"

export function LogoIcon({
  size = 44,
  className = '',
}: {
  size?: number
  className?: string
}) {
  const w = size * (48 / 56)
  return (
    <svg
      width={w}
      height={size}
      viewBox="0 0 48 56"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      <defs>
        {/* Shield frame — side-bevel illusion via left→right gradient */}
        <linearGradient id="sh-frame" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%"   stopColor="#060E18"/>
          <stop offset="25%"  stopColor="#122030"/>
          <stop offset="50%"  stopColor="#1E3A56"/>
          <stop offset="75%"  stopColor="#122030"/>
          <stop offset="100%" stopColor="#060E18"/>
        </linearGradient>

        {/* Shield face — lit from top-centre */}
        <radialGradient id="sh-face" cx="50%" cy="22%" r="72%">
          <stop offset="0%"   stopColor="#1E3E60"/>
          <stop offset="45%"  stopColor="#112233"/>
          <stop offset="100%" stopColor="#070E1A"/>
        </radialGradient>

        {/* Top-edge bevel: bright silver-blue strip */}
        <linearGradient id="sh-bevel-top" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stopColor="#6AAED8" stopOpacity="0.95"/>
          <stop offset="100%" stopColor="#6AAED8" stopOpacity="0"/>
        </linearGradient>

        {/* Left-edge bevel highlight */}
        <linearGradient id="sh-bevel-l" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%"   stopColor="#5090BC" stopOpacity="0.7"/>
          <stop offset="100%" stopColor="#5090BC" stopOpacity="0"/>
        </linearGradient>

        {/* Top hotspot — concentrated light reflection */}
        <radialGradient id="sh-hot" cx="50%" cy="0%" r="55%">
          <stop offset="0%"   stopColor="#B0D8F4" stopOpacity="0.55"/>
          <stop offset="100%" stopColor="#B0D8F4" stopOpacity="0"/>
        </radialGradient>

        {/* N mark — steel-blue top to deep blue bottom */}
        <linearGradient id="sh-n" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stopColor="#93C5FD"/>
          <stop offset="40%"  stopColor="#60A5FA"/>
          <stop offset="100%" stopColor="#1D4ED8"/>
        </linearGradient>

        {/* N glow — subtle blue haze behind the mark */}
        <filter id="sh-nglow" x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur stdDeviation="1.8" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>

        {/* Shield outer ambient glow */}
        <filter id="sh-outer" x="-25%" y="-20%" width="150%" height="140%">
          <feGaussianBlur stdDeviation="2.5" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
      </defs>

      {/* ── OUTER AMBIENT GLOW ────────────────────────────────────── */}
      <path d={SHIELD}
        fill="none" stroke="#1E5A8A" strokeWidth="4"
        opacity="0.35" filter="url(#sh-outer)"/>

      {/* ── SHIELD FRAME (outer – inner gap = bevel) ──────────────── */}
      <path d={SHIELD} fill="url(#sh-frame)"/>

      {/* Top-edge bevel highlight */}
      <path d="M24,1.5 L45,9 L41,11 L24,4.5 L7,11 L3,9 Z"
        fill="url(#sh-bevel-top)"/>

      {/* Left-edge bevel highlight */}
      <path d="M3,9 L7,11 L7,31 L3,32 Z"
        fill="url(#sh-bevel-l)"/>

      {/* ── SHIELD FACE ───────────────────────────────────────────── */}
      <path d={FACE} fill="url(#sh-face)"/>

      {/* Face top hotspot */}
      <path d={FACE} fill="url(#sh-hot)"/>

      {/* Subtle inner-edge dark ring for depth */}
      <path d={FACE}
        fill="none" stroke="#000A14" strokeWidth="1.2" opacity="0.5"/>

      {/* ── N LETTERMARK ─────────────────────────────────────────── */}
      <path d={N_PATH} fill="url(#sh-n)" filter="url(#sh-nglow)"/>

      {/* N top-edge highlights (brightest part of each vertical stroke) */}
      <rect x="14.5" y="17" width="4.5" height="2.5"
        fill="rgba(190,225,255,0.55)" rx="0.5"/>
      <rect x="29" y="17" width="4.5" height="2.5"
        fill="rgba(190,225,255,0.55)" rx="0.5"/>

      {/* ── SHIELD OUTER EDGE LINE ────────────────────────────────── */}
      <path d={SHIELD}
        stroke="#2A5F90" strokeWidth="0.7" fill="none" opacity="0.8"/>

      {/* Very bright top-tip glint */}
      <circle cx="24" cy="3.5" r="1.2"
        fill="rgba(180,225,255,0.7)" filter="url(#sh-nglow)"/>
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
      <LogoIcon size={44} />
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
