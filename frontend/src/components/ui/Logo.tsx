interface LogoProps {
  size?: number
  showText?: boolean
  showSubtitle?: boolean
  className?: string
}

export function LogoIcon({ size = 44, className = '' }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size * (48 / 44)}
      viewBox="0 0 44 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      <defs>
        <filter id="ring-glow" x="-30%" y="-30%" width="160%" height="160%">
          <feGaussianBlur stdDeviation="1.8" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <filter id="dot-glow" x="-100%" y="-100%" width="300%" height="300%">
          <feGaussianBlur stdDeviation="1.2" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Outer ring */}
      <circle
        cx="22"
        cy="22"
        r="16"
        stroke="white"
        strokeWidth="1.8"
        fill="none"
        opacity="0.9"
        filter="url(#ring-glow)"
      />

      {/* Top dot */}
      <circle
        cx="22"
        cy="2"
        r="1.8"
        fill="white"
        filter="url(#dot-glow)"
      />

      {/* Bottom dot */}
      <circle
        cx="22"
        cy="42"
        r="1.8"
        fill="white"
        filter="url(#dot-glow)"
      />

      {/* Left tick */}
      <line
        x1="2" y1="22" x2="5" y2="22"
        stroke="white" strokeWidth="1" opacity="0.35"
      />

      {/* Right tick */}
      <line
        x1="39" y1="22" x2="42" y2="22"
        stroke="white" strokeWidth="1" opacity="0.35"
      />

      {/* Center dot (very small, subtle) */}
      <circle cx="22" cy="22" r="1" fill="white" opacity="0.4" />
    </svg>
  )
}

export function LogoFull({ size = 44, className = '' }: LogoProps) {
  return (
    <div
      className={className}
      style={{ display: 'flex', alignItems: 'center', gap: 14 }}
    >
      <LogoIcon size={size} />
      <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        {/* Brand name */}
        <span
          style={{
            fontFamily: "'Inter', system-ui, sans-serif",
            fontSize: 15,
            fontWeight: 700,
            letterSpacing: '0.28em',
            color: '#FFFFFF',
            textTransform: 'uppercase' as const,
            lineHeight: 1,
          }}
        >
          NEURASHIELD
        </span>
        {/* Subtitle */}
        <span
          style={{
            fontFamily: "'Inter', system-ui, sans-serif",
            fontSize: 7,
            fontWeight: 400,
            letterSpacing: '0.28em',
            color: 'rgba(255,255,255,0.3)',
            textTransform: 'uppercase' as const,
            lineHeight: 1,
          }}
        >
          AI POWERED SOC ANALYST PLATFORM
        </span>
      </div>
    </div>
  )
}

// Small variant for sidebar (icon only or compact)
export function LogoCompact({ className = '' }: { className?: string }) {
  return (
    <div
      className={className}
      style={{ display: 'flex', alignItems: 'center', gap: 10 }}
    >
      <LogoIcon size={32} />
      <span
        style={{
          fontFamily: "'Inter', system-ui, sans-serif",
          fontSize: 13,
          fontWeight: 700,
          letterSpacing: '0.28em',
          color: '#FFFFFF',
          textTransform: 'uppercase' as const,
        }}
      >
        NEURASHIELD
      </span>
    </div>
  )
}

export default LogoFull
