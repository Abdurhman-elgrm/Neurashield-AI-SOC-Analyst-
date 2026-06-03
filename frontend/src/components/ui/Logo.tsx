const SHIELD = "M4,2 L36,2 Q38,2 38,4 L38,26 Q38,36 20,44 Q2,36 2,26 L2,4 Q2,2 4,2 Z";

interface LogoIconProps {
  size?: number;
}

export function LogoIcon({ size = 36 }: LogoIconProps) {
  const s = size / 46;
  return (
    <svg width={40 * s} height={46 * s} viewBox="0 0 40 46" fill="none">
      <defs>
        <linearGradient id="lg1" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#3B82F6" />
          <stop offset="100%" stopColor="#93C5FD" />
        </linearGradient>
        <linearGradient id="lg2" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#3B82F6" stopOpacity="0.08" />
          <stop offset="100%" stopColor="#93C5FD" stopOpacity="0.04" />
        </linearGradient>
        <filter id="glow-logo">
          <feGaussianBlur stdDeviation="1.2" result="b" />
          <feMerge>
            <feMergeNode in="b" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Shield fill */}
      <path d={SHIELD} fill="url(#lg2)" />
      {/* Shield border */}
      <path d={SHIELD} stroke="url(#lg1)" strokeWidth="1.5" fill="none" />

      {/* Neural network connections */}
      <g stroke="rgba(96,165,250,0.3)" strokeWidth="0.7" strokeLinecap="round">
        <line x1="20" y1="10" x2="12" y2="20" />
        <line x1="20" y1="10" x2="28" y2="20" />
        <line x1="12" y1="20" x2="28" y2="20" />
        <line x1="12" y1="20" x2="16" y2="32" />
        <line x1="28" y1="20" x2="24" y2="32" />
        <line x1="16" y1="32" x2="24" y2="32" />
        <line x1="20" y1="10" x2="16" y2="32" />
        <line x1="20" y1="10" x2="24" y2="32" />
      </g>

      {/* Neural network nodes */}
      <g filter="url(#glow-logo)">
        <circle cx="20" cy="10" r="2.2" fill="#60A5FA" />
        <circle cx="12" cy="20" r="1.6" fill="#3B82F6" />
        <circle cx="28" cy="20" r="1.6" fill="#3B82F6" />
        <circle cx="16" cy="32" r="1.6" fill="#93C5FD" />
        <circle cx="24" cy="32" r="1.6" fill="#93C5FD" />
      </g>
    </svg>
  );
}

interface LogoFullProps {
  size?: number;
  showSubtitle?: boolean;
}

export function LogoFull({ size = 34, showSubtitle = false }: LogoFullProps) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
      <LogoIcon size={size} />
      <div style={{ lineHeight: 1 }}>
        <div style={{
          fontFamily: "'Space Grotesk', sans-serif",
          fontWeight: 700,
          fontSize: 14,
          letterSpacing: "0.18em",
          color: "#F5F7FA",
        }}>
          NEURA<span style={{ color: "#60A5FA" }}>SHIELD</span>
        </div>
        {showSubtitle && (
          <div style={{
            fontSize: 8,
            color: "#3A4150",
            letterSpacing: "0.2em",
            marginTop: 2,
            fontFamily: "'Inter', sans-serif",
            fontWeight: 500,
            textTransform: "uppercase",
          }}>
            AI THREAT INTELLIGENCE
          </div>
        )}
      </div>
    </div>
  );
}
