interface LogoIconProps {
  size?: number;
  className?: string;
}

interface LogoFullProps {
  size?: number;
  showSubtitle?: boolean;
  className?: string;
}

export function LogoIcon({ size = 36, className = "" }: LogoIconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 40 40"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      <defs>
        <linearGradient id="shield-grad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#3B82F6" />
          <stop offset="100%" stopColor="#38BDF8" />
        </linearGradient>
        <linearGradient id="node-grad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#60A5FA" />
          <stop offset="100%" stopColor="#38BDF8" />
        </linearGradient>
        <filter id="glow">
          <feGaussianBlur stdDeviation="1" result="coloredBlur" />
          <feMerge>
            <feMergeNode in="coloredBlur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Shield shape */}
      <path
        d="M20 3L5 9.5V20.5C5 28.5 11.5 35.5 20 38C28.5 35.5 35 28.5 35 20.5V9.5L20 3Z"
        fill="url(#shield-grad)"
        fillOpacity="0.15"
        stroke="url(#shield-grad)"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />

      {/* Neural network nodes */}
      <circle cx="20" cy="14" r="2.5" fill="url(#node-grad)" filter="url(#glow)" />
      <circle cx="13" cy="22" r="2"   fill="url(#node-grad)" filter="url(#glow)" />
      <circle cx="27" cy="22" r="2"   fill="url(#node-grad)" filter="url(#glow)" />
      <circle cx="20" cy="29" r="2"   fill="url(#node-grad)" filter="url(#glow)" />

      {/* Neural network connections */}
      <line x1="20" y1="14" x2="13" y2="22" stroke="#3B82F6" strokeWidth="0.8" strokeOpacity="0.7" />
      <line x1="20" y1="14" x2="27" y2="22" stroke="#3B82F6" strokeWidth="0.8" strokeOpacity="0.7" />
      <line x1="13" y1="22" x2="20" y2="29" stroke="#38BDF8" strokeWidth="0.8" strokeOpacity="0.7" />
      <line x1="27" y1="22" x2="20" y2="29" stroke="#38BDF8" strokeWidth="0.8" strokeOpacity="0.7" />
      <line x1="13" y1="22" x2="27" y2="22" stroke="#3B82F6" strokeWidth="0.5" strokeOpacity="0.4" />
      <line x1="20" y1="14" x2="20" y2="29" stroke="#38BDF8" strokeWidth="0.5" strokeOpacity="0.3" />
    </svg>
  );
}

export function LogoFull({ size = 36, showSubtitle = false, className = "" }: LogoFullProps) {
  const textScale = size / 36;

  return (
    <div className={`flex items-center gap-2.5 ${className}`}>
      <LogoIcon size={size} />
      <div className="flex flex-col leading-none">
        <div
          className="font-display font-bold tracking-wide"
          style={{ fontSize: `${Math.round(textScale * 17)}px`, lineHeight: 1.1 }}
        >
          <span className="text-white">NEURA</span>
          <span style={{ color: "#60A5FA" }}>SHIELD</span>
        </div>
        {showSubtitle && (
          <span
            className="text-text-muted font-sans tracking-wider uppercase"
            style={{ fontSize: `${Math.round(textScale * 8)}px`, marginTop: 3 }}
          >
            AI-Powered Threat Intelligence
          </span>
        )}
      </div>
    </div>
  );
}
