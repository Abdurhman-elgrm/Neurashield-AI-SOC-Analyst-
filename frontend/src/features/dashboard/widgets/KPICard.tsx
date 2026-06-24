import { useEffect, useRef, useState } from "react";
import { TrendingUp, TrendingDown, Minus, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";

// ─── Animated counter ─────────────────────────────────────────────────────────

function useCountUp(target: number, duration = 500) {
  const [value, setValue] = useState(target);
  const prevRef = useRef(target);

  useEffect(() => {
    const start = prevRef.current;
    const end = target;
    if (start === end) return;

    const startTime = performance.now();

    const tick = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setValue(Math.round(start + (end - start) * eased));
      if (progress < 1) requestAnimationFrame(tick);
    };

    requestAnimationFrame(tick);
    prevRef.current = target;
  }, [target, duration]);

  return value;
}

// ─── Trend indicator ──────────────────────────────────────────────────────────

function TrendBadge({ delta }: { delta: number }) {
  if (delta === 0) {
    return (
      <span className="inline-flex items-center gap-0.5 text-xs text-text-muted">
        <Minus className="w-3 h-3" /> 0%
      </span>
    );
  }

  const isUp = delta > 0;
  const pct  = Math.abs(delta).toFixed(0);

  return (
    <span className={cn(
      "inline-flex items-center gap-0.5 text-xs font-medium",
      isUp ? "text-severity-critical" : "text-severity-low"
    )}>
      {isUp ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
      {pct}%
    </span>
  );
}

// ─── Variant → color token ────────────────────────────────────────────────────

const VARIANT_COLOR: Record<NonNullable<KPICardProps["colorVariant"]>, string> = {
  default:  "#5C6373",
  accent:   "#3B82F6",
  critical: "#EF4444",
  high:     "#F97316",
  medium:   "#F59E0B",
  low:      "#10B981",
};

// ─── KPICard ──────────────────────────────────────────────────────────────────

export interface KPICardProps {
  label: string;
  value: number;
  delta?: number;
  deltaPercent?: number;
  icon: React.ReactNode;
  isLoading?: boolean;
  isLive?: boolean;
  colorVariant?: "default" | "critical" | "high" | "medium" | "low" | "accent";
  suffix?: string;
  formatter?: (v: number) => string;
  onClick?: () => void;
}

export function KPICard({
  label,
  value,
  deltaPercent,
  icon,
  isLoading = false,
  isLive = false,
  colorVariant = "default",
  suffix,
  formatter,
  onClick,
}: KPICardProps) {
  const animatedValue = useCountUp(value);
  const displayValue  = formatter ? formatter(animatedValue) : animatedValue.toLocaleString();
  const color         = VARIANT_COLOR[colorVariant];

  if (isLoading) return <KPICardSkeleton />;

  return (
    <button
      onClick={onClick}
      disabled={!onClick}
      style={{
        display: "flex", flexDirection: "column", width: "100%",
        background: "#0D0D0D",
        border: "1px solid rgba(255,255,255,0.06)",
        borderLeft: `3px solid ${color}`,
        borderRadius: 8,
        padding: "12px 14px",
        textAlign: "left",
        cursor: onClick ? "pointer" : "default",
        transition: "border-color 120ms, background 120ms",
        position: "relative",
        overflow: "hidden",
      }}
      onMouseEnter={e => {
        if (!onClick) return;
        (e.currentTarget as HTMLButtonElement).style.background = "rgba(255,255,255,0.018)";
        (e.currentTarget as HTMLButtonElement).style.borderColor = `rgba(255,255,255,0.10)`;
      }}
      onMouseLeave={e => {
        (e.currentTarget as HTMLButtonElement).style.background = "#0D0D0D";
        (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(255,255,255,0.06)";
      }}
    >
      {/* Subtle glow for critical/high */}
      {(colorVariant === "critical" || colorVariant === "high") && value > 0 && (
        <div style={{
          position: "absolute", inset: 0, pointerEvents: "none",
          background: `radial-gradient(ellipse at 0% 50%, ${color}06 0%, transparent 60%)`,
        }} />
      )}

      {/* Label row */}
      <div style={{ display: "flex", alignItems: "center", gap: 5, marginBottom: 8 }}>
        <span style={{ color, display: "flex", alignItems: "center", flexShrink: 0, opacity: 0.85 }}>
          {icon}
        </span>
        <span style={{
          fontSize: 9, fontWeight: 700, textTransform: "uppercase",
          letterSpacing: "1.2px", color: "#5C6373",
          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
        }}>
          {label}
        </span>
        {isLive && (
          <span style={{
            marginLeft: "auto", width: 6, height: 6, borderRadius: "50%",
            background: "#10B981", flexShrink: 0,
            boxShadow: "0 0 6px #10B981",
            animation: "pulse 2s ease-in-out infinite",
          }} />
        )}
      </div>

      {/* Value */}
      <div style={{ display: "flex", alignItems: "baseline", gap: 5, lineHeight: 1 }}>
        <span style={{
          fontSize: 28, fontWeight: 800, color,
          fontFamily: "'JetBrains Mono', monospace",
          lineHeight: 1, letterSpacing: "-0.5px",
        }}>
          {displayValue}
        </span>
        {suffix && (
          <span style={{ fontSize: 13, color: "#5C6373", fontFamily: "'JetBrains Mono', monospace" }}>
            {suffix}
          </span>
        )}
      </div>

      {/* Delta */}
      {deltaPercent !== undefined && (
        <div style={{ marginTop: 6, display: "flex", alignItems: "center", gap: 4 }}>
          <TrendBadge delta={deltaPercent} />
          <span style={{ fontSize: 9, color: "#3A4150" }}>vs prev</span>
        </div>
      )}
    </button>
  );
}

// ─── KPICardSkeleton ──────────────────────────────────────────────────────────

export function KPICardSkeleton() {
  return (
    <div style={{
      background: "#0D0D0D", border: "1px solid rgba(255,255,255,0.06)",
      borderLeft: "3px solid rgba(255,255,255,0.06)",
      borderRadius: 8, padding: "12px 14px",
    }}>
      <div className="skel" style={{ height: 9, width: 70, borderRadius: 4, marginBottom: 10 }} />
      <div className="skel" style={{ height: 28, width: 56, borderRadius: 4, marginBottom: 8 }} />
      <div className="skel" style={{ height: 9, width: 40, borderRadius: 4 }} />
    </div>
  );
}

// ─── Refresh button ───────────────────────────────────────────────────────────

export function WidgetRefreshButton({
  onClick,
  isRefetching,
  isError = false,
}: {
  onClick: () => void;
  isRefetching: boolean;
  isError?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "p-1 rounded transition-colors",
        isError
          ? "text-severity-medium hover:text-severity-high hover:bg-severity-medium/10"
          : "text-text-muted hover:text-text-primary hover:bg-bg-subtle"
      )}
      title={isError ? "Data unavailable — click to retry" : "Refresh"}
      aria-label={isError ? "Data unavailable — click to retry" : "Refresh"}
    >
      <RefreshCw className={cn("w-3.5 h-3.5", isRefetching && "animate-spin")} />
    </button>
  );
}
