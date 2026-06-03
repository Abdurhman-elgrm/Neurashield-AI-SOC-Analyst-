import { useEffect, useRef, useState } from "react";
import { TrendingUp, TrendingDown, Minus, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/Skeleton";

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
      const eased = 1 - Math.pow(1 - progress, 3); // cubic ease-out
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
  const pct = Math.abs(delta).toFixed(0);

  return (
    <span
      className={cn(
        "inline-flex items-center gap-0.5 text-xs font-medium",
        isUp ? "text-severity-critical" : "text-severity-low"
      )}
    >
      {isUp ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
      {pct}%
    </span>
  );
}

// ─── KPICard ─────────────────────────────────────────────────────────────────

export interface KPICardProps {
  label: string;
  value: number;
  delta?: number;           // absolute change; we show % only when formatDelta is provided
  deltaPercent?: number;    // percentage change for trend badge
  icon: React.ReactNode;
  isLoading?: boolean;
  isLive?: boolean;         // shows a pulse indicator
  colorVariant?: "default" | "critical" | "high" | "medium" | "low" | "accent";
  suffix?: string;
  formatter?: (v: number) => string;
  onClick?: () => void;
}

const VARIANT_STYLES: Record<NonNullable<KPICardProps["colorVariant"]>, string> = {
  default:  "border-border",
  accent:   "border-primary-600/30",
  critical: "border-severity-critical/40",
  high:     "border-severity-high/30",
  medium:   "border-severity-medium/30",
  low:      "border-severity-low/30",
};

const VARIANT_GLOW: Record<NonNullable<KPICardProps["colorVariant"]>, string> = {
  default:  "",
  accent:   "0 0 20px rgba(59,130,246,0.12)",
  critical: "0 0 20px rgba(248,113,113,0.12)",
  high:     "0 0 16px rgba(251,146,60,0.1)",
  medium:   "",
  low:      "0 0 16px rgba(52,211,153,0.08)",
};

const VARIANT_ICON_BG: Record<NonNullable<KPICardProps["colorVariant"]>, string> = {
  default:  "bg-bg-subtle text-text-muted",
  accent:   "bg-primary-600/15 text-primary-400",
  critical: "bg-severity-critical/10 text-severity-critical",
  high:     "bg-severity-high/10 text-severity-high",
  medium:   "bg-severity-medium/10 text-severity-medium",
  low:      "bg-severity-low/10 text-severity-low",
};

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
  const displayValue = formatter ? formatter(animatedValue) : animatedValue.toLocaleString();

  if (isLoading) {
    return (
      <div className="card p-4">
        <Skeleton className="h-4 w-24 mb-3" />
        <Skeleton className="h-8 w-16 mb-2" />
        <Skeleton className="h-3 w-12" />
      </div>
    );
  }

  return (
    <button
      onClick={onClick}
      className={cn(
        "card p-4 text-left w-full transition-all",
        "hover:bg-bg-elevated/80 hover:border-border-strong",
        VARIANT_STYLES[colorVariant],
        onClick && "cursor-pointer"
      )}
      style={VARIANT_GLOW[colorVariant] ? { boxShadow: VARIANT_GLOW[colorVariant] } : undefined}
    >
      <div className="flex items-start justify-between mb-3">
        <div className={cn("w-8 h-8 rounded-md flex items-center justify-center flex-shrink-0", VARIANT_ICON_BG[colorVariant])}>
          {icon}
        </div>
        {isLive && (
          <span className="flex items-center gap-1 text-2xs text-status-online">
            <span className="w-1.5 h-1.5 bg-status-online rounded-full animate-pulse" />
            Live
          </span>
        )}
      </div>

      <div className="space-y-0.5">
        <p className="text-2xs text-text-muted font-medium uppercase tracking-wider">{label}</p>
        <div className="flex items-baseline gap-1">
          <span className="text-2xl font-bold text-text-primary tabular-nums">{displayValue}</span>
          {suffix && <span className="text-sm text-text-muted">{suffix}</span>}
        </div>
      </div>

      {deltaPercent !== undefined && (
        <div className="mt-2">
          <TrendBadge delta={deltaPercent} />
          <span className="ml-1 text-2xs text-text-muted">vs prev period</span>
        </div>
      )}
    </button>
  );
}

// ─── KPICardSkeleton ──────────────────────────────────────────────────────────

export function KPICardSkeleton() {
  return (
    <div className="card p-4 animate-pulse">
      <div className="flex items-start justify-between mb-3">
        <div className="w-8 h-8 rounded-md bg-bg-subtle" />
      </div>
      <div className="space-y-1.5">
        <div className="h-3 w-20 rounded bg-bg-subtle" />
        <div className="h-7 w-14 rounded bg-bg-subtle" />
        <div className="h-3 w-12 rounded bg-bg-subtle" />
      </div>
    </div>
  );
}

// ─── Refresh button ───────────────────────────────────────────────────────────

export function WidgetRefreshButton({
  onClick,
  isRefetching,
}: {
  onClick: () => void;
  isRefetching: boolean;
}) {
  return (
    <button
      onClick={onClick}
      className="p-1 rounded text-text-muted hover:text-text-primary hover:bg-bg-subtle transition-colors"
      aria-label="Refresh"
    >
      <RefreshCw className={cn("w-3.5 h-3.5", isRefetching && "animate-spin")} />
    </button>
  );
}
