import { Activity, CheckCircle, AlertOctagon, VolumeX, RefreshCw } from "lucide-react";
import { WidgetRefreshButton } from "./KPICard";
import { SkeletonText } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/ui/EmptyState";
import { useDetectionHealth } from "@/features/dashboard/hooks/useDashboardData";
import type { DashboardTimeRange, DetectionRuleHealth } from "@/features/dashboard/types/dashboard";

// ─── Status stat pill ─────────────────────────────────────────────────────────

function StatPill({
  icon,
  label,
  value,
  variant,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  variant: "success" | "warning" | "error" | "muted";
}) {
  const colors = {
    success: { text: "#10B981", bg: "rgba(16,185,129,0.08)", border: "rgba(16,185,129,0.2)" },
    warning: { text: "#F59E0B", bg: "rgba(245,158,11,0.08)", border: "rgba(245,158,11,0.2)" },
    error:   { text: "#EF4444", bg: "rgba(239,68,68,0.08)",  border: "rgba(239,68,68,0.2)"  },
    muted:   { text: "#5C6373", bg: "rgba(255,255,255,0.03)", border: "rgba(255,255,255,0.07)" },
  }[variant];

  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center", gap: 3,
      padding: "8px 4px", borderRadius: 8,
      background: colors.bg, border: `1px solid ${colors.border}`,
    }}>
      <span style={{ color: colors.text, display: "flex", alignItems: "center" }}>
        {icon}
      </span>
      <span style={{
        fontSize: 15, fontWeight: 700, color: colors.text,
        fontFamily: "'JetBrains Mono', monospace", lineHeight: 1,
      }}>
        {value.toLocaleString()}
      </span>
      <span style={{ fontSize: 9, color: "#5C6373", textTransform: "uppercase", letterSpacing: "0.5px" }}>
        {label}
      </span>
    </div>
  );
}

// ─── Rule row with inline progress bar ───────────────────────────────────────

const STATUS_COLOR: Record<DetectionRuleHealth["status"], string> = {
  active:   "#10B981",
  noisy:    "#F59E0B",
  error:    "#EF4444",
  disabled: "#374151",
};

function RuleBar({ rule, maxCount }: { rule: DetectionRuleHealth; maxCount: number }) {
  const pct = maxCount > 0 ? Math.max(2, (rule.triggeredCount / maxCount) * 100) : 0;
  const color = STATUS_COLOR[rule.status];

  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 8,
      padding: "5px 0",
      borderBottom: "1px solid rgba(255,255,255,0.04)",
    }}>
      {/* Status dot */}
      <div style={{
        width: 6, height: 6, borderRadius: "50%",
        background: color, flexShrink: 0,
        boxShadow: rule.status !== "disabled" ? `0 0 4px ${color}60` : "none",
      }} />

      {/* Rule name */}
      <span style={{
        flex: 1, fontSize: 11, color: "#8B95A7",
        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
        lineHeight: 1.3,
      }}>
        {rule.ruleName}
      </span>

      {/* Progress bar */}
      <div style={{
        width: 44, height: 3, background: "rgba(255,255,255,0.06)",
        borderRadius: 2, flexShrink: 0, overflow: "hidden",
      }}>
        <div style={{
          width: `${pct}%`, height: "100%",
          background: color, borderRadius: 2,
          transition: "width 400ms ease",
        }} />
      </div>

      {/* Count */}
      <span style={{
        width: 28, textAlign: "right", flexShrink: 0,
        fontSize: 11, fontWeight: 600, color: rule.triggeredCount > 0 ? "#F5F7FA" : "#374151",
        fontFamily: "'JetBrains Mono', monospace",
      }}>
        {rule.triggeredCount.toLocaleString()}
      </span>
    </div>
  );
}

// ─── DetectionHealthWidget ────────────────────────────────────────────────────

export function DetectionHealthWidget({ timeRange }: { timeRange: DashboardTimeRange }) {
  const { data, isLoading, isRefetching, isError, refetch } = useDetectionHealth(timeRange);

  const topRules  = data?.topRules?.slice(0, 8) ?? [];
  const maxCount  = topRules.reduce((m, r) => Math.max(m, r.triggeredCount), 0);

  return (
    <div className="card flex flex-col h-full">

      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <Activity className="w-3.5 h-3.5 text-accent" />
          <h3 className="text-sm font-semibold text-text-primary">Detection Health</h3>
        </div>
        <WidgetRefreshButton onClick={() => void refetch()} isRefetching={isRefetching} isError={isError} />
      </div>

      <div style={{ flex: 1, padding: "12px 14px", display: "flex", flexDirection: "column", gap: 12, minHeight: 0, overflowY: "auto" }}>

        {/* Status pills */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 6 }}>
          <StatPill
            icon={<CheckCircle size={12} />}
            label="Active"
            value={data?.activeRules ?? 0}
            variant="success"
          />
          <StatPill
            icon={<VolumeX size={12} />}
            label="Noisy"
            value={data?.noisyRules ?? 0}
            variant="warning"
          />
          <StatPill
            icon={<AlertOctagon size={12} />}
            label="Error"
            value={data?.errorRules ?? 0}
            variant="error"
          />
          <StatPill
            icon={<RefreshCw size={12} />}
            label="Off"
            value={data?.disabledRules ?? 0}
            variant="muted"
          />
        </div>

        {/* Avg latency */}
        {data && data.avgLatencyMs > 0 && (
          <div style={{
            display: "flex", alignItems: "center", justifyContent: "space-between",
            padding: "6px 0",
            borderTop: "1px solid rgba(255,255,255,0.05)",
            borderBottom: "1px solid rgba(255,255,255,0.05)",
          }}>
            <span style={{ fontSize: 11, color: "#5C6373" }}>Avg detect latency</span>
            <span style={{ fontSize: 11, fontWeight: 600, color: "#8B95A7", fontFamily: "'JetBrains Mono', monospace" }}>
              {data.avgLatencyMs >= 1000
                ? `${(data.avgLatencyMs / 1000).toFixed(1)}s`
                : `${data.avgLatencyMs}ms`}
            </span>
          </div>
        )}

        {/* Top triggered rules */}
        <div style={{ flex: 1 }}>
          <div style={{
            display: "flex", alignItems: "center", justifyContent: "space-between",
            marginBottom: 8,
          }}>
            <span style={{
              fontSize: 9, fontWeight: 700, color: "#5C6373",
              textTransform: "uppercase", letterSpacing: "0.8px",
              fontFamily: "'JetBrains Mono', monospace",
            }}>
              Top Triggered Rules
            </span>
            <span style={{
              fontSize: 9, color: "#374151",
              fontFamily: "'JetBrains Mono', monospace",
            }}>
              HITS
            </span>
          </div>

          {isLoading ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {Array.from({ length: 5 }).map((_, i) => (
                <SkeletonText key={i} lines={1} />
              ))}
            </div>
          ) : topRules.length === 0 ? (
            <EmptyState
              icon={<Activity className="w-5 h-5" />}
              title="No rule activity"
              description="No rules triggered in this period."
              className="py-4"
            />
          ) : (
            <div>
              {topRules.map((rule) => (
                <RuleBar key={rule.ruleId} rule={rule} maxCount={maxCount} />
              ))}
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
