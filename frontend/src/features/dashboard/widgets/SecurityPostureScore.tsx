import { useQuery } from "@tanstack/react-query";
import { TrendingUp, TrendingDown, ShieldAlert, ShieldCheck, Zap } from "lucide-react";
import { socMetricsApi } from "@/api/soc-metrics";
import { useNavigate } from "react-router-dom";

// ─── Circular gauge ───────────────────────────────────────────────────────────

function CircularGauge({ score, size = 120 }: { score: number; size?: number }) {
  const r = (size / 2) - 10;
  const circ = 2 * Math.PI * r;
  // arc goes from -225deg to +45deg (270deg sweep) = 3/4 of circle
  const clampedScore = Math.max(0, Math.min(100, score));
  const fillFraction = clampedScore / 100;
  const dash = circ * 0.75 * fillFraction;
  const gap  = circ * 0.75 * (1 - fillFraction) + circ * 0.25;

  const color =
    score >= 80 ? "#10B981" :
    score >= 60 ? "#3B82F6" :
    score >= 40 ? "#F59E0B" :
                  "#EF4444";

  const glowColor =
    score >= 80 ? "rgba(16,185,129,0.35)" :
    score >= 60 ? "rgba(59,130,246,0.35)"  :
    score >= 40 ? "rgba(245,158,11,0.35)"  :
                  "rgba(239,68,68,0.35)";

  const label =
    score >= 80 ? "EXCELLENT" :
    score >= 60 ? "GOOD"      :
    score >= 40 ? "FAIR"      :
                  "AT RISK";

  return (
    <div style={{ position: "relative", width: size, height: size, flexShrink: 0 }}>
      <svg width={size} height={size} style={{ transform: "rotate(135deg)" }}>
        {/* Track */}
        <circle
          cx={size / 2} cy={size / 2} r={r}
          fill="none"
          stroke="rgba(255,255,255,0.06)"
          strokeWidth={8}
          strokeLinecap="round"
          strokeDasharray={`${circ * 0.75} ${circ * 0.25}`}
        />
        {/* Fill */}
        <circle
          cx={size / 2} cy={size / 2} r={r}
          fill="none"
          stroke={color}
          strokeWidth={8}
          strokeLinecap="round"
          strokeDasharray={`${dash} ${gap}`}
          style={{
            filter: `drop-shadow(0 0 6px ${glowColor})`,
            transition: "stroke-dasharray 800ms cubic-bezier(0.4,0,0.2,1)",
          }}
        />
      </svg>
      {/* Center text */}
      <div style={{
        position: "absolute", inset: 0,
        display: "flex", flexDirection: "column",
        alignItems: "center", justifyContent: "center",
      }}>
        <span style={{
          fontSize: size > 100 ? 28 : 20,
          fontWeight: 800,
          color,
          fontFamily: "'JetBrains Mono', monospace",
          lineHeight: 1,
        }}>
          {Math.round(clampedScore)}
        </span>
        <span style={{
          fontSize: 8,
          fontWeight: 700,
          textTransform: "uppercase" as const,
          letterSpacing: "1.5px",
          color,
          marginTop: 2,
          opacity: 0.8,
        }}>
          {label}
        </span>
      </div>
    </div>
  );
}

// ─── Mini stat pill ───────────────────────────────────────────────────────────

function StatPill({
  label, value, color, onClick,
}: {
  label: string; value: string | number; color: string; onClick?: () => void;
}) {
  return (
    <button
      onClick={onClick}
      style={{
        display: "flex", flexDirection: "column", gap: 2,
        padding: "8px 12px", borderRadius: 8,
        background: `${color}0d`,
        border: `1px solid ${color}22`,
        cursor: onClick ? "pointer" : "default",
        textAlign: "left",
        transition: "all 150ms",
        flex: 1,
        minWidth: 0,
      }}
      onMouseOver={(e) => { if (onClick) (e.currentTarget as HTMLButtonElement).style.borderColor = `${color}44`; }}
      onMouseOut={(e)  => { if (onClick) (e.currentTarget as HTMLButtonElement).style.borderColor = `${color}22`; }}
    >
      <span style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase" as const, letterSpacing: "1.2px", color: `${color}99` }}>
        {label}
      </span>
      <span style={{ fontSize: 18, fontWeight: 800, color, fontFamily: "'JetBrains Mono', monospace", lineHeight: 1 }}>
        {value}
      </span>
    </button>
  );
}

// ─── SecurityPostureScore ─────────────────────────────────────────────────────

export function SecurityPostureScore() {
  const navigate = useNavigate();

  const { data: coverage } = useQuery({
    queryKey: ["metrics", "coverage-score"],
    queryFn: socMetricsApi.getCoverageScore,
    staleTime: 300_000,
  });

  const { data: mttr } = useQuery({
    queryKey: ["metrics", "mttr"],
    queryFn: () => socMetricsApi.getMTTR("30d"),
    staleTime: 300_000,
  });

  const { data: slaBreachRate } = useQuery({
    queryKey: ["metrics", "sla-breach-rate"],
    queryFn: () => socMetricsApi.getSLABreachRate("30d"),
    staleTime: 300_000,
  });

  // Composite score: 40% coverage + 30% SLA compliance + 30% MTTR
  const coverageScore = coverage?.score_pct ?? 0;
  const latestSlaBreachPct = slaBreachRate?.[slaBreachRate.length - 1]?.crit_breach_pct ?? 0;
  const slaCompliance = Math.max(0, 100 - latestSlaBreachPct);
  const critMttr = mttr?.find((r) => r.severity === "critical")?.mean_minutes ?? 0;
  const mttrScore = Math.max(0, 100 - Math.min(critMttr / 60, 100));
  const compositeScore = Math.round(coverageScore * 0.4 + slaCompliance * 0.3 + mttrScore * 0.3);

  const trendDelta = coverage?.trend_delta ?? 0;

  return (
    <div
      className="card"
      style={{
        padding: "20px 24px",
        display: "flex",
        alignItems: "center",
        gap: 28,
        background: "linear-gradient(135deg, #0D0D0D 0%, #0A0F1E 100%)",
        borderColor: "rgba(59,130,246,0.15)",
        boxShadow: "0 0 40px rgba(59,130,246,0.05)",
        position: "relative",
        overflow: "hidden",
      }}
    >
      {/* Subtle grid background */}
      <div style={{
        position: "absolute", inset: 0, pointerEvents: "none",
        backgroundImage: "linear-gradient(rgba(59,130,246,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(59,130,246,0.03) 1px, transparent 1px)",
        backgroundSize: "32px 32px",
      }} />

      {/* Gauge */}
      <CircularGauge score={compositeScore} size={120} />

      {/* Center content */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
          <h2 style={{ fontSize: 15, fontWeight: 700, color: "#F5F7FA", fontFamily: "'Space Grotesk', sans-serif", margin: 0 }}>
            Security Posture
          </h2>
          <span style={{
            display: "inline-flex", alignItems: "center", gap: 4,
            fontSize: 10, fontWeight: 600,
            color: trendDelta >= 0 ? "#10B981" : "#EF4444",
          }}>
            {trendDelta >= 0
              ? <TrendingUp size={11} />
              : <TrendingDown size={11} />}
            {trendDelta >= 0 ? "+" : ""}{trendDelta}% vs last period
          </span>
        </div>
        <p style={{ fontSize: 11, color: "#5C6373", margin: "0 0 14px" }}>
          Composite score — MITRE coverage, SLA compliance, and MTTR
        </p>

        {/* Breakdown bars */}
        <div style={{ display: "flex", flexDirection: "column", gap: 5, maxWidth: 400 }}>
          {[
            { label: "MITRE Coverage",  value: coverageScore,   color: "#3B82F6", target: 80  },
            { label: "SLA Compliance",  value: Math.round(slaCompliance), color: "#10B981", target: 95  },
            { label: "Response Speed",  value: Math.round(mttrScore),     color: "#F59E0B", target: 70  },
          ].map(({ label, value, color, target }) => (
            <div key={label}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                <span style={{ fontSize: 10, color: "#8B95A7" }}>{label}</span>
                <span style={{ fontSize: 10, color, fontFamily: "monospace", fontWeight: 700 }}>
                  {value}% <span style={{ color: "#3A4150", fontWeight: 400 }}>/ {target}% target</span>
                </span>
              </div>
              <div style={{ height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2, position: "relative" }}>
                <div style={{
                  position: "absolute", left: 0, top: 0, bottom: 0,
                  width: `${value}%`, background: color, borderRadius: 2,
                  transition: "width 600ms cubic-bezier(0.4,0,0.2,1)",
                }} />
                {/* Target marker */}
                <div style={{
                  position: "absolute", left: `${target}%`, top: -2, bottom: -2,
                  width: 1, background: `${color}55`,
                }} />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Right: action stats */}
      <div style={{ display: "flex", flexDirection: "column", gap: 6, minWidth: 200 }}>
        <div style={{ display: "flex", gap: 6 }}>
          <StatPill label="Coverage" value={`${coverageScore}%`}    color="#3B82F6" onClick={() => navigate("/mitre")} />
          <StatPill label="SLA OK"   value={`${Math.round(slaCompliance)}%`} color="#10B981" onClick={() => navigate("/soc-metrics/sla")} />
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          <StatPill
            label="Crit MTTR"
            value={critMttr >= 60 ? `${(critMttr / 60).toFixed(1)}h` : `${Math.round(critMttr)}m`}
            color="#F59E0B"
            onClick={() => navigate("/soc-metrics")}
          />
          <StatPill
            label="Techniques"
            value={coverage ? `${coverage.covered_techniques}/${coverage.total_techniques}` : "—"}
            color="#8B5CF6"
            onClick={() => navigate("/mitre")}
          />
        </div>
        <div style={{ display: "flex", gap: 6, marginTop: 2 }}>
          {compositeScore >= 80 ? (
            <div style={{ display: "flex", alignItems: "center", gap: 5, padding: "5px 10px", borderRadius: 6, background: "rgba(16,185,129,0.08)", border: "1px solid rgba(16,185,129,0.2)", flex: 1 }}>
              <ShieldCheck size={12} style={{ color: "#10B981", flexShrink: 0 }} />
              <span style={{ fontSize: 10, color: "#10B981", fontWeight: 600 }}>Enterprise-grade posture</span>
            </div>
          ) : compositeScore >= 60 ? (
            <div style={{ display: "flex", alignItems: "center", gap: 5, padding: "5px 10px", borderRadius: 6, background: "rgba(59,130,246,0.08)", border: "1px solid rgba(59,130,246,0.2)", flex: 1 }}>
              <Zap size={12} style={{ color: "#60A5FA", flexShrink: 0 }} />
              <span style={{ fontSize: 10, color: "#60A5FA", fontWeight: 600 }}>Improving — review coverage gaps</span>
            </div>
          ) : (
            <div style={{ display: "flex", alignItems: "center", gap: 5, padding: "5px 10px", borderRadius: 6, background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.2)", flex: 1 }}>
              <ShieldAlert size={12} style={{ color: "#F87171", flexShrink: 0 }} />
              <span style={{ fontSize: 10, color: "#F87171", fontWeight: 600 }}>Needs immediate attention</span>
            </div>
          )}
          <button
            onClick={() => navigate("/soc-metrics")}
            style={{
              padding: "5px 10px", borderRadius: 6, fontSize: 10, fontWeight: 600,
              background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)",
              color: "#8B95A7", cursor: "pointer", flexShrink: 0,
              transition: "all 120ms",
            }}
          >
            Full Report →
          </button>
        </div>
      </div>
    </div>
  );
}
