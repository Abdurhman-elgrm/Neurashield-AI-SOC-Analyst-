import { useState, useEffect, useRef } from "react";
import { Bell, AlertTriangle, FolderSearch, Activity } from "lucide-react";
import { useDashboardStore } from "@/stores/dashboardStore";
import { useDashboardRealtime } from "./hooks/useDashboardRealtime";
import { useKPISummary } from "./hooks/useDashboardData";
import { LiveAlertsFeed } from "./widgets/LiveAlertsFeed";
import { IngestionRateChart } from "./widgets/IngestionRateChart";
import { DetectionHealthWidget } from "./widgets/DetectionHealthWidget";
import { MitreHeatmap } from "./widgets/MitreHeatmap";
import { CorrelationWidget } from "./widgets/CorrelationWidget";
import { AIInvestigationWidget } from "./widgets/AIInvestigationWidget";
import type { DashboardTimeRange } from "./types/dashboard";
import { TIME_RANGE_LABELS } from "./types/dashboard";

const TIME_RANGES: DashboardTimeRange[] = [
  "last_15m", "last_1h", "last_6h", "last_24h", "last_7d",
];

// ─── Animated count-up ────────────────────────────────────────────────────────

function useCountUp(target: number, duration = 800) {
  const [display, setDisplay] = useState(0);
  const prev = useRef(0);
  useEffect(() => {
    const start = prev.current;
    const end = target;
    prev.current = target;
    if (start === end) return;
    const step = (end - start) / (duration / 16);
    let current = start;
    const timer = setInterval(() => {
      current = Math.min(current + step, end);
      setDisplay(Math.floor(current));
      if (current >= end) clearInterval(timer);
    }, 16);
    return () => clearInterval(timer);
  }, [target, duration]);
  return display;
}

// ─── KPI Card ─────────────────────────────────────────────────────────────────

interface KPICardProps {
  label: string;
  value: number;
  icon: React.ElementType;
  accent: string;
  live?: boolean;
  formatter?: (v: number) => string;
}

function KPICard({ label, value, icon: Icon, accent, live, formatter }: KPICardProps) {
  const display = useCountUp(value);
  const formatted = formatter ? formatter(display) : display.toLocaleString();

  return (
    <div className="kpi-card" style={{ cursor: "default" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
        <span className="kpi-label">{label}</span>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          {live && (
            <>
              <span className="dot-live" />
              <span style={{ fontSize: 9, color: "#10B981", fontWeight: 700 }}>LIVE</span>
            </>
          )}
          <Icon size={14} style={{ color: accent, opacity: 0.7 }} />
        </div>
      </div>
      <div className="kpi-value" style={{ color: value > 0 ? accent : "#F5F7FA" }}>
        {formatted}
      </div>
      <div className="kpi-trend">— 0% vs prev period</div>
    </div>
  );
}

// ─── Time range picker ────────────────────────────────────────────────────────

function TimeRangePicker({
  value,
  onChange,
}: {
  value: DashboardTimeRange;
  onChange: (v: DashboardTimeRange) => void;
}) {
  return (
    <div style={{
      display: "flex",
      gap: 2,
      background: "#0D0D0D",
      border: "1px solid rgba(255,255,255,0.06)",
      borderRadius: 8,
      padding: 3,
    }}>
      {TIME_RANGES.map((r) => (
        <button
          key={r}
          onClick={() => onChange(r)}
          style={{
            padding: "4px 12px",
            borderRadius: 6,
            fontSize: 11,
            fontWeight: 600,
            background: value === r ? "#2563EB" : "transparent",
            color: value === r ? "#fff" : "#5C6373",
            border: "none",
            cursor: "pointer",
            transition: "all 120ms",
            fontFamily: "'JetBrains Mono', monospace",
          }}
        >
          {TIME_RANGE_LABELS[r]}
        </button>
      ))}
    </div>
  );
}

// ─── Dashboard page ───────────────────────────────────────────────────────────

export function DashboardPage() {
  const timeRange    = useDashboardStore((s) => s.timeRange);
  const setTimeRange = useDashboardStore((s) => s.setTimeRange);
  const { data }     = useKPISummary(timeRange);

  useDashboardRealtime(timeRange);

  const s = data!;

  return (
    <div style={{ paddingBottom: 24 }}>

      {/* Page header */}
      <div style={{
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "space-between",
        marginBottom: 20,
        flexWrap: "wrap",
        gap: 12,
      }}>
        <div>
          <h1 style={{
            fontSize: 20,
            fontWeight: 800,
            color: "#F5F7FA",
            fontFamily: "'Space Grotesk', sans-serif",
          }}>
            Security Overview
          </h1>
          <p style={{ fontSize: 12, color: "#5C6373", marginTop: 2 }}>
            Real-time threat intelligence command center
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, color: "#10B981" }}>
            <span className="dot-live" />
            <span style={{ fontWeight: 600 }}>Live</span>
          </div>
          <TimeRangePicker value={timeRange} onChange={setTimeRange} />
        </div>
      </div>

      {/* KPI strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 16 }}>
        <KPICard
          label="TOTAL ALERTS"
          value={s?.alerts?.total ?? 0}
          icon={Bell}
          accent="#EF4444"
          live
        />
        <KPICard
          label="CRITICAL P1"
          value={s?.alerts?.critical ?? 0}
          icon={AlertTriangle}
          accent="#EF4444"
        />
        <KPICard
          label="ACTIVE INVEST."
          value={s?.investigations?.active ?? 0}
          icon={FolderSearch}
          accent="#3B82F6"
        />
        <KPICard
          label="EVENTS / SEC"
          value={s?.ingestion?.epsNow ?? 0}
          icon={Activity}
          accent="#10B981"
          live
          formatter={(v) => v >= 1000 ? `${(v / 1000).toFixed(1)}K` : String(v)}
        />
      </div>

      {/* Row 2: Alerts + Ingestion + Detection */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto", gap: 12, marginBottom: 12 }}>
        <LiveAlertsFeed timeRange={timeRange} maxHeight={380} />
        <IngestionRateChart timeRange={timeRange} />
        <div style={{ width: 260 }}>
          <DetectionHealthWidget timeRange={timeRange} />
        </div>
      </div>

      {/* Row 3: MITRE + Correlation */}
      <div style={{ display: "grid", gridTemplateColumns: "3fr 2fr", gap: 12, marginBottom: 12 }}>
        <MitreHeatmap timeRange={timeRange} />
        <CorrelationWidget timeRange={timeRange} />
      </div>

      {/* Row 4: AI operations */}
      <AIInvestigationWidget timeRange={timeRange} />
    </div>
  );
}
