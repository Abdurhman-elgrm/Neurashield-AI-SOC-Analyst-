import { useState } from "react";
import { Settings2, ShieldAlert } from "lucide-react";
import { useDashboardStore } from "@/stores/dashboardStore";
import { useDashboardRealtime } from "./hooks/useDashboardRealtime";
import { KPIMetricsRow } from "./widgets/KPIMetricsRow";
import { LiveAlertsFeed } from "./widgets/LiveAlertsFeed";
import { IngestionRateChart } from "./widgets/IngestionRateChart";
import { DetectionHealthWidget } from "./widgets/DetectionHealthWidget";
import { MitreHeatmap } from "./widgets/MitreHeatmap";
import { CorrelationWidget } from "./widgets/CorrelationWidget";
import { AIInvestigationWidget } from "./widgets/AIInvestigationWidget";
import { GeoThreatMap } from "./widgets/GeoThreatMap";
import { TopEntitiesWidget } from "./widgets/TopEntitiesWidget";
import { AlertVolumeHeatmap } from "./widgets/AlertVolumeHeatmap";
import { MTTRTrendChart } from "./widgets/MTTRTrendChart";
import { CustomDashboardBuilder } from "./widgets/CustomDashboardBuilder";
import { SecurityPostureScore } from "./widgets/SecurityPostureScore";
import { WidgetErrorBoundary } from "@/components/ui/WidgetErrorBoundary";
import { useKPISummary } from "./hooks/useDashboardData";
import type { DashboardTimeRange } from "./types/dashboard";
import { TIME_RANGE_LABELS } from "./types/dashboard";

const TIME_RANGES: DashboardTimeRange[] = [
  "last_15m", "last_1h", "last_6h", "last_24h", "last_7d",
];

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
      display: "flex", gap: 2,
      background: "rgba(255,255,255,0.03)",
      border: "1px solid rgba(255,255,255,0.07)",
      borderRadius: 7, padding: 3,
    }}>
      {TIME_RANGES.map((r) => (
        <button
          key={r}
          onClick={() => onChange(r)}
          style={{
            padding: "4px 10px", borderRadius: 4, border: "none", cursor: "pointer",
            fontSize: 11, fontWeight: 600, transition: "all 100ms",
            fontFamily: "'JetBrains Mono', monospace",
            background: r === value ? "rgba(59,130,246,0.15)" : "transparent",
            color: r === value ? "#60A5FA" : "#5C6373",
          }}
        >
          {TIME_RANGE_LABELS[r]}
        </button>
      ))}
    </div>
  );
}

// ─── Section header ───────────────────────────────────────────────────────────

function SectionHeader({
  title,
  subtitle,
  accent = "#3B82F6",
}: {
  title: string;
  subtitle?: string;
  accent?: string;
}) {
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 10, marginBottom: 10,
    }}>
      <div style={{
        width: 3, height: 28, borderRadius: 2,
        background: `linear-gradient(180deg, ${accent}, ${accent}40)`,
        flexShrink: 0,
      }} />
      <div>
        <div style={{
          fontSize: 10, fontWeight: 700, textTransform: "uppercase",
          letterSpacing: "1.8px", color: "#5C6373",
        }}>
          {title}
        </div>
        {subtitle && (
          <div style={{ fontSize: 10, color: "#3A4150", marginTop: 1 }}>{subtitle}</div>
        )}
      </div>
    </div>
  );
}

// ─── Critical alert banner ────────────────────────────────────────────────────

function CriticalAlertBanner({ count }: { count: number }) {
  const [dismissed, setDismissed] = useState(false);
  if (count === 0 || dismissed) return null;
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 10,
      padding: "9px 14px", marginBottom: 14, borderRadius: 8,
      background: "rgba(239,68,68,0.07)",
      border: "1px solid rgba(239,68,68,0.22)",
      borderLeft: "3px solid #EF4444",
    }}>
      <ShieldAlert size={14} style={{ color: "#EF4444", flexShrink: 0 }} />
      <div style={{ flex: 1 }}>
        <span style={{ fontSize: 12, fontWeight: 700, color: "#FCA5A5" }}>
          {count} critical alert{count > 1 ? "s" : ""} require immediate attention
        </span>
        <span style={{ fontSize: 11, color: "#5C6373", marginLeft: 8 }}>
          · Escalation may be required
        </span>
      </div>
      <a href="/alerts?severity=critical" style={{
        padding: "4px 10px", borderRadius: 5, fontSize: 10, fontWeight: 700,
        background: "rgba(239,68,68,0.12)", border: "1px solid rgba(239,68,68,0.3)",
        color: "#FCA5A5", textDecoration: "none", flexShrink: 0,
        textTransform: "uppercase", letterSpacing: "0.5px",
      }}>
        View →
      </a>
      <button onClick={() => setDismissed(true)} style={{
        background: "none", border: "none", cursor: "pointer",
        color: "#5C6373", fontSize: 14, lineHeight: 1, padding: 2, flexShrink: 0,
      }}>
        ✕
      </button>
    </div>
  );
}

// ─── Dashboard page ───────────────────────────────────────────────────────────

export function DashboardPage() {
  const timeRange    = useDashboardStore((s) => s.timeRange);
  const setTimeRange = useDashboardStore((s) => s.setTimeRange);
  const [editMode, setEditMode] = useState(false);

  useDashboardRealtime(timeRange);

  // Peek at KPI data to drive the critical alert banner
  const { data: kpi } = useKPISummary(timeRange);
  const criticalCount = kpi?.alerts.critical ?? 0;

  return (
    <div className="pb-8">

      {/* Page header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 14, flexWrap: "wrap", gap: 12 }}>
        <div>
          <h1 style={{
            fontSize: 20, fontWeight: 800,
            fontFamily: "'Space Grotesk', sans-serif",
            color: "#F5F7FA", margin: 0, letterSpacing: "-0.3px",
          }}>
            Security Overview
          </h1>
          <p style={{ fontSize: 12, color: "#5C6373", margin: "3px 0 0" }}>
            Real-time threat intelligence command center
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 10, color: "#10B981", fontWeight: 700 }}>
            <span style={{
              width: 6, height: 6, borderRadius: "50%", background: "#10B981",
              boxShadow: "0 0 6px #10B981", animation: "pulse 2s ease-in-out infinite",
            }} />
            LIVE
          </span>
          <TimeRangePicker value={timeRange} onChange={setTimeRange} />
          <button
            onClick={() => setEditMode((v) => !v)}
            style={{
              display: "flex", alignItems: "center", gap: 6,
              padding: "6px 12px", borderRadius: 6, fontSize: 11, fontWeight: 600,
              background: editMode ? "rgba(59,130,246,0.12)" : "rgba(255,255,255,0.04)",
              border: editMode ? "1px solid rgba(59,130,246,0.3)" : "1px solid rgba(255,255,255,0.08)",
              color: editMode ? "#60A5FA" : "#8B95A7",
              cursor: "pointer", transition: "all 120ms",
            }}
          >
            <Settings2 size={12} />
            {editMode ? "Done" : "Customize"}
          </button>
        </div>
      </div>

      {/* Critical alert banner */}
      <CriticalAlertBanner count={criticalCount} />

      {/* Custom Dashboard Builder (edit mode only) */}
      <CustomDashboardBuilder editMode={editMode} />

      {/* ── Security Posture ── */}
      <div style={{ marginBottom: 20 }}>
        <SectionHeader title="Security Posture" subtitle="Composite readiness score" accent="#3B82F6" />
        <WidgetErrorBoundary title="Security Posture Score">
          <SecurityPostureScore />
        </WidgetErrorBoundary>
      </div>

      {/* ── KPI strip ── */}
      <div style={{ marginBottom: 20 }}>
        <SectionHeader
          title="Key Performance Indicators"
          subtitle="Click any metric to drill in"
          accent={criticalCount > 0 ? "#EF4444" : "#3B82F6"}
        />
        <WidgetErrorBoundary title="KPI Metrics">
          <KPIMetricsRow timeRange={timeRange} />
        </WidgetErrorBoundary>
      </div>

      {/* ── Operations ── */}
      <div style={{ marginBottom: 20 }}>
        <SectionHeader title="Operations" subtitle="Real-time alert stream and data ingestion" accent="#F97316" />
        <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1.2fr) minmax(0,1fr) 290px", gap: 12 }}>
          <WidgetErrorBoundary title="Live Alerts Feed">
            <LiveAlertsFeed timeRange={timeRange} maxHeight={360} />
          </WidgetErrorBoundary>
          <WidgetErrorBoundary title="Ingestion Rate">
            <IngestionRateChart timeRange={timeRange} />
          </WidgetErrorBoundary>
          <WidgetErrorBoundary title="Detection Health">
            <DetectionHealthWidget timeRange={timeRange} />
          </WidgetErrorBoundary>
        </div>
      </div>

      {/* ── Threat Intelligence ── */}
      <div style={{ marginBottom: 20 }}>
        <SectionHeader title="Threat Intelligence" subtitle="ATT&CK coverage and correlation activity" accent="#8B5CF6" />
        <div style={{ display: "grid", gridTemplateColumns: "3fr 2fr", gap: 12 }}>
          <WidgetErrorBoundary title="MITRE ATT&CK">
            <MitreHeatmap timeRange={timeRange} />
          </WidgetErrorBoundary>
          <WidgetErrorBoundary title="Correlation Activity">
            <CorrelationWidget timeRange={timeRange} />
          </WidgetErrorBoundary>
        </div>
      </div>

      {/* ── AI Operations ── */}
      <div style={{ marginBottom: 20 }}>
        <SectionHeader title="AI Operations" subtitle="AI-powered investigation queue and recommendations" accent="#06B6D4" />
        <WidgetErrorBoundary title="AI Investigations">
          <AIInvestigationWidget timeRange={timeRange} />
        </WidgetErrorBoundary>
      </div>

      {/* ── Geospatial Intelligence ── */}
      <div style={{ marginBottom: 20 }}>
        <SectionHeader title="Geospatial Intelligence" subtitle="Threat origin mapping and top entity monitoring" accent="#10B981" />
        <div style={{ display: "grid", gridTemplateColumns: "3fr 2fr", gap: 12 }}>
          <WidgetErrorBoundary title="Geo Threat Map">
            <GeoThreatMap timeRange={timeRange} />
          </WidgetErrorBoundary>
          <WidgetErrorBoundary title="Top Entities">
            <TopEntitiesWidget timeRange={timeRange} />
          </WidgetErrorBoundary>
        </div>
      </div>

      {/* ── Performance Trends ── */}
      <div>
        <SectionHeader title="Performance Trends" subtitle="Alert volume patterns and mean time to resolution" accent="#F59E0B" />
        <div style={{ display: "grid", gridTemplateColumns: "3fr 2fr", gap: 12 }}>
          <WidgetErrorBoundary title="Alert Volume Heatmap">
            <AlertVolumeHeatmap timeRange={timeRange} />
          </WidgetErrorBoundary>
          <WidgetErrorBoundary title="MTTR Trend">
            <MTTRTrendChart timeRange={timeRange} />
          </WidgetErrorBoundary>
        </div>
      </div>
    </div>
  );
}
