import { useState } from "react";
import { Settings2 } from "lucide-react";
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
    <div className="flex gap-0.5 bg-bg-surface border border-border rounded-lg p-0.5">
      {TIME_RANGES.map((r) => (
        <button
          key={r}
          onClick={() => onChange(r)}
          className={
            r === value
              ? "px-3 py-1 rounded-md text-xs font-semibold bg-primary-600 text-white transition-all"
              : "px-3 py-1 rounded-md text-xs font-semibold text-text-muted hover:text-text-secondary transition-all"
          }
        >
          {TIME_RANGE_LABELS[r]}
        </button>
      ))}
    </div>
  );
}

// ─── Section header ───────────────────────────────────────────────────────────

function SectionHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div style={{ marginBottom: 8 }}>
      <h2 style={{
        fontSize: 11, fontWeight: 700, textTransform: "uppercase",
        letterSpacing: "1.5px", color: "#5C6373", margin: 0,
      }}>{title}</h2>
      {subtitle && (
        <p style={{ fontSize: 10, color: "#3A4150", margin: "2px 0 0" }}>{subtitle}</p>
      )}
    </div>
  );
}

// ─── Dashboard page ───────────────────────────────────────────────────────────

export function DashboardPage() {
  const timeRange    = useDashboardStore((s) => s.timeRange);
  const setTimeRange = useDashboardStore((s) => s.setTimeRange);
  const [editMode, setEditMode] = useState(false);

  useDashboardRealtime(timeRange);

  return (
    <div className="pb-8">

      {/* Page header */}
      <div className="flex items-start justify-between mb-5 flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-extrabold text-text-primary font-display tracking-tight">
            Security Overview
          </h1>
          <p className="text-xs text-text-muted mt-0.5">
            Real-time threat intelligence command center
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 text-xs text-status-online font-semibold">
            <span className="w-1.5 h-1.5 bg-status-online rounded-full animate-pulse" />
            Live
          </span>
          <TimeRangePicker value={timeRange} onChange={setTimeRange} />
          <button
            onClick={() => setEditMode((v) => !v)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs border border-border text-text-muted hover:text-text-primary hover:border-border-hover transition-all"
            aria-label="Customize dashboard layout"
          >
            <Settings2 size={12} />
            {editMode ? "Done" : "Customize"}
          </button>
        </div>
      </div>

      {/* Custom Dashboard Builder (edit mode only) */}
      <CustomDashboardBuilder editMode={editMode} />

      {/* ── Row 0: Security Posture Score ── */}
      <div className="mb-4">
        <SectionHeader title="Security Posture" subtitle="Composite readiness score" />
        <WidgetErrorBoundary title="Security Posture Score">
          <SecurityPostureScore />
        </WidgetErrorBoundary>
      </div>

      {/* ── Row 1: KPI strip ── */}
      <div className="mb-4">
        <SectionHeader title="Key Performance Indicators" subtitle="Click any metric to drill into the data" />
        <WidgetErrorBoundary title="KPI Metrics">
          <KPIMetricsRow timeRange={timeRange} />
        </WidgetErrorBoundary>
      </div>

      {/* ── Row 2: Live alerts + ingestion + detection health ── */}
      <div className="mb-4">
        <SectionHeader title="Operations" subtitle="Real-time alert stream and data ingestion" />
        <div className="grid mb-0" style={{ gridTemplateColumns: "minmax(0,1.2fr) minmax(0,1fr) 290px", gap: 12 }}>
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

      {/* ── Row 3: MITRE ATT&CK + Correlation ── */}
      <div className="mb-4">
        <SectionHeader title="Threat Intelligence" subtitle="ATT&CK coverage and correlation activity" />
        <div className="grid" style={{ gridTemplateColumns: "3fr 2fr", gap: 12 }}>
          <WidgetErrorBoundary title="MITRE ATT&CK">
            <MitreHeatmap timeRange={timeRange} />
          </WidgetErrorBoundary>
          <WidgetErrorBoundary title="Correlation Activity">
            <CorrelationWidget timeRange={timeRange} />
          </WidgetErrorBoundary>
        </div>
      </div>

      {/* ── Row 4: AI Investigations ── */}
      <div className="mb-4">
        <SectionHeader title="AI Operations" subtitle="AI-powered investigation queue and recommendations" />
        <WidgetErrorBoundary title="AI Investigations">
          <AIInvestigationWidget timeRange={timeRange} />
        </WidgetErrorBoundary>
      </div>

      {/* ── Row 5: Geo threat map + top entities ── */}
      <div className="mb-4">
        <SectionHeader title="Geospatial Intelligence" subtitle="Threat origin mapping and top entity monitoring" />
        <div className="grid" style={{ gridTemplateColumns: "3fr 2fr", gap: 12 }}>
          <WidgetErrorBoundary title="Geo Threat Map">
            <GeoThreatMap timeRange={timeRange} />
          </WidgetErrorBoundary>
          <WidgetErrorBoundary title="Top Entities">
            <TopEntitiesWidget timeRange={timeRange} />
          </WidgetErrorBoundary>
        </div>
      </div>

      {/* ── Row 6: Alert volume heatmap + MTTR trend ── */}
      <div>
        <SectionHeader title="Performance Trends" subtitle="Alert volume patterns and mean time to resolution" />
        <div className="grid" style={{ gridTemplateColumns: "3fr 2fr", gap: 12 }}>
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
