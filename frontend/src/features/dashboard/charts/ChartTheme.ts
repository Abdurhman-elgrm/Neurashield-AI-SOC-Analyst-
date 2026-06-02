// ─── Chart design tokens ──────────────────────────────────────────────────────
// These must stay in sync with the CSS variables in index.css.
// Recharts components require explicit color strings (no CSS variables).

export const CHART_COLORS = {
  accent:    "#3b82f6",   // --color-accent
  success:   "#22c55e",   // --color-severity-low
  warning:   "#eab308",   // --color-severity-medium
  high:      "#f97316",   // --color-severity-high
  critical:  "#ef4444",   // --color-severity-critical
  info:      "#60a5fa",   // lighter blue
  muted:     "#64748b",   // --color-text-muted
  border:    "#1e293b",   // --color-border
  gridLine:  "#1e293b",   // subtle grid
} as const;

export const CHART_SEVERITY_COLORS = {
  critical: CHART_COLORS.critical,
  high:     CHART_COLORS.high,
  medium:   CHART_COLORS.warning,
  low:      CHART_COLORS.success,
  info:     CHART_COLORS.info,
} as const;

// Multi-series palette (for stacked charts, etc.)
export const CHART_PALETTE = [
  CHART_COLORS.accent,
  CHART_COLORS.success,
  CHART_COLORS.warning,
  CHART_COLORS.high,
  CHART_COLORS.critical,
  CHART_COLORS.info,
];

// Shared axis/grid config for Recharts
export const CHART_AXIS_STYLE = {
  tick:  { fill: CHART_COLORS.muted, fontSize: 11, fontFamily: "inherit" },
  line:  { stroke: CHART_COLORS.border },
  label: { fill: CHART_COLORS.muted, fontSize: 11 },
} as const;

export const CHART_TOOLTIP_STYLE = {
  contentStyle: {
    backgroundColor: "#0f1729",
    border: `1px solid ${CHART_COLORS.border}`,
    borderRadius: "8px",
    fontSize: "12px",
    color: "#e2e8f0",
  },
  labelStyle: { color: CHART_COLORS.muted },
  itemStyle:  { color: "#e2e8f0" },
  cursor:     { fill: "rgba(59,130,246,0.05)", stroke: "none" },
} as const;
