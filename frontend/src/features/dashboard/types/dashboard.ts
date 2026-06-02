// ─── Time range ───────────────────────────────────────────────────────────────

export type DashboardTimeRange =
  | "last_15m"
  | "last_1h"
  | "last_6h"
  | "last_24h"
  | "last_7d";

export const TIME_RANGE_LABELS: Record<DashboardTimeRange, string> = {
  last_15m: "Last 15m",
  last_1h:  "Last 1h",
  last_6h:  "Last 6h",
  last_24h: "Last 24h",
  last_7d:  "Last 7d",
};

export const TIME_RANGE_MINUTES: Record<DashboardTimeRange, number> = {
  last_15m: 15,
  last_1h:  60,
  last_6h:  360,
  last_24h: 1440,
  last_7d:  10080,
};

// ─── KPI summary ──────────────────────────────────────────────────────────────

export interface AlertKPI {
  total: number;
  open: number;
  critical: number;
  high: number;
  delta24h: number;           // absolute change vs previous period
  criticalDelta24h: number;
}

export interface InvestigationKPI {
  active: number;
  correlated: number;
  aiPending: number;
  delta24h: number;
}

export interface IngestionKPI {
  epsNow: number;
  epsPeak: number;
  totalEvents: number;
  deltaPercent: number;       // % change vs previous period
}

export interface AgentKPI {
  online: number;
  total: number;
  offline: number;
}

export interface DetectionKPI {
  rulesTriggered: number;
  activeRules: number;
  noisyRules: number;
  delta24h: number;
}

export interface DashboardSummary {
  alerts: AlertKPI;
  investigations: InvestigationKPI;
  ingestion: IngestionKPI;
  agents: AgentKPI;
  detection: DetectionKPI;
  generatedAt: string;        // ISO timestamp
}

// ─── Ingestion rate time-series ───────────────────────────────────────────────

export interface IngestionRatePoint {
  timestamp: string;          // ISO string
  eps: number;
  normalizedEps: number;
  alertsCreated: number;
}

export interface IngestionRateSeries {
  points: IngestionRatePoint[];
  averageEps: number;
  peakEps: number;
}

// ─── Alert feed ───────────────────────────────────────────────────────────────

export type AlertSeverity = "critical" | "high" | "medium" | "low" | "info";
export type AlertStatus   = "open" | "acknowledged" | "resolved" | "suppressed";

export interface LiveAlert {
  id: string;
  title: string;
  severity: AlertSeverity;
  status: AlertStatus;
  hostname: string;
  sourceIp?: string;
  ruleId: string;
  ruleName: string;
  correlationScore: number;   // 0–100
  investigationId?: string;
  tenantId: string;
  createdAt: string;
}

// ─── Detection health ─────────────────────────────────────────────────────────

export interface DetectionRuleHealth {
  ruleId: string;
  ruleName: string;
  triggeredCount: number;
  alertsCreated: number;
  suppressedCount: number;
  lastTriggeredAt: string | null;
  avgLatencyMs: number;
  status: "active" | "noisy" | "disabled" | "error";
}

export interface DetectionHealthData {
  activeRules: number;
  disabledRules: number;
  noisyRules: number;
  errorRules: number;
  avgLatencyMs: number;
  ingestionToDetectionMs: number;
  topRules: DetectionRuleHealth[];
}

// ─── Correlation activity ─────────────────────────────────────────────────────

export interface CorrelationEvent {
  id: string;
  investigationId: string;
  investigationTitle: string;
  alertCount: number;
  entityCount: number;
  behaviorMatches: string[];
  severity: AlertSeverity;
  correlatedAt: string;
}

export interface CorrelationActivityData {
  activeInvestigations: number;
  totalGroupedAlerts: number;
  totalEntities: number;
  recentCorrelations: CorrelationEvent[];
}

// ─── AI operations ────────────────────────────────────────────────────────────

export interface AIVerdict {
  verdict: "true_positive" | "false_positive" | "benign" | "pending";
  confidence: number;           // 0–100
  investigationId: string;
  title: string;
  analyzedAt: string | null;
}

export interface AIOperationsData {
  queueDepth: number;
  analyzedLast24h: number;
  truePositiveCount: number;
  falsePositiveCount: number;
  pendingCount: number;
  avgConfidence: number;
  recentVerdicts: AIVerdict[];
}

// ─── Widget metadata ──────────────────────────────────────────────────────────

export interface WidgetMeta {
  widgetId: string;
  lastRefreshedAt: number;    // unix timestamp ms
  isStale: boolean;
}
