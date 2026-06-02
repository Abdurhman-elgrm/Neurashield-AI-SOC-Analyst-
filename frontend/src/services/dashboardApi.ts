import { apiClient } from "@/api/client";
import type { APIResponse } from "@/types/api";
import type {
  DashboardSummary,
  IngestionRateSeries,
  LiveAlert,
  DetectionHealthData,
  CorrelationActivityData,
  AIOperationsData,
  DashboardTimeRange,
} from "@/features/dashboard/types/dashboard";
import type { MitreCoverageData } from "@/features/dashboard/types/mitre";

interface TimeRangeParams {
  timeRange: DashboardTimeRange;
}

// ─── Dashboard summary (KPI metrics) ─────────────────────────────────────────

export async function getDashboardSummary(params: TimeRangeParams): Promise<DashboardSummary> {
  try {
    const { data } = await apiClient.get<APIResponse<DashboardSummary>>(
      "/dashboard/summary",
      { params: { time_range: params.timeRange } }
    );
    return data.data ?? PLACEHOLDER_SUMMARY;
  } catch {
    return PLACEHOLDER_SUMMARY;
  }
}

// ─── Ingestion rate time-series ───────────────────────────────────────────────

export async function getIngestionRate(params: TimeRangeParams): Promise<IngestionRateSeries> {
  try {
    const { data } = await apiClient.get<APIResponse<IngestionRateSeries>>(
      "/dashboard/ingestion-rate",
      { params: { time_range: params.timeRange } }
    );
    return data.data ?? buildPlaceholderIngestionSeries(30);
  } catch {
    return buildPlaceholderIngestionSeries(30);
  }
}

// ─── Live alerts feed ─────────────────────────────────────────────────────────

export interface AlertsFeedParams {
  timeRange: DashboardTimeRange;
  limit?: number;
  severity?: string;
  status?: string;
}

export async function getAlertsFeed(params: AlertsFeedParams): Promise<LiveAlert[]> {
  try {
    const { data } = await apiClient.get<APIResponse<LiveAlert[]>>(
      "/alerts",
      {
        params: {
          time_range: params.timeRange,
          limit: params.limit ?? 100,
          sort: "-created_at",
          ...(params.severity && { severity: params.severity }),
          ...(params.status && { status: params.status }),
        },
      }
    );
    return data.data ?? [];
  } catch {
    return [];
  }
}

// ─── Detection health ─────────────────────────────────────────────────────────

export async function getDetectionHealth(params: TimeRangeParams): Promise<DetectionHealthData> {
  try {
    const { data } = await apiClient.get<APIResponse<DetectionHealthData>>(
      "/dashboard/detection-health",
      { params: { time_range: params.timeRange } }
    );
    return data.data ?? PLACEHOLDER_DETECTION_HEALTH;
  } catch {
    return PLACEHOLDER_DETECTION_HEALTH;
  }
}

// ─── MITRE ATT&CK coverage ────────────────────────────────────────────────────

export async function getMitreCoverage(params: TimeRangeParams): Promise<MitreCoverageData> {
  try {
    const { data } = await apiClient.get<APIResponse<MitreCoverageData>>(
      "/dashboard/mitre-coverage",
      { params: { time_range: params.timeRange } }
    );
    return data.data ?? PLACEHOLDER_MITRE_COVERAGE;
  } catch {
    return PLACEHOLDER_MITRE_COVERAGE;
  }
}

// ─── Correlation activity ─────────────────────────────────────────────────────

export async function getCorrelationActivity(params: TimeRangeParams): Promise<CorrelationActivityData> {
  try {
    const { data } = await apiClient.get<APIResponse<CorrelationActivityData>>(
      "/dashboard/correlation-activity",
      { params: { time_range: params.timeRange } }
    );
    return data.data ?? PLACEHOLDER_CORRELATION;
  } catch {
    return PLACEHOLDER_CORRELATION;
  }
}

// ─── AI operations ────────────────────────────────────────────────────────────

export async function getAIOperations(params: TimeRangeParams): Promise<AIOperationsData> {
  try {
    const { data } = await apiClient.get<APIResponse<AIOperationsData>>(
      "/dashboard/ai-operations",
      { params: { time_range: params.timeRange } }
    );
    return data.data ?? PLACEHOLDER_AI_OPS;
  } catch {
    return PLACEHOLDER_AI_OPS;
  }
}

// ─── Placeholder data (used while backend endpoints are built) ─────────────────
// These are structurally identical to real responses — components never distinguish.

export const PLACEHOLDER_SUMMARY: DashboardSummary = {
  alerts: { total: 0, open: 0, critical: 0, high: 0, delta24h: 0, criticalDelta24h: 0 },
  investigations: { active: 0, correlated: 0, aiPending: 0, delta24h: 0 },
  ingestion: { epsNow: 0, epsPeak: 0, totalEvents: 0, deltaPercent: 0 },
  agents: { online: 0, total: 0, offline: 0 },
  detection: { rulesTriggered: 0, activeRules: 0, noisyRules: 0, delta24h: 0 },
  generatedAt: new Date().toISOString(),
};

export function buildPlaceholderIngestionSeries(points = 30): IngestionRateSeries {
  const now = Date.now();
  const pts = Array.from({ length: points }, (_, i) => ({
    timestamp: new Date(now - (points - i) * 60_000).toISOString(),
    eps: 0,
    normalizedEps: 0,
    alertsCreated: 0,
  }));
  return { points: pts, averageEps: 0, peakEps: 0 };
}

export const PLACEHOLDER_DETECTION_HEALTH: DetectionHealthData = {
  activeRules: 0, disabledRules: 0, noisyRules: 0, errorRules: 0,
  avgLatencyMs: 0, ingestionToDetectionMs: 0, topRules: [],
};

export const PLACEHOLDER_MITRE_COVERAGE: MitreCoverageData = {
  techniqueCounts: {}, totalAlerts: 0, coveredTechniques: 0,
  topTechnique: null, generatedAt: new Date().toISOString(),
};

export const PLACEHOLDER_CORRELATION: CorrelationActivityData = {
  activeInvestigations: 0, totalGroupedAlerts: 0, totalEntities: 0, recentCorrelations: [],
};

export const PLACEHOLDER_AI_OPS: AIOperationsData = {
  queueDepth: 0, analyzedLast24h: 0, truePositiveCount: 0, falsePositiveCount: 0,
  pendingCount: 0, avgConfidence: 0, recentVerdicts: [],
};
