import { apiClient } from "./client";

// GET /metrics/mttr?timeRange=30d
export interface MTTRData {
  severity: string;
  mean_minutes: number;
  median_minutes: number;
  sample_count: number;
}

// GET /metrics/alert-volume?timeRange=30d&group_by=day,severity
export interface AlertVolumePoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

// GET /metrics/analyst-performance
export interface AnalystPerformance {
  user_id: string;
  name: string;
  email: string;
  alerts_triaged_today: number;
  avg_resolution_minutes: number;
  open_assignments: number;
}

// GET /metrics/sla-breach-rate
export interface SLABreachPoint {
  date: string;
  warn_breach_pct: number;
  crit_breach_pct: number;
}

// GET /metrics/sla-by-severity
export interface SLABySeverityRow {
  severity: "critical" | "high" | "medium" | "low";
  target_minutes: number;   // SLA target response time
  avg_minutes: number;      // actual avg response time
  compliance_pct: number;   // % resolved within target
  total_alerts: number;
  breached: number;
}

// GET /metrics/sla-breaches?timeRange=…&page=…
export interface SLABreachAlert {
  alert_id: string;
  title: string;
  severity: string;
  created_at: string;
  resolved_at: string | null;
  assigned_to: string | null;
  elapsed_minutes: number;
  target_minutes: number;
  breach_type: "response" | "resolution";
}

export interface SLABreachListResponse {
  items: SLABreachAlert[];
  total: number;
  page: number;
}

// GET /metrics/response-time-distribution
export interface ResponseTimeBin {
  label: string;     // e.g. "<15m"
  max_minutes: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

// GET /metrics/analyst-sla
export interface AnalystSLARow {
  user_id: string;
  name: string;
  handled: number;
  within_sla: number;
  compliance_pct: number;
  avg_response_minutes: number;
  avg_resolve_minutes: number;
  open_breaches: number;
}

// GET /metrics/sla-summary
export interface SLASummary {
  compliance_pct: number;
  compliance_delta: number;   // vs prior period
  total_breaches: number;
  breach_delta: number;
  avg_response_minutes: number;
  avg_resolve_minutes: number;
  within_sla: number;
  total: number;
}

// GET /metrics/verdict-distribution
export interface VerdictDistribution {
  true_positive: number;
  false_positive: number;
  benign: number;
  unknown: number;
}

// GET /rules/coverage
export interface DetectionCoverageScore {
  score_pct: number;
  covered_techniques: number;
  total_techniques: number;
  trend_delta: number;
}

// GET /dashboard/geo-threats
export interface GeoThreat {
  lat: number;
  lng: number;
  severity: string;
  count: number;
  country: string;
}

// GET /dashboard/network-flow
export interface NetworkFlowNode {
  name: string;
  is_threat?: boolean;
  is_internal?: boolean;
}

export interface NetworkFlowLink {
  source: number;
  target: number;
  value: number;
}

export interface NetworkFlowData {
  nodes: NetworkFlowNode[];
  links: NetworkFlowLink[];
}

export const socMetricsApi = {
  getMTTR: (timeRange = "30d") =>
    apiClient.get<MTTRData[]>(`/metrics/mttr?timeRange=${timeRange}`).then((r) => r.data),

  getAlertVolume: (timeRange = "30d") =>
    apiClient.get<AlertVolumePoint[]>(`/metrics/alert-volume?timeRange=${timeRange}&group_by=day,severity`).then((r) => r.data),

  getAnalystPerformance: () =>
    apiClient.get<AnalystPerformance[]>("/metrics/analyst-performance").then((r) => r.data),

  getSLABreachRate: (timeRange = "30d") =>
    apiClient.get<SLABreachPoint[]>(`/metrics/sla-breach-rate?timeRange=${timeRange}`).then((r) => r.data),

  getSLASummary: (timeRange = "30d") =>
    apiClient.get<SLASummary>(`/metrics/sla-summary?timeRange=${timeRange}`).then((r) => r.data),

  getSLABySeverity: (timeRange = "30d") =>
    apiClient.get<SLABySeverityRow[]>(`/metrics/sla-by-severity?timeRange=${timeRange}`).then((r) => r.data),

  getSLABreaches: (timeRange = "30d", page = 1) =>
    apiClient.get<SLABreachListResponse>(`/metrics/sla-breaches?timeRange=${timeRange}&page=${page}`).then((r) => r.data),

  getResponseTimeDistribution: (timeRange = "30d") =>
    apiClient.get<ResponseTimeBin[]>(`/metrics/response-time-distribution?timeRange=${timeRange}`).then((r) => r.data),

  getAnalystSLA: (timeRange = "30d") =>
    apiClient.get<AnalystSLARow[]>(`/metrics/analyst-sla?timeRange=${timeRange}`).then((r) => r.data),

  getVerdictDistribution: (timeRange = "30d") =>
    apiClient.get<VerdictDistribution>(`/metrics/verdict-distribution?timeRange=${timeRange}`).then((r) => r.data),

  getCoverageScore: () =>
    apiClient.get<DetectionCoverageScore>("/rules/coverage").then((r) => r.data),

  getGeoThreats: (timeRange = "24h") =>
    apiClient.get<GeoThreat[]>(`/dashboard/geo-threats?timeRange=${timeRange}`).then((r) => r.data),

  getNetworkFlow: (timeRange = "24h") =>
    apiClient.get<NetworkFlowData>(`/dashboard/network-flow?timeRange=${timeRange}`).then((r) => r.data),
};
