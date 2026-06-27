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

// All backend endpoints return APIResponse envelope {status, data}. Unwrap with .data.data
 
const unwrap = (r: { data: any }) => r.data?.data ?? r.data;

export const socMetricsApi = {
  getMTTR: (timeRange = "30d") =>
    apiClient.get(`/metrics/mttr?timeRange=${timeRange}`).then(unwrap) as Promise<MTTRData[]>,

  getAlertVolume: (timeRange = "30d") =>
    apiClient.get(`/metrics/alert-volume?timeRange=${timeRange}&group_by=day,severity`).then(unwrap) as Promise<AlertVolumePoint[]>,

  getAnalystPerformance: () =>
    apiClient.get("/metrics/analyst-performance").then(unwrap) as Promise<AnalystPerformance[]>,

  getSLABreachRate: (timeRange = "30d") =>
    apiClient.get(`/metrics/sla-breach-rate?timeRange=${timeRange}`).then(unwrap) as Promise<SLABreachPoint[]>,

  getSLASummary: (timeRange = "30d") =>
    apiClient.get(`/metrics/sla-summary?timeRange=${timeRange}`).then(unwrap) as Promise<SLASummary>,

  getSLABySeverity: (timeRange = "30d") =>
    apiClient.get(`/metrics/sla-by-severity?timeRange=${timeRange}`).then(unwrap) as Promise<SLABySeverityRow[]>,

  getSLABreaches: (timeRange = "30d", page = 1) =>
    apiClient.get(`/metrics/sla-breaches?timeRange=${timeRange}&page=${page}`).then(unwrap) as Promise<SLABreachListResponse>,

  getResponseTimeDistribution: (timeRange = "30d") =>
    apiClient.get(`/metrics/response-time-distribution?timeRange=${timeRange}`).then(unwrap) as Promise<ResponseTimeBin[]>,

  getAnalystSLA: (timeRange = "30d") =>
    apiClient.get(`/metrics/analyst-sla?timeRange=${timeRange}`).then(unwrap) as Promise<AnalystSLARow[]>,

  getVerdictDistribution: (timeRange = "30d") =>
    apiClient.get(`/metrics/verdict-distribution?timeRange=${timeRange}`).then(unwrap) as Promise<VerdictDistribution>,

  getCoverageScore: () =>
    apiClient.get("/rules/coverage").then(unwrap) as Promise<DetectionCoverageScore>,

  getGeoThreats: (timeRange = "24h") =>
    apiClient.get(`/dashboard/geo-threats?timeRange=${timeRange}`).then(unwrap) as Promise<GeoThreat[]>,

  getNetworkFlow: (timeRange = "24h") =>
    apiClient.get(`/dashboard/network-flow?timeRange=${timeRange}`).then(unwrap) as Promise<NetworkFlowData>,
};
