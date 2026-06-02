import { useQuery } from "@tanstack/react-query";
import * as dashboardApi from "@/services/dashboardApi";
import type { DashboardTimeRange } from "@/features/dashboard/types/dashboard";

// ─── Query key factory ────────────────────────────────────────────────────────

export const dashboardKeys = {
  all:              () => ["dashboard"] as const,
  summary:          (tr: DashboardTimeRange) => ["dashboard", "summary", tr] as const,
  ingestionRate:    (tr: DashboardTimeRange) => ["dashboard", "ingestion-rate", tr] as const,
  alertsFeed:       (tr: DashboardTimeRange) => ["dashboard", "alerts-feed", tr] as const,
  detectionHealth:  (tr: DashboardTimeRange) => ["dashboard", "detection-health", tr] as const,
  mitreCoverage:    (tr: DashboardTimeRange) => ["dashboard", "mitre-coverage", tr] as const,
  correlation:      (tr: DashboardTimeRange) => ["dashboard", "correlation", tr] as const,
  aiOperations:     (tr: DashboardTimeRange) => ["dashboard", "ai-operations", tr] as const,
};

// ─── KPI summary ──────────────────────────────────────────────────────────────

export function useKPISummary(timeRange: DashboardTimeRange) {
  return useQuery({
    queryKey: dashboardKeys.summary(timeRange),
    queryFn: () => dashboardApi.getDashboardSummary({ timeRange }),
    staleTime: 30_000,
    refetchInterval: 60_000,
    placeholderData: dashboardApi.PLACEHOLDER_SUMMARY,
    retry: 1,
  });
}

// ─── Ingestion rate chart ─────────────────────────────────────────────────────

export function useIngestionRate(timeRange: DashboardTimeRange) {
  return useQuery({
    queryKey: dashboardKeys.ingestionRate(timeRange),
    queryFn: () => dashboardApi.getIngestionRate({ timeRange }),
    staleTime: 15_000,
    refetchInterval: 30_000,
    placeholderData: () => dashboardApi.buildPlaceholderIngestionSeries(
      timeRange === "last_15m" ? 15 : timeRange === "last_1h" ? 30 : 48
    ),
    retry: 1,
  });
}

// ─── Live alerts feed ─────────────────────────────────────────────────────────

export function useAlertsFeed(timeRange: DashboardTimeRange) {
  return useQuery({
    queryKey: dashboardKeys.alertsFeed(timeRange),
    queryFn: () => dashboardApi.getAlertsFeed({ timeRange, limit: 100 }),
    staleTime: 15_000,
    refetchInterval: 20_000,
    placeholderData: [],
    retry: 1,
  });
}

// ─── Detection health ─────────────────────────────────────────────────────────

export function useDetectionHealth(timeRange: DashboardTimeRange) {
  return useQuery({
    queryKey: dashboardKeys.detectionHealth(timeRange),
    queryFn: () => dashboardApi.getDetectionHealth({ timeRange }),
    staleTime: 60_000,
    refetchInterval: 120_000,
    placeholderData: dashboardApi.PLACEHOLDER_DETECTION_HEALTH,
    retry: 1,
  });
}

// ─── MITRE coverage ───────────────────────────────────────────────────────────

export function useMitreCoverage(timeRange: DashboardTimeRange) {
  return useQuery({
    queryKey: dashboardKeys.mitreCoverage(timeRange),
    queryFn: () => dashboardApi.getMitreCoverage({ timeRange }),
    staleTime: 60_000,
    refetchInterval: 300_000,   // 5min — MITRE data changes slowly
    placeholderData: dashboardApi.PLACEHOLDER_MITRE_COVERAGE,
    retry: 1,
  });
}

// ─── Correlation activity ─────────────────────────────────────────────────────

export function useCorrelationActivity(timeRange: DashboardTimeRange) {
  return useQuery({
    queryKey: dashboardKeys.correlation(timeRange),
    queryFn: () => dashboardApi.getCorrelationActivity({ timeRange }),
    staleTime: 30_000,
    refetchInterval: 60_000,
    placeholderData: dashboardApi.PLACEHOLDER_CORRELATION,
    retry: 1,
  });
}

// ─── AI operations ────────────────────────────────────────────────────────────

export function useAIOperations(timeRange: DashboardTimeRange) {
  return useQuery({
    queryKey: dashboardKeys.aiOperations(timeRange),
    queryFn: () => dashboardApi.getAIOperations({ timeRange }),
    staleTime: 30_000,
    refetchInterval: 60_000,
    placeholderData: dashboardApi.PLACEHOLDER_AI_OPS,
    retry: 1,
  });
}
