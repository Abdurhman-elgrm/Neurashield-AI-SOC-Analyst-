import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  getAlerts,
  getAlertDetail,
  getAlertContext,
  getAlertTimeline,
  PLACEHOLDER_ALERT_LIST,
} from "@/services/alertsApi";
import type { AlertListParams, AlertListResponse } from "@/features/alerts/types";

// ─── Query key factory ────────────────────────────────────────────────────────

export const alertsKeys = {
  all: ["alerts"] as const,
  lists: () => [...alertsKeys.all, "list"] as const,
  list: (params: AlertListParams) => [...alertsKeys.lists(), params] as const,
  detail: (id: string) => [...alertsKeys.all, "detail", id] as const,
  context: (id: string) => [...alertsKeys.all, "context", id] as const,
  timeline: (id: string) => [...alertsKeys.all, "timeline", id] as const,
};

// ─── Alert list (paginated, filterable) ───────────────────────────────────────

export function useAlertsList(params: AlertListParams) {
  return useQuery({
    queryKey: alertsKeys.list(params),
    queryFn: () => getAlerts(params),
    placeholderData: (prev: AlertListResponse | undefined) => prev ?? PLACEHOLDER_ALERT_LIST,
    staleTime: 15_000,
    refetchInterval: 30_000,
  });
}

// ─── Single alert detail ──────────────────────────────────────────────────────

export function useAlertDetail(alertId: string | null) {
  return useQuery({
    queryKey: alertsKeys.detail(alertId ?? ""),
    queryFn: () => getAlertDetail(alertId!),
    enabled: !!alertId,
    staleTime: 10_000,
  });
}

// ─── Alert investigation context ──────────────────────────────────────────────

export function useAlertContext(alertId: string | null) {
  return useQuery({
    queryKey: alertsKeys.context(alertId ?? ""),
    queryFn: () => getAlertContext(alertId!),
    enabled: !!alertId,
    staleTime: 30_000,
  });
}

// ─── Alert timeline ───────────────────────────────────────────────────────────

export function useAlertTimeline(alertId: string | null) {
  return useQuery({
    queryKey: alertsKeys.timeline(alertId ?? ""),
    queryFn: () => getAlertTimeline(alertId!),
    enabled: !!alertId,
    staleTime: 10_000,
    refetchInterval: 15_000,
  });
}

// ─── Prefetch next page ───────────────────────────────────────────────────────

export function usePrefetchAlerts(params: AlertListParams) {
  const qc = useQueryClient();
  return () => {
    const nextParams = { ...params, page: (params.page ?? 1) + 1 };
    void qc.prefetchQuery({
      queryKey: alertsKeys.list(nextParams),
      queryFn: () => getAlerts(nextParams),
      staleTime: 15_000,
    });
  };
}
