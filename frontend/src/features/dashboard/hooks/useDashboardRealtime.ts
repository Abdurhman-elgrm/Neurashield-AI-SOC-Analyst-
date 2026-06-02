import { useEffect, useRef, useCallback } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useWSManager } from "@/websocket/WSProvider";
import type { LiveAlert } from "@/features/dashboard/types/dashboard";
import type { DashboardTimeRange } from "@/features/dashboard/types/dashboard";
import { dashboardKeys } from "./useDashboardData";

/**
 * Subscribes to realtime events and injects them into the React Query cache.
 * Avoids rerender storms by updating the query cache directly instead of
 * triggering state changes on every event.
 */
export function useDashboardRealtime(timeRange: DashboardTimeRange) {
  const ws = useWSManager();
  const qc = useQueryClient();
  const timeRangeRef = useRef(timeRange);
  timeRangeRef.current = timeRange;

  const injectAlert = useCallback(
    (alert: LiveAlert) => {
      qc.setQueryData<LiveAlert[]>(
        dashboardKeys.alertsFeed(timeRangeRef.current),
        (prev) => {
          if (!prev) return [alert];
          // Prepend + cap at 200 to avoid unbounded growth
          const next = [alert, ...prev.filter((a) => a.id !== alert.id)];
          return next.slice(0, 200);
        }
      );

      // Increment KPI alert counts
      qc.setQueryData(
        dashboardKeys.summary(timeRangeRef.current),
        (prev: Parameters<typeof qc.setQueryData>[1]) => {
          if (!prev || typeof prev !== "object") return prev;
          const summary = prev as { alerts: { total: number; critical: number; open: number; delta24h: number; criticalDelta24h: number; high: number } };
          return {
            ...summary,
            alerts: {
              ...summary.alerts,
              total: summary.alerts.total + 1,
              open:  summary.alerts.open + 1,
              ...(alert.severity === "critical"
                ? { critical: summary.alerts.critical + 1 }
                : {}),
            },
          };
        }
      );
    },
    [qc]
  );

  useEffect(() => {
    const offAlert = ws.on<LiveAlert>("alert.created", (event) => {
      injectAlert(event.payload);
    });

    // Investigation correlations — invalidate summary to pick up new counts
    const offInv = ws.on("investigation.created", () => {
      void qc.invalidateQueries({
        queryKey: dashboardKeys.summary(timeRangeRef.current),
        exact: true,
      });
      void qc.invalidateQueries({
        queryKey: dashboardKeys.correlation(timeRangeRef.current),
        exact: true,
      });
    });

    return () => {
      offAlert();
      offInv();
    };
  }, [ws, qc, injectAlert]);
}
