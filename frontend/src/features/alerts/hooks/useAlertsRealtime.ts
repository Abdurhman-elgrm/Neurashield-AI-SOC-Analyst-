import { useEffect, useRef } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useWSManager } from "@/websocket/WSProvider";
import { alertsKeys } from "./useAlerts";
import type { Alert, AlertListResponse } from "@/features/alerts/types";

interface UseAlertsRealtimeOptions {
  onNewAlert?: (alert: Alert) => void;
}

export function useAlertsRealtime({ onNewAlert }: UseAlertsRealtimeOptions = {}) {
  const ws = useWSManager();
  const qc = useQueryClient();
  const onNewAlertRef = useRef(onNewAlert);
  onNewAlertRef.current = onNewAlert;

  useEffect(() => {
    // New alert created — prepend to first page, update total count
    const offCreated = ws.on<Alert>("alert.created", (event) => {
      const alert = event.payload;

      qc.setQueriesData<AlertListResponse>(
        { queryKey: alertsKeys.lists() },
        (prev) => {
          if (!prev) return prev;
          const alreadyExists = prev.items.some((a) => a.id === alert.id);
          if (alreadyExists) return prev;
          return {
            ...prev,
            total: prev.total + 1,
            items: [alert, ...prev.items],
          };
        }
      );

      onNewAlertRef.current?.(alert);
    });

    // Alert updated (status change, assignment, AI verdict) — patch in-place
    const offUpdated = ws.on<Alert>("alert.updated", (event) => {
      const updated = event.payload;

      qc.setQueriesData<AlertListResponse>(
        { queryKey: alertsKeys.lists() },
        (prev) => {
          if (!prev) return prev;
          return {
            ...prev,
            items: prev.items.map((a) => (a.id === updated.id ? updated : a)),
          };
        }
      );

      // Also patch detail cache if this alert is open in a drawer
      qc.setQueryData<Alert>(alertsKeys.detail(updated.id), (prev) =>
        prev ? { ...prev, ...updated } : prev
      );
    });

    // Investigation created — invalidate context for any open alert
    const offInv = ws.on("investigation.created", () => {
      void qc.invalidateQueries({ queryKey: [...alertsKeys.all, "context"] });
    });

    return () => {
      offCreated();
      offUpdated();
      offInv();
    };
  }, [ws, qc]);
}
