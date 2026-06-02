import { useMutation, useQueryClient } from "@tanstack/react-query";
import { bulkUpdateAlerts } from "@/services/alertsApi";
import { alertsKeys } from "./useAlerts";
import type { Alert, AlertListResponse, BulkActionPayload } from "@/features/alerts/types";

export function useBulkAlerts() {
  const qc = useQueryClient();

  return useMutation({
    mutationFn: (payload: BulkActionPayload) => bulkUpdateAlerts(payload),

    onMutate: async (payload) => {
      // Cancel any in-flight list queries
      await qc.cancelQueries({ queryKey: alertsKeys.lists() });

      // Snapshot all cached list pages for rollback
      const snapshots: Array<{ key: unknown[]; data: AlertListResponse }> = [];

      qc.getQueriesData<AlertListResponse>({ queryKey: alertsKeys.lists() }).forEach(
        ([key, data]) => {
          if (data) snapshots.push({ key: key as unknown[], data });
        }
      );

      // Optimistically apply the mutation to every cached list
      qc.setQueriesData<AlertListResponse>(
        { queryKey: alertsKeys.lists() },
        (prev) => {
          if (!prev) return prev;
          const updated = applyOptimisticUpdate(prev.items, payload);
          return { ...prev, items: updated };
        }
      );

      return { snapshots };
    },

    onError: (_err, _payload, ctx) => {
      // Roll back every snapshot
      if (ctx?.snapshots) {
        for (const { key, data } of ctx.snapshots) {
          qc.setQueryData(key, data);
        }
      }
    },

    onSettled: () => {
      void qc.invalidateQueries({ queryKey: alertsKeys.lists() });
    },
  });
}

// ─── Optimistic updater ───────────────────────────────────────────────────────

function applyOptimisticUpdate(items: Alert[], payload: BulkActionPayload): Alert[] {
  const ids = new Set(payload.alertIds);

  return items.map((alert) => {
    if (!ids.has(alert.id)) return alert;

    switch (payload.action) {
      case "close":
        return { ...alert, status: "closed" as const, closedAt: new Date().toISOString() };
      case "reopen":
        return { ...alert, status: "open" as const, closedAt: undefined };
      case "assign":
        return { ...alert, assignedTo: payload.assignTo ?? alert.assignedTo };
      case "mark_true_positive":
        return { ...alert, aiVerdict: { verdict: "true_positive" as const, confidence: 100 } };
      case "mark_false_positive":
        return { ...alert, aiVerdict: { verdict: "false_positive" as const, confidence: 100 } };
      case "add_tag":
        return payload.tag && !alert.tags.includes(payload.tag)
          ? { ...alert, tags: [...alert.tags, payload.tag] }
          : alert;
      case "remove_tag":
        return payload.tag
          ? { ...alert, tags: alert.tags.filter((t) => t !== payload.tag) }
          : alert;
      case "update_severity":
        return payload.severity ? { ...alert, severity: payload.severity } : alert;
      default:
        return alert;
    }
  });
}
