import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { DashboardTimeRange } from "@/features/dashboard/types/dashboard";

interface DashboardState {
  timeRange: DashboardTimeRange;
  lastRefreshAt: Record<string, number>;  // widgetId → unix ms

  setTimeRange: (range: DashboardTimeRange) => void;
  markWidgetRefresh: (widgetId: string) => void;
  getWidgetAge: (widgetId: string) => number; // seconds since last refresh
}

export const useDashboardStore = create<DashboardState>()(
  persist(
    (set, get) => ({
      timeRange: "last_24h",
      lastRefreshAt: {},

      setTimeRange: (range) => set({ timeRange: range }),

      markWidgetRefresh: (widgetId) =>
        set((s) => ({
          lastRefreshAt: { ...s.lastRefreshAt, [widgetId]: Date.now() },
        })),

      getWidgetAge: (widgetId) => {
        const ts = get().lastRefreshAt[widgetId];
        if (!ts) return Infinity;
        return Math.floor((Date.now() - ts) / 1000);
      },
    }),
    {
      name: "soc-dashboard",
      partialize: (s) => ({ timeRange: s.timeRange }),
    }
  )
);
