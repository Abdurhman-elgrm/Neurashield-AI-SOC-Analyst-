import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { DashboardTimeRange } from "@/features/dashboard/types/dashboard";

interface DashboardState {
  timeRange: DashboardTimeRange;
  setTimeRange: (range: DashboardTimeRange) => void;
}

export const useDashboardStore = create<DashboardState>()(
  persist(
    (set) => ({
      timeRange: "last_24h",
      setTimeRange: (range) => set({ timeRange: range }),
    }),
    {
      name: "soc-dashboard",
      partialize: (s) => ({ timeRange: s.timeRange }),
    }
  )
);
