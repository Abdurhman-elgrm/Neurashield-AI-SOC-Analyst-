import { create } from "zustand";
import type { PresenceState, WSConnectionState } from "@/types/realtime";

interface RealtimeState {
  connectionState: WSConnectionState;
  onlineCount: number;
  onlineAnalysts: PresenceState[];

  setConnectionState: (s: WSConnectionState) => void;
  setOnlineCount: (n: number) => void;
  addOnlineAnalyst: (p: PresenceState) => void;
  removeOnlineAnalyst: (analystId: string) => void;
  updateAnalystPresence: (analystId: string, patch: Partial<PresenceState>) => void;
  clearPresence: () => void;
}

export const useRealtimeStore = create<RealtimeState>()((set) => ({
  connectionState: "disconnected",
  onlineCount: 0,
  onlineAnalysts: [],

  setConnectionState: (connectionState) => set({ connectionState }),

  setOnlineCount: (onlineCount) => set({ onlineCount }),

  addOnlineAnalyst: (presence) =>
    set((s) => {
      const exists = s.onlineAnalysts.some(
        (a) => a.analyst_id === presence.analyst_id
      );
      if (exists) {
        return {
          onlineAnalysts: s.onlineAnalysts.map((a) =>
            a.analyst_id === presence.analyst_id ? presence : a
          ),
        };
      }
      return {
        onlineAnalysts: [...s.onlineAnalysts, presence],
        onlineCount: s.onlineCount + 1,
      };
    }),

  removeOnlineAnalyst: (analystId) =>
    set((s) => ({
      onlineAnalysts: s.onlineAnalysts.filter(
        (a) => a.analyst_id !== analystId
      ),
      onlineCount: Math.max(0, s.onlineCount - 1),
    })),

  updateAnalystPresence: (analystId, patch) =>
    set((s) => ({
      onlineAnalysts: s.onlineAnalysts.map((a) =>
        a.analyst_id === analystId ? { ...a, ...patch } : a
      ),
    })),

  clearPresence: () =>
    set({ onlineAnalysts: [], onlineCount: 0, connectionState: "disconnected" }),
}));
