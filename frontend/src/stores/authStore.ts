import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import type { User } from "@/types/auth";

interface AuthState {
  user: User | null;
  accessToken: string | null;
  refreshToken: string | null;
  activeTenantId: string | null;

  // Actions
  setAuth: (user: User, accessToken: string, refreshToken: string) => void;
  setTokens: (accessToken: string, refreshToken: string) => void;
  setActiveTenant: (tenantId: string | null) => void;
  clearAuth: () => void;

  // Computed
  isAuthenticated: () => boolean;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      activeTenantId: null,

      setAuth: (user, accessToken, refreshToken) =>
        set({ user, accessToken, refreshToken }),

      setTokens: (accessToken, refreshToken) =>
        set({ accessToken, refreshToken }),

      setActiveTenant: (tenantId) =>
        set({ activeTenantId: tenantId }),

      clearAuth: () =>
        set({
          user: null,
          accessToken: null,
          refreshToken: null,
          activeTenantId: null,
        }),

      isAuthenticated: () => {
        const { accessToken } = get();
        return accessToken !== null;
      },
    }),
    {
      name: "soc-auth",
      storage: createJSONStorage(() => localStorage),
      // Only persist tokens and active tenant — not full user object
      // (user profile is re-fetched on app init)
      partialize: (state) => ({
        accessToken: state.accessToken,
        refreshToken: state.refreshToken,
        activeTenantId: state.activeTenantId,
        user: state.user,
      }),
    },
  ),
);
