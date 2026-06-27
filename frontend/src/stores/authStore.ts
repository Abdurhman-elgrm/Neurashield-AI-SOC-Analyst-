import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import type { User } from "@/types/auth";

// Temporary MFA challenge state — holds credentials just long enough for the
// MFA prompt screen.  Never persisted to localStorage.
interface MFAPending {
  email: string;
  password: string;
}

interface AuthState {
  user: User | null;
  accessToken: string | null;
  activeTenantId: string | null;
  // mfaPending is in-memory only (NOT in partialize) — cleared on page reload
  mfaPending: MFAPending | null;

  // Actions
  setAuth: (user: User, accessToken: string) => void;
  setTokens: (accessToken: string) => void;
  setActiveTenant: (tenantId: string | null) => void;
  setUser: (user: User) => void;
  clearAuth: () => void;
  setMFAPending: (pending: MFAPending | null) => void;

  // Computed
  isAuthenticated: () => boolean;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      accessToken: null,
      activeTenantId: null,
      mfaPending: null,

      // refreshToken is intentionally absent from state.
      // It lives exclusively in an httpOnly SameSite=strict cookie set by the server.
      // Storing it in JS memory would expose it to XSS; the cookie is inaccessible to JS.

      setAuth: (user, accessToken) =>
        set({ user, accessToken, mfaPending: null }),

      setTokens: (accessToken) =>
        set({ accessToken }),

      setActiveTenant: (tenantId) =>
        set({ activeTenantId: tenantId }),

      setUser: (user) =>
        set({ user }),

      clearAuth: () =>
        set({
          user: null,
          accessToken: null,
          activeTenantId: null,
          mfaPending: null,
        }),

      setMFAPending: (pending) =>
        set({ mfaPending: pending }),

      isAuthenticated: () => {
        const { accessToken } = get();
        return accessToken !== null;
      },
    }),
    {
      name: "soc-auth",
      storage: createJSONStorage(() => localStorage),
      // Only the active tenant selection persists across reloads. accessToken,
      // user, and mfaPending are intentionally excluded: accessToken must not be
      // in localStorage (XSS readable), user PII has no reason to survive a reload
      // (AuthGuard redirects unauthenticated users to /login before any component
      // renders), and mfaPending must not survive a reload by design.
      partialize: (state) => ({
        activeTenantId: state.activeTenantId,
      }),
    },
  ),
);
