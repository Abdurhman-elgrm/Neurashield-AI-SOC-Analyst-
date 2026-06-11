import axios, {
  AxiosError,
  AxiosInstance,
  AxiosResponse,
  InternalAxiosRequestConfig,
} from "axios";
import { useAuthStore } from "@/stores/authStore";
import { useTenantStore } from "@/stores/tenantStore";
import type { APIResponse } from "@/types/api";

const API_BASE_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
const API_PREFIX = "/api/v1";

// Log the resolved base URL so it's visible in browser DevTools console.
console.info(`[API] Base URL: ${API_BASE_URL}${API_PREFIX}`);
if (!import.meta.env.VITE_API_URL) {
  if (import.meta.env.PROD) {
    console.error("[API] VITE_API_URL is not set — falling back to http://localhost:8000 which will fail in production. Set VITE_API_URL in Railway frontend Variables.");
  } else {
    console.warn("[API] VITE_API_URL not set — using localhost fallback.");
  }
}

// ─── Axios instance ───────────────────────────────────────────────────────────

export const apiClient: AxiosInstance = axios.create({
  baseURL: `${API_BASE_URL}${API_PREFIX}`,
  headers: {
    "Content-Type": "application/json",
  },
  timeout: 30000,
});

// ─── Request interceptor — attach access token ────────────────────────────────

apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const token = useAuthStore.getState().accessToken;
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    // Prefer in-memory tenantStore (current session); fall back to persisted authStore value
    const tenantId =
      useTenantStore.getState().activeTenant?.id ??
      useAuthStore.getState().activeTenantId;
    if (tenantId) {
      config.headers["X-Tenant-ID"] = tenantId;
    }

    return config;
  },
  (error) => Promise.reject(error),
);

// ─── Response interceptor — token refresh on 401 ─────────────────────────────

let isRefreshing = false;
let refreshSubscribers: Array<(token: string) => void> = [];

function subscribeTokenRefresh(cb: (token: string) => void): void {
  refreshSubscribers.push(cb);
}

function onRefreshComplete(token: string): void {
  refreshSubscribers.forEach((cb) => cb(token));
  refreshSubscribers = [];
}

apiClient.interceptors.response.use(
  (response: AxiosResponse) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & {
      _retried?: boolean;
    };

    // Only attempt refresh on 401, and not on auth endpoints themselves
    if (
      error.response?.status === 401 &&
      !originalRequest._retried &&
      !originalRequest.url?.includes("/auth/")
    ) {
      const refreshToken = useAuthStore.getState().refreshToken;
      if (!refreshToken) {
        useAuthStore.getState().clearAuth();
        return Promise.reject(error);
      }

      if (isRefreshing) {
        // Queue this request until refresh completes
        return new Promise((resolve) => {
          subscribeTokenRefresh((newToken) => {
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
            resolve(apiClient(originalRequest));
          });
        });
      }

      originalRequest._retried = true;
      isRefreshing = true;

      try {
        const response = await axios.post<APIResponse<{
          access_token: string;
          refresh_token: string;
          token_type: string;
          expires_in: number;
        }>>(`${API_BASE_URL}${API_PREFIX}/auth/refresh`, {
          refresh_token: refreshToken,
        });

        const tokens = response.data.data!;
        useAuthStore.getState().setTokens(tokens.access_token, tokens.refresh_token);
        onRefreshComplete(tokens.access_token);

        originalRequest.headers.Authorization = `Bearer ${tokens.access_token}`;
        return apiClient(originalRequest);
      } catch {
        useAuthStore.getState().clearAuth();
        return Promise.reject(error);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  },
);

// ─── Typed request helpers ────────────────────────────────────────────────────

export async function apiGet<T>(url: string, params?: Record<string, unknown>): Promise<T> {
  const response = await apiClient.get<APIResponse<T>>(url, { params });
  if (response.data.error) {
    throw new ApiError(response.data.error.code, response.data.error.message, response.data.error.details);
  }
  return response.data.data as T;
}

export async function apiPost<T>(url: string, data?: unknown): Promise<T> {
  const response = await apiClient.post<APIResponse<T>>(url, data);
  if (response.data.error) {
    throw new ApiError(response.data.error.code, response.data.error.message, response.data.error.details);
  }
  return response.data.data as T;
}

export async function apiPatch<T>(url: string, data?: unknown): Promise<T> {
  const response = await apiClient.patch<APIResponse<T>>(url, data);
  if (response.data.error) {
    throw new ApiError(response.data.error.code, response.data.error.message, response.data.error.details);
  }
  return response.data.data as T;
}

export async function apiDelete<T = void>(url: string): Promise<T> {
  const response = await apiClient.delete<APIResponse<T>>(url);
  if (response.data.error) {
    throw new ApiError(response.data.error.code, response.data.error.message, response.data.error.details);
  }
  return response.data.data as T;
}

// ─── API Error class ──────────────────────────────────────────────────────────

export class ApiError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}
