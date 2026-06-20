import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

export function formatDate(date: string | Date): string {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(date));
}

export function formatRelativeTime(date: string | Date): string {
  const now  = Date.now();
  const then = new Date(date).getTime();
  const diff = now - then; // positive = past, negative = future

  // Future date (e.g. invitation expiry)
  if (diff < 0) {
    const abs     = Math.abs(diff);
    const seconds = Math.floor(abs / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours   = Math.floor(minutes / 60);
    const days    = Math.floor(hours / 24);
    if (seconds < 60)  return "in a moment";
    if (minutes < 60)  return `in ${minutes}m`;
    if (hours < 24)    return `in ${hours}h`;
    if (days < 7)      return `in ${days}d`;
    return formatDate(date);
  }

  // Past date
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours   = Math.floor(minutes / 60);
  const days    = Math.floor(hours / 24);
  if (seconds < 60) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24)   return `${hours}h ago`;
  if (days < 7)     return `${days}d ago`;
  return formatDate(date);
}

export function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength) + "…";
}

// Fallback messages for known API error codes when the backend message is absent.
const API_ERROR_FALLBACKS: Record<string, string> = {
  UNAUTHORIZED:        "Your session has expired. Please sign in again.",
  FORBIDDEN:           "You don't have permission to perform this action.",
  NOT_FOUND:           "The requested resource was not found.",
  CONFLICT:            "This action conflicts with existing data.",
  VALIDATION_ERROR:    "Please check the information you entered and try again.",
  RATE_LIMIT_EXCEEDED: "Too many attempts. Please wait a moment and try again.",
  SERVICE_UNAVAILABLE: "The service is temporarily unavailable. Please try again shortly.",
  AGENT_LOCKED:        "This agent is currently locked by another operation.",
  INTERNAL_ERROR:      "Something went wrong on our end. Please try again.",
};

// Readable messages for Axios network-level errors (no server response).
function _axiosNetworkMessage(error: Record<string, unknown>): string | null {
  const code = error["code"];
  if (code === "ECONNABORTED" || String(error["message"] ?? "").includes("timeout"))
    return "The request timed out. Please check your connection and try again.";
  if (code === "ERR_NETWORK" || String(error["message"] ?? "").toLowerCase().includes("network"))
    return "Unable to reach the server. Please check your internet connection.";
  return null;
}

export function extractApiError(error: unknown): string {
  if (error == null) return "An unexpected error occurred.";

  // ApiError thrown by apiGet/apiPost when the 2xx response body contains an error field.
  if (error instanceof Error && error.name === "ApiError") return error.message;

  if (typeof error === "object") {
    const err = error as Record<string, unknown>;

    // AxiosError with a server response — read the structured API envelope.
    const response = err["response"] as Record<string, unknown> | null | undefined;
    if (response != null) {
      const data = response["data"] as Record<string, unknown> | null | undefined;
      const apiErr = data?.["error"] as Record<string, unknown> | null | undefined;

      // Prefer the backend's human-readable message.
      const msg = apiErr?.["message"];
      if (typeof msg === "string" && msg.length > 0) return msg;

      // Fall back to a mapped message based on the error code.
      const code = apiErr?.["code"];
      if (typeof code === "string" && API_ERROR_FALLBACKS[code]) return API_ERROR_FALLBACKS[code];

      // Last resort for HTTP errors: generic but not technical.
      const status = response["status"];
      if (status === 401) return API_ERROR_FALLBACKS.UNAUTHORIZED;
      if (status === 403) return API_ERROR_FALLBACKS.FORBIDDEN;
      if (status === 404) return API_ERROR_FALLBACKS.NOT_FOUND;
      if (status === 409) return API_ERROR_FALLBACKS.CONFLICT;
      if (status === 422) return API_ERROR_FALLBACKS.VALIDATION_ERROR;
      if (status === 429) return API_ERROR_FALLBACKS.RATE_LIMIT_EXCEEDED;
      if (Number(status) >= 500) return API_ERROR_FALLBACKS.INTERNAL_ERROR;
    }

    // AxiosError without a server response (network error, timeout, CORS).
    const netMsg = _axiosNetworkMessage(err);
    if (netMsg) return netMsg;
  }

  if (error instanceof Error) {
    // Don't surface raw Axios/browser messages like "Request failed with status code 429".
    if (/request failed|status code|network error/i.test(error.message))
      return "Something went wrong. Please try again.";
    return error.message;
  }

  if (typeof error === "string") return error;
  return "Something went wrong. Please try again.";
}

// Returns the machine-readable error code from an API error, or null.
export function getApiErrorCode(error: unknown): string | null {
  if (error instanceof Error && error.name === "ApiError") {
    return (error as unknown as { code?: string }).code ?? null;
  }
  if (error != null && typeof error === "object") {
    const response = (error as Record<string, unknown>)["response"] as Record<string, unknown> | null | undefined;
    const data = response?.["data"] as Record<string, unknown> | null | undefined;
    const code = (data?.["error"] as Record<string, unknown> | null | undefined)?.["code"];
    return typeof code === "string" ? code : null;
  }
  return null;
}
