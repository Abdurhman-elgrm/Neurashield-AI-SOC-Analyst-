// ─── API Response Envelope ────────────────────────────────────────────────────

export interface ResponseMeta {
  request_id: string;
  timestamp: string;
}

export interface ErrorDetail {
  code: string;
  message: string;
  details?: ValidationFieldError[] | Record<string, unknown> | null;
}

export interface ValidationFieldError {
  field: string;
  message: string;
  type: string;
}

export interface APIResponse<T> {
  data: T | null;
  error: ErrorDetail | null;
  meta: ResponseMeta;
}

// ─── Pagination ───────────────────────────────────────────────────────────────

export interface CursorPagination {
  next_cursor: string | null;
  prev_cursor: string | null;
  has_more: boolean;
  limit: number;
}

export interface OffsetPagination {
  page: number;
  limit: number;
  total: number;
  pages: number;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: CursorPagination | OffsetPagination;
  meta: ResponseMeta;
}

// ─── Query params ─────────────────────────────────────────────────────────────

export interface PaginationParams {
  page?: number;
  limit?: number;
}

export interface DateRangeParams {
  from?: string;
  to?: string;
  since?: string; // relative: "1h" | "24h" | "7d" | "30d"
}
