// ─── Filter engine types ──────────────────────────────────────────────────────

export type FilterOperator =
  | "eq"     // equals
  | "neq"    // not equals
  | "in"     // one of
  | "not_in"
  | "contains"
  | "starts_with"
  | "gte"    // >=
  | "lte"    // <=
  | "between"
  | "is_null"
  | "is_not_null";

export type FilterFieldType =
  | "string"
  | "number"
  | "enum"
  | "date"
  | "boolean";

export interface FilterFieldDef {
  key: string;
  label: string;
  type: FilterFieldType;
  operators?: FilterOperator[];
  options?: { value: string; label: string }[];  // for enum fields
  placeholder?: string;
}

export interface ActiveFilter {
  id: string;         // unique id for this filter instance
  field: string;      // key from FilterFieldDef
  operator: FilterOperator;
  value: string | string[] | number | [number, number] | null;
  label?: string;     // display label
}

export interface FilterState {
  search: string;
  filters: ActiveFilter[];
  dateRange: DateRange | null;
  savedViewId: string | null;
}

export interface DateRange {
  from: string | null;
  to: string | null;
  preset?: TimePreset;
}

export type TimePreset =
  | "last_15m"
  | "last_1h"
  | "last_4h"
  | "last_24h"
  | "last_7d"
  | "last_30d"
  | "last_90d"
  | "custom";

export const TIME_PRESETS: { value: TimePreset; label: string; minutes: number }[] = [
  { value: "last_15m",  label: "Last 15 minutes", minutes: 15 },
  { value: "last_1h",   label: "Last hour",        minutes: 60 },
  { value: "last_4h",   label: "Last 4 hours",     minutes: 240 },
  { value: "last_24h",  label: "Last 24 hours",    minutes: 1440 },
  { value: "last_7d",   label: "Last 7 days",      minutes: 10080 },
  { value: "last_30d",  label: "Last 30 days",     minutes: 43200 },
  { value: "last_90d",  label: "Last 90 days",     minutes: 129600 },
];

export interface SavedView {
  id: string;
  name: string;
  filters: ActiveFilter[];
  dateRange: DateRange | null;
  search: string;
  isDefault?: boolean;
}
