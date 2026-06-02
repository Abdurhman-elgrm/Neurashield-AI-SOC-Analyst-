import { useState, type ReactNode } from "react";
import { X, Clock, ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/Button";
import { SearchInput } from "@/components/ui/Input";
import type {
  ActiveFilter,
  FilterFieldDef,
  FilterState,
  DateRange,
  SavedView,
} from "./types";
import { TIME_PRESETS } from "./types";
import * as Popover from "@radix-ui/react-popover";

// ─── FilterChip ───────────────────────────────────────────────────────────────

function FilterChip({
  filter,
  fieldDef,
  onRemove,
}: {
  filter: ActiveFilter;
  fieldDef?: FilterFieldDef;
  onRemove: () => void;
}) {
  const fieldLabel = fieldDef?.label ?? filter.field;
  const displayValue = Array.isArray(filter.value)
    ? filter.value.join(", ")
    : String(filter.value ?? "");

  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-accent/10 border border-accent/20 text-xs text-accent">
      <span className="text-accent/60">{fieldLabel}:</span>
      <span>{displayValue}</span>
      <button
        onClick={onRemove}
        className="ml-0.5 hover:text-accent-hover transition-colors"
        aria-label={`Remove ${fieldLabel} filter`}
      >
        <X className="w-3 h-3" />
      </button>
    </span>
  );
}

// ─── TimeRangeSelector ────────────────────────────────────────────────────────

function TimeRangeSelector({
  dateRange,
  onChange,
}: {
  dateRange: DateRange | null;
  onChange: (dr: DateRange | null) => void;
}) {
  const [open, setOpen] = useState(false);
  const selected = TIME_PRESETS.find((p) => p.value === dateRange?.preset);

  return (
    <Popover.Root open={open} onOpenChange={setOpen}>
      <Popover.Trigger asChild>
        <Button variant="secondary" size="sm">
          <Clock className="w-3.5 h-3.5" />
          {selected?.label ?? "Time range"}
          <ChevronDown className="w-3 h-3 text-text-muted" />
        </Button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          sideOffset={6}
          align="start"
          className="z-50 min-w-[200px] rounded-lg border border-border bg-bg-elevated shadow-elevated p-1"
        >
          {TIME_PRESETS.map((preset) => (
            <button
              key={preset.value}
              onClick={() => {
                const now = new Date();
                const from = new Date(now.getTime() - preset.minutes * 60 * 1000);
                onChange({ from: from.toISOString(), to: now.toISOString(), preset: preset.value });
                setOpen(false);
              }}
              className={cn(
                "w-full text-left px-3 py-1.5 text-sm rounded transition-colors",
                dateRange?.preset === preset.value
                  ? "text-accent bg-accent/10"
                  : "text-text-secondary hover:bg-bg-subtle hover:text-text-primary"
              )}
            >
              {preset.label}
            </button>
          ))}
          {dateRange && (
            <>
              <div className="-mx-1 my-1 h-px bg-border" />
              <button
                onClick={() => { onChange(null); setOpen(false); }}
                className="w-full text-left px-3 py-1.5 text-sm text-text-muted hover:text-text-primary rounded transition-colors"
              >
                Clear time range
              </button>
            </>
          )}
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

// ─── FilterBar ────────────────────────────────────────────────────────────────

export interface FilterBarProps {
  fields?: FilterFieldDef[];
  filterState: FilterState;
  onFilterChange: (state: FilterState) => void;
  savedViews?: SavedView[];
  onSaveView?: (name: string) => void;
  showSearch?: boolean;
  searchPlaceholder?: string;
  children?: ReactNode;
  className?: string;
}

export function FilterBar({
  fields = [],
  filterState,
  onFilterChange,
  showSearch = true,
  searchPlaceholder = "Search…",
  children,
  className,
}: FilterBarProps) {
  const { search, filters, dateRange } = filterState;

  const removeFilter = (id: string) =>
    onFilterChange({ ...filterState, filters: filters.filter((f) => f.id !== id) });

  const clearAll = () =>
    onFilterChange({ search: "", filters: [], dateRange: null, savedViewId: null });

  const hasActive = filters.length > 0 || !!dateRange || !!search;

  return (
    <div className={cn("flex flex-col gap-2", className)}>
      {/* Main bar */}
      <div className="flex items-center gap-2 flex-wrap">
        {showSearch && (
          <SearchInput
            value={search}
            onChange={(e) => onFilterChange({ ...filterState, search: e.target.value })}
            placeholder={searchPlaceholder}
            className="max-w-[280px]"
          />
        )}

        <TimeRangeSelector
          dateRange={dateRange}
          onChange={(dr) => onFilterChange({ ...filterState, dateRange: dr })}
        />

        {children}

        {hasActive && (
          <Button variant="ghost" size="sm" onClick={clearAll} className="text-text-muted hover:text-severity-critical">
            <X className="w-3.5 h-3.5" />
            Clear all
          </Button>
        )}
      </div>

      {/* Active filter chips */}
      {filters.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {filters.map((f) => (
            <FilterChip
              key={f.id}
              filter={f}
              fieldDef={fields.find((fd) => fd.key === f.field)}
              onRemove={() => removeFilter(f.id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}
