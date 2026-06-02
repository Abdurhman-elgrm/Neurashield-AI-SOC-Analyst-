import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { SearchInput } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import type { BulkAction } from "./types";

export interface TableToolbarProps {
  globalFilter?: string;
  onGlobalFilterChange?: (v: string) => void;
  searchPlaceholder?: string;
  selectedCount?: number;
  totalCount?: number;
  bulkActions?: BulkAction[];
  selectedIds?: string[];
  left?: ReactNode;
  right?: ReactNode;
  className?: string;
}

export function TableToolbar({
  globalFilter,
  onGlobalFilterChange,
  searchPlaceholder = "Search…",
  selectedCount = 0,
  totalCount,
  bulkActions,
  selectedIds = [],
  left,
  right,
  className,
}: TableToolbarProps) {
  const hasSelection = selectedCount > 0;

  return (
    <div
      className={cn(
        "flex items-center justify-between gap-3 px-1 py-2",
        className
      )}
    >
      {/* Left side */}
      <div className="flex items-center gap-2 flex-1 min-w-0">
        {onGlobalFilterChange && (
          <SearchInput
            value={globalFilter ?? ""}
            onChange={(e) => onGlobalFilterChange(e.target.value)}
            placeholder={searchPlaceholder}
            className="max-w-[280px]"
          />
        )}
        {left}
      </div>

      {/* Center: bulk actions when rows are selected */}
      {hasSelection && bulkActions && (
        <div className="flex items-center gap-1.5 px-3 py-1 rounded bg-bg-elevated border border-border">
          <span className="text-xs text-text-muted mr-1.5">{selectedCount} selected</span>
          {bulkActions.map((action) => (
            <Button
              key={action.id}
              variant={action.variant ?? "ghost"}
              size="xs"
              onClick={() => action.onClick(selectedIds)}
            >
              {action.icon}
              {action.label}
            </Button>
          ))}
        </div>
      )}

      {/* Right side */}
      <div className="flex items-center gap-2">
        {totalCount !== undefined && (
          <span className="text-xs text-text-muted whitespace-nowrap">
            {totalCount.toLocaleString()} results
          </span>
        )}
        {right}
      </div>
    </div>
  );
}
