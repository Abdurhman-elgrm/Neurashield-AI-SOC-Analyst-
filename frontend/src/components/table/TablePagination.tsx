import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { cn } from "@/lib/utils";
import type { PaginationState } from "./types";

export interface TablePaginationProps {
  pagination: PaginationState;
  pageCount: number;
  onPaginationChange: (p: PaginationState) => void;
  totalRows?: number;
  pageSizeOptions?: number[];
  className?: string;
}

export function TablePagination({
  pagination,
  pageCount,
  onPaginationChange,
  totalRows,
  pageSizeOptions = [10, 25, 50, 100],
  className,
}: TablePaginationProps) {
  const { pageIndex, pageSize } = pagination;
  const canPrev = pageIndex > 0;
  const canNext = pageIndex < pageCount - 1;

  const setPage = (idx: number) =>
    onPaginationChange({ ...pagination, pageIndex: idx });
  const setPageSize = (size: number) =>
    onPaginationChange({ pageIndex: 0, pageSize: size });

  // Compute visible page numbers (window of 5)
  const pages = usePagination(pageIndex, pageCount);

  const startRow = pageIndex * pageSize + 1;
  const endRow = Math.min((pageIndex + 1) * pageSize, totalRows ?? (pageIndex + 1) * pageSize);

  return (
    <div className={cn("flex items-center justify-between px-1 py-2 text-xs text-text-muted", className)}>
      {/* Row info */}
      <div className="hidden sm:block">
        {totalRows !== undefined
          ? `${startRow}–${endRow} of ${totalRows.toLocaleString()}`
          : `Page ${pageIndex + 1} of ${pageCount}`}
      </div>

      {/* Page controls */}
      <div className="flex items-center gap-1">
        <Button
          variant="ghost"
          size="icon-sm"
          onClick={() => setPage(0)}
          disabled={!canPrev}
          aria-label="First page"
        >
          <ChevronsLeft className="w-3.5 h-3.5" />
        </Button>
        <Button
          variant="ghost"
          size="icon-sm"
          onClick={() => setPage(pageIndex - 1)}
          disabled={!canPrev}
          aria-label="Previous page"
        >
          <ChevronLeft className="w-3.5 h-3.5" />
        </Button>

        <div className="flex items-center gap-0.5">
          {pages.map((p, i) =>
            p === "ellipsis" ? (
              <span key={`e-${i}`} className="px-1">…</span>
            ) : (
              <button
                key={p}
                onClick={() => setPage(p as number)}
                className={cn(
                  "w-6 h-6 rounded text-xs transition-colors",
                  p === pageIndex
                    ? "bg-accent text-white font-medium"
                    : "hover:bg-bg-subtle text-text-muted"
                )}
              >
                {(p as number) + 1}
              </button>
            )
          )}
        </div>

        <Button
          variant="ghost"
          size="icon-sm"
          onClick={() => setPage(pageIndex + 1)}
          disabled={!canNext}
          aria-label="Next page"
        >
          <ChevronRight className="w-3.5 h-3.5" />
        </Button>
        <Button
          variant="ghost"
          size="icon-sm"
          onClick={() => setPage(pageCount - 1)}
          disabled={!canNext}
          aria-label="Last page"
        >
          <ChevronsRight className="w-3.5 h-3.5" />
        </Button>
      </div>

      {/* Page size selector */}
      <div className="flex items-center gap-2">
        <span>Rows:</span>
        <select
          value={pageSize}
          onChange={(e) => setPageSize(Number(e.target.value))}
          className="bg-bg-elevated border border-border rounded px-1.5 py-0.5 text-xs text-text-primary focus:outline-none focus:border-accent"
        >
          {pageSizeOptions.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>
    </div>
  );
}

function usePagination(current: number, total: number): (number | "ellipsis")[] {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i);
  const pages: (number | "ellipsis")[] = [];
  if (current <= 3) {
    pages.push(0, 1, 2, 3, 4, "ellipsis", total - 1);
  } else if (current >= total - 4) {
    pages.push(0, "ellipsis", total - 5, total - 4, total - 3, total - 2, total - 1);
  } else {
    pages.push(0, "ellipsis", current - 1, current, current + 1, "ellipsis", total - 1);
  }
  return pages;
}
