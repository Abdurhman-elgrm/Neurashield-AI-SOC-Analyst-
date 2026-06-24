import { useRef } from "react";
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { cn } from "@/lib/utils";
import { SkeletonTable } from "@/components/ui/Skeleton";
import type { DataTableProps } from "./types";

const ROW_ESTIMATE_SIZE = 44;

export function DataTable<TData>({
  data,
  columns,
  pageCount,
  pagination,
  onPaginationChange,
  manualPagination = false,
  sorting,
  onSortingChange,
  manualSorting = false,
  columnFilters,
  onColumnFiltersChange,
  rowSelection,
  onRowSelectionChange,
  enableRowSelection = false,
  columnVisibility,
  onColumnVisibilityChange,
  enableVirtualization = false,
  stickyHeader = true,
  onRowClick,
  onRowMouseEnter,
  onRowMouseLeave,
  highlightRowId,
  getRowId,
  isLoading = false,
  emptyMessage = "No results found",
  getRowClassName,
  className,
}: DataTableProps<TData>) {
  const tableContainerRef = useRef<HTMLDivElement>(null);

  const table = useReactTable({
    data,
    columns,
    pageCount: pageCount ?? -1,
    state: {
      pagination,
      sorting,
      columnFilters,
      rowSelection: rowSelection ?? {},
      columnVisibility: columnVisibility ?? {},
    },
    onPaginationChange: onPaginationChange as any,
    onSortingChange: onSortingChange as any,
    onColumnFiltersChange: onColumnFiltersChange as any,
    onRowSelectionChange: onRowSelectionChange as any,
    onColumnVisibilityChange: onColumnVisibilityChange as any,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: manualPagination ? undefined : getPaginationRowModel(),
    manualPagination,
    manualSorting,
    enableRowSelection,
    getRowId,
  });

  const { rows } = table.getRowModel();

  const virtualizer = useVirtualizer({
    count: enableVirtualization ? rows.length : 0,
    getScrollElement: () => tableContainerRef.current,
    estimateSize: () => ROW_ESTIMATE_SIZE,
    overscan: 10,
  });

  const virtualRows = enableVirtualization ? virtualizer.getVirtualItems() : null;
  const totalSize = enableVirtualization ? virtualizer.getTotalSize() : 0;
  const paddingTop = virtualRows && virtualRows.length > 0 ? virtualRows[0].start : 0;
  const paddingBottom =
    virtualRows && virtualRows.length > 0
      ? totalSize - virtualRows[virtualRows.length - 1].end
      : 0;

  if (isLoading) {
    return <SkeletonTable rows={8} cols={columns.length} />;
  }

  const renderRows = enableVirtualization
    ? virtualRows!.map((vRow) => rows[vRow.index])
    : rows;

  return (
    <div
      ref={tableContainerRef}
      className={cn(
        "overflow-auto",
        enableVirtualization && "h-full",
        className
      )}
    >
      <table className="w-full border-collapse text-sm">
        <thead
          className={cn(
            "bg-bg-surface",
            stickyHeader && "sticky top-0 z-10"
          )}
        >
          {table.getHeaderGroups().map((headerGroup) => (
            <tr key={headerGroup.id} className="border-b border-border">
              {headerGroup.headers.map((header) => (
                <th
                  key={header.id}
                  className={cn(
                    "px-3 py-2.5 text-left text-xs font-medium text-text-muted whitespace-nowrap",
                    header.column.getCanSort() && "cursor-pointer select-none hover:text-text-secondary"
                  )}
                  style={{ width: header.getSize() }}
                  onClick={header.column.getToggleSortingHandler()}
                >
                  <div className="flex items-center gap-1">
                    {flexRender(header.column.columnDef.header, header.getContext())}
                    {header.column.getCanSort() && (
                      <span className="text-text-muted/60">
                        {header.column.getIsSorted() === "asc" && " ↑"}
                        {header.column.getIsSorted() === "desc" && " ↓"}
                        {!header.column.getIsSorted() && " ↕"}
                      </span>
                    )}
                  </div>
                </th>
              ))}
            </tr>
          ))}
        </thead>

        <tbody>
          {enableVirtualization && paddingTop > 0 && (
            <tr><td style={{ height: paddingTop }} /></tr>
          )}

          {renderRows.map((row) => (
            <tr
              key={row.id}
              onClick={() => onRowClick?.(row.original)}
              onMouseEnter={(e) => onRowMouseEnter?.(row.original, e)}
              onMouseLeave={(e) => onRowMouseLeave?.(row.original, e)}
              data-selected={row.getIsSelected()}
              className={cn(
                "border-b border-border transition-colors duration-100",
                "hover:bg-bg-elevated",
                onRowClick && "cursor-pointer",
                row.getIsSelected() && "bg-accent/5",
                highlightRowId && getRowId?.(row.original) === highlightRowId && "bg-accent/5",
                getRowClassName?.(row.original)
              )}
            >
              {row.getVisibleCells().map((cell) => (
                <td key={cell.id} className="px-3 py-2.5 text-text-secondary">
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </td>
              ))}
            </tr>
          ))}

          {renderRows.length === 0 && (
            <tr>
              <td
                colSpan={columns.length}
                className="px-3 py-12 text-center text-sm text-text-muted"
              >
                {emptyMessage}
              </td>
            </tr>
          )}

          {enableVirtualization && paddingBottom > 0 && (
            <tr><td style={{ height: paddingBottom }} /></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
