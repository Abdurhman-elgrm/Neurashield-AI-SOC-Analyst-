import type { ColumnDef, SortingState, VisibilityState, RowSelectionState, PaginationState, ColumnFiltersState } from "@tanstack/react-table";

export type { ColumnDef, SortingState, VisibilityState, RowSelectionState, PaginationState, ColumnFiltersState };

export interface DataTableProps<TData> {
  data: TData[];
  columns: ColumnDef<TData, unknown>[];
  // Pagination
  pageCount?: number;           // total pages (server-side)
  pagination?: PaginationState;
  onPaginationChange?: (p: PaginationState) => void;
  manualPagination?: boolean;
  // Sorting
  sorting?: SortingState;
  onSortingChange?: (s: SortingState) => void;
  manualSorting?: boolean;
  // Column filters
  columnFilters?: ColumnFiltersState;
  onColumnFiltersChange?: (f: ColumnFiltersState) => void;
  // Row selection
  rowSelection?: RowSelectionState;
  onRowSelectionChange?: (s: RowSelectionState) => void;
  enableRowSelection?: boolean;
  // Column visibility
  columnVisibility?: VisibilityState;
  onColumnVisibilityChange?: (v: VisibilityState) => void;
  // Features
  enableVirtualization?: boolean;
  stickyHeader?: boolean;
  onRowClick?: (row: TData) => void;
  getRowId?: (row: TData) => string;
  getRowClassName?: (row: TData) => string;
  // Loading
  isLoading?: boolean;
  // Realtime
  realtimeKey?: string | number;    // when changed, flash new rows
  className?: string;
}

export interface DataTableToolbarProps {
  globalFilter?: string;
  onGlobalFilterChange?: (v: string) => void;
  selectedCount?: number;
  totalCount?: number;
  bulkActions?: BulkAction[];
  children?: React.ReactNode;
}

export interface BulkAction {
  id: string;
  label: string;
  icon?: React.ReactNode;
  variant?: "primary" | "danger" | "secondary";
  onClick: (selectedIds: string[]) => void;
}
