import { useState, useCallback, useRef } from "react";
import { Bell } from "lucide-react";
import { cn } from "@/lib/utils";
import { DataTable } from "@/components/table/DataTable";
import { TablePagination } from "@/components/table/TablePagination";
import { FilterBar } from "@/components/filters/FilterBar";
import { alertColumns } from "./alertColumns";
import { ALERT_FILTER_FIELDS } from "./alertFilterFields";
import { AlertDrawer } from "./components/AlertDrawer";
import { BulkActionBar } from "./components/BulkActionBar";
import { NewAlertsIndicator } from "./components/NewAlertsIndicator";
import { useAlertsList } from "./hooks/useAlerts";
import { useAlertsRealtime } from "./hooks/useAlertsRealtime";
import type { Alert, AlertSeverity, AlertStatus, AlertListParams } from "./types";
import type { FilterState, ActiveFilter } from "@/components/filters/types";
import type { PaginationState, RowSelectionState } from "@/components/table/types";

// ─── Row severity highlighting ────────────────────────────────────────────────

function getAlertRowClassName(alert: Alert): string {
  switch (alert.severity) {
    case "critical":
      return "border-l-2 border-l-severity-critical bg-severity-critical/[0.03]";
    case "high":
      return "border-l-2 border-l-severity-high";
    default:
      return "";
  }
}

// ─── Filter state → API params conversion ─────────────────────────────────────

function filtersToParams(filterState: FilterState, pagination: PaginationState): AlertListParams {
  const params: AlertListParams = {
    page: pagination.pageIndex + 1,
    pageSize: pagination.pageSize,
    sort: "-created_at",
    search: filterState.search || undefined,
  };

  for (const f of filterState.filters) {
    const value = f.value;
    switch (f.field) {
      case "severity":
        params.severity = (Array.isArray(value) ? value : [value]) as AlertSeverity[];
        break;
      case "status":
        params.status = (Array.isArray(value) ? value : [value]) as AlertStatus[];
        break;
      case "hostname":
        params.hostname = String(value ?? "");
        break;
      case "username":
        params.username = String(value ?? "");
        break;
      case "source_ip":
        params.sourceIp = String(value ?? "");
        break;
      case "mitre_technique":
        params.mitreTechnique = String(value ?? "");
        break;
      case "assigned_to":
        params.assignedTo = String(value ?? "");
        break;
    }
  }

  if (filterState.dateRange?.preset) {
    params.timeRange = filterState.dateRange.preset;
  }

  return params;
}

// ─── AlertsPage ───────────────────────────────────────────────────────────────

export function AlertsPage() {
  const [filterState, setFilterState] = useState<FilterState>({
    search: "",
    filters: [] as ActiveFilter[],
    dateRange: null,
    savedViewId: null,
  });
  const [pagination, setPagination] = useState<PaginationState>({
    pageIndex: 0,
    pageSize: 50,
  });
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);

  const [newAlertCount, setNewAlertCount] = useState(0);
  const newAlertsSince = useRef<Date | null>(null);

  const queryParams = filtersToParams(filterState, pagination);
  const { data, isLoading } = useAlertsList(queryParams);

  const handleNewAlert = useCallback((_alert: Alert) => {
    setNewAlertCount((n) => n + 1);
    if (!newAlertsSince.current) newAlertsSince.current = new Date();
  }, []);

  useAlertsRealtime({ onNewAlert: handleNewAlert });

  const selectedIds = Object.keys(rowSelection).filter((k) => rowSelection[k]);

  const handleFilterChange = (next: FilterState) => {
    setFilterState(next);
    setPagination((p) => ({ ...p, pageIndex: 0 }));
  };

  return (
    <div className="flex flex-col h-full gap-4">
      {/* Page header */}
      <div className="flex items-center justify-between flex-wrap gap-3 flex-shrink-0">
        <div>
          <h1 className="page-title flex items-center gap-2">
            <Bell className="w-5 h-5" />
            Alerts
          </h1>
          <p className="text-sm text-text-secondary mt-0.5">
            {data?.total != null ? (
              <span>
                <span className="text-text-primary font-medium tabular-nums">{data.total}</span>{" "}
                alerts total
              </span>
            ) : (
              "Security alert triage workspace"
            )}
          </p>
        </div>

        <NewAlertsIndicator
          count={newAlertCount}
          since={newAlertsSince.current}
          onDismiss={() => {
            setNewAlertCount(0);
            newAlertsSince.current = null;
          }}
        />
      </div>

      {/* Filter bar */}
      <FilterBar
        fields={ALERT_FILTER_FIELDS}
        filterState={filterState}
        onFilterChange={handleFilterChange}
        showSearch
        searchPlaceholder="Search alerts, rules, hosts..."
        className="flex-shrink-0"
      />

      {/* Table card */}
      <div className={cn("flex-1 min-h-0 card overflow-hidden flex flex-col")}>
        <DataTable
          data={data?.items ?? []}
          columns={alertColumns}
          isLoading={isLoading}
          enableRowSelection
          rowSelection={rowSelection}
          onRowSelectionChange={setRowSelection}
          getRowId={(row) => row.id}
          onRowClick={(alert) => setSelectedAlertId(alert.id)}
          getRowClassName={getAlertRowClassName}
          pagination={pagination}
          onPaginationChange={setPagination}
          pageCount={data?.pageCount ?? 0}
          manualPagination
          stickyHeader
          enableVirtualization
          className="flex-1 min-h-0"
        />

        <div className="flex-shrink-0 border-t border-border">
          <TablePagination
            pagination={pagination}
            pageCount={data?.pageCount ?? 0}
            totalRows={data?.total}
            onPaginationChange={setPagination}
          />
        </div>
      </div>

      {/* Alert detail drawer */}
      <AlertDrawer
        alertId={selectedAlertId}
        onClose={() => setSelectedAlertId(null)}
      />

      {/* Floating bulk action bar */}
      <BulkActionBar
        selectedIds={selectedIds}
        onClear={() => setRowSelection({})}
      />
    </div>
  );
}
