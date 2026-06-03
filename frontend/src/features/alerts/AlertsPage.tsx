import { useState, useCallback, useRef } from "react";
import { RefreshCw } from "lucide-react";
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
import { getAlerts } from "@/services/alertsApi";
import { useQuery } from "@tanstack/react-query";
import type { Alert, AlertSeverity, AlertStatus, AlertListParams } from "./types";
import type { FilterState, ActiveFilter } from "@/components/filters/types";
import type { PaginationState, RowSelectionState } from "@/components/table/types";

// ─── Status KPI band ──────────────────────────────────────────────────────────

function useStatusCount(status: AlertStatus) {
  const { data } = useQuery({
    queryKey: ["alerts", "count", status],
    queryFn: () => getAlerts({ status: [status], pageSize: 1, page: 1 }),
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: false,
  });
  return data?.total ?? 0;
}

const STATUS_ITEMS = [
  { key: "open"        as AlertStatus, label: "OPEN",        color: "#60A5FA" },
  { key: "in_progress" as AlertStatus, label: "IN PROGRESS", color: "#F59E0B" },
  { key: "closed"      as AlertStatus, label: "CLOSED",      color: "#4B5563" },
  { key: "suppressed"  as AlertStatus, label: "SUPPRESSED",  color: "#FCA5A5" },
] as const;

function StatusKPIBand({
  activeStatus,
  onSelect,
}: {
  activeStatus: AlertStatus | null;
  onSelect: (s: AlertStatus | null) => void;
}) {
  const open       = useStatusCount("open");
  const inProgress = useStatusCount("in_progress");
  const closed     = useStatusCount("closed");
  const suppressed = useStatusCount("suppressed");

  const counts: Record<AlertStatus, number> = {
    open,
    in_progress: inProgress,
    closed,
    suppressed,
  };

  return (
    <div style={{
      display: "flex",
      borderBottom: "1px solid rgba(255,255,255,0.06)",
      flexShrink: 0,
    }}>
      {STATUS_ITEMS.map((item) => (
        <button
          key={item.key}
          onClick={() => onSelect(activeStatus === item.key ? null : item.key)}
          style={{
            flex: 1,
            padding: "10px 16px",
            textAlign: "left",
            background: activeStatus === item.key ? "rgba(59,130,246,0.05)" : "transparent",
            border: "none",
            borderRight: "1px solid rgba(255,255,255,0.05)",
            borderBottom: `2px solid ${activeStatus === item.key ? "#3B82F6" : "transparent"}`,
            cursor: "pointer",
            transition: "all 120ms",
          }}
        >
          <div style={{
            fontSize: 9,
            fontWeight: 700,
            textTransform: "uppercase",
            letterSpacing: "1px",
            color: "#5C6373",
            marginBottom: 4,
          }}>
            {item.label}
          </div>
          <div style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 20,
            fontWeight: 700,
            color: item.color,
          }}>
            {counts[item.key]}
          </div>
        </button>
      ))}
    </div>
  );
}

// ─── Row severity highlighting ────────────────────────────────────────────────

function getAlertRowClassName(alert: Alert): string {
  switch (alert.severity) {
    case "critical": return "border-l-2 border-l-severity-critical bg-severity-critical/[0.03]";
    case "high":     return "border-l-2 border-l-severity-high";
    default:         return "";
  }
}

// ─── Filter state → API params ────────────────────────────────────────────────

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
      case "severity":       params.severity       = (Array.isArray(value) ? value : [value]) as AlertSeverity[]; break;
      case "status":         params.status         = (Array.isArray(value) ? value : [value]) as AlertStatus[];   break;
      case "hostname":       params.hostname       = String(value ?? ""); break;
      case "username":       params.username       = String(value ?? ""); break;
      case "source_ip":      params.sourceIp       = String(value ?? ""); break;
      case "mitre_technique":params.mitreTechnique = String(value ?? ""); break;
      case "assigned_to":    params.assignedTo     = String(value ?? ""); break;
    }
  }
  if (filterState.dateRange?.preset) params.timeRange = filterState.dateRange.preset;
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
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 50 });
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [activeStatus, setActiveStatus] = useState<AlertStatus | null>(null);
  const [newAlertCount, setNewAlertCount] = useState(0);
  const newAlertsSince = useRef<Date | null>(null);

  const queryParams = {
    ...filtersToParams(filterState, pagination),
    ...(activeStatus ? { status: [activeStatus] } : {}),
  };
  const { data, isLoading, refetch } = useAlertsList(queryParams);

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
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 50px - 40px)", overflow: "hidden" }}>

      {/* Page header */}
      <div style={{
        paddingBottom: 12,
        borderBottom: "1px solid rgba(255,255,255,0.06)",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        flexShrink: 0,
        marginBottom: 0,
      }}>
        <div>
          <h1 style={{ fontSize: 17, fontWeight: 800, fontFamily: "'Space Grotesk', sans-serif", color: "#F5F7FA" }}>
            Alert Triage
          </h1>
          <p style={{ fontSize: 12, color: "#5C6373", marginTop: 2 }}>
            {data?.total != null
              ? <><span style={{ color: "#F5F7FA", fontWeight: 500 }}>{data.total}</span> alerts total</>
              : "Security alert triage workspace"}
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <NewAlertsIndicator
            count={newAlertCount}
            since={newAlertsSince.current}
            onDismiss={() => { setNewAlertCount(0); newAlertsSince.current = null; }}
          />
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => refetch()}
            style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11 }}
          >
            <RefreshCw size={12} /> Refresh
          </button>
        </div>
      </div>

      {/* Status KPI band */}
      <StatusKPIBand activeStatus={activeStatus} onSelect={setActiveStatus} />

      {/* Filter bar */}
      <div style={{ padding: "8px 0", borderBottom: "1px solid rgba(255,255,255,0.04)", flexShrink: 0 }}>
        <FilterBar
          fields={ALERT_FILTER_FIELDS}
          filterState={filterState}
          onFilterChange={handleFilterChange}
          showSearch
          searchPlaceholder="Search alerts, rules, hosts..."
        />
      </div>

      {/* Table + drawer */}
      <div className={cn("flex-1 min-h-0 card overflow-hidden flex flex-col")} style={{ marginTop: 8 }}>
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
      <AlertDrawer alertId={selectedAlertId} onClose={() => setSelectedAlertId(null)} />

      {/* Floating bulk action bar */}
      <BulkActionBar selectedIds={selectedIds} onClear={() => setRowSelection({})} />
    </div>
  );
}
