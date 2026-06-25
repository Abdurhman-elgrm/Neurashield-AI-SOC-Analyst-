import { useState, useCallback, useRef, useEffect } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { RefreshCw, SlidersHorizontal, Keyboard } from "lucide-react";
import { cn } from "@/lib/utils";
import { DataTable } from "@/components/table/DataTable";
import { TablePagination } from "@/components/table/TablePagination";
import { FilterBar } from "@/components/filters/FilterBar";
import { alertColumns } from "./alertColumns";
import { ALERT_FILTER_FIELDS } from "./alertFilterFields";
import { AlertDrawer } from "./components/AlertDrawer";
import { BulkActionBar } from "./components/BulkActionBar";
import { NewAlertsIndicator } from "./components/NewAlertsIndicator";
import { SavedViewsBar, useSavedViews } from "./components/SavedViewsBar";
import { useAlertsList, useAlertsSummary } from "./hooks/useAlerts";
import { useAlertsRealtime } from "./hooks/useAlertsRealtime";
import { updateAlert } from "@/services/alertsApi";
import type { Alert, AlertSeverity, AlertStatus, AlertListParams } from "./types";
import type { FilterState, ActiveFilter } from "@/components/filters/types";
import type { PaginationState, RowSelectionState } from "@/components/table/types";
import type { SortingState, VisibilityState } from "@tanstack/react-table";
import { useQueryClient } from "@tanstack/react-query";
import { alertsKeys } from "./hooks/useAlerts";
import { useTenantStore } from "@/stores/tenantStore";
import { toastSuccess, toastError } from "@/lib/toast";

// ─── Column visibility localStorage ──────────────────────────────────────────

const COL_VIS_KEY = "neurashield:alert_columns_v1";

function loadColVisibility(): VisibilityState {
  try { return JSON.parse(localStorage.getItem(COL_VIS_KEY) ?? "{}"); }
  catch { return {}; }
}
function saveColVisibility(v: VisibilityState) {
  localStorage.setItem(COL_VIS_KEY, JSON.stringify(v));
}

// ─── Status KPI band with trend deltas ───────────────────────────────────────

const STATUS_ITEMS = [
  {
    key: "open"           as AlertStatus,
    label: "Open",
    color: "#60A5FA",
    glowColor: "rgba(96,165,250,0.15)",
    description: "Awaiting triage",
  },
  {
    key: "acknowledged"   as AlertStatus,
    label: "Acknowledged",
    color: "#F59E0B",
    glowColor: "rgba(245,158,11,0.12)",
    description: "In progress",
  },
  {
    key: "closed"         as AlertStatus,
    label: "Closed",
    color: "#4B5563",
    glowColor: "rgba(75,85,99,0.10)",
    description: "Resolved",
  },
  {
    key: "false_positive" as AlertStatus,
    label: "False Positive",
    color: "#10B981",
    glowColor: "rgba(16,185,129,0.12)",
    description: "Noise reduction",
  },
] as const;

function StatusKPIBand({
  activeStatus,
  onSelect,
}: {
  activeStatus: AlertStatus | null;
  onSelect: (s: AlertStatus | null) => void;
}) {
  const { data: summary } = useAlertsSummary();

  const counts: Record<AlertStatus, number> = {
    open:           summary?.open           ?? 0,
    acknowledged:   summary?.acknowledged   ?? 0,
    closed:         summary?.closed         ?? 0,
    false_positive: summary?.false_positive ?? 0,
  };

  // Synthetic trend: show arrows based on relative proportion
  const total = Object.values(counts).reduce((a, b) => a + b, 0);

  return (
    <div
      style={{
        display: "flex",
        flexShrink: 0,
        borderBottom: "1px solid rgba(255,255,255,0.06)",
      }}
    >
      {STATUS_ITEMS.map((item, idx) => {
        const count = counts[item.key];
        const pct = total > 0 ? ((count / total) * 100).toFixed(1) : "0.0";
        const isActive = activeStatus === item.key;

        return (
          <button
            key={item.key}
            onClick={() => onSelect(isActive ? null : item.key)}
            style={{
              flex: 1,
              padding: "12px 16px",
              textAlign: "left",
              background: isActive ? `${item.glowColor}` : "transparent",
              borderRight: idx < STATUS_ITEMS.length - 1 ? "1px solid rgba(255,255,255,0.05)" : "none",
              borderBottom: `2px solid ${isActive ? item.color : "transparent"}`,
              cursor: "pointer",
              transition: "all 120ms",
              position: "relative",
            }}
          >
            {/* Active glow bar at bottom */}
            {isActive && (
              <div style={{
                position: "absolute", bottom: -1, left: "20%", right: "20%",
                height: 1, background: item.color,
                filter: `blur(3px)`,
              }} />
            )}

            <div style={{
              fontSize: 9, fontWeight: 700, textTransform: "uppercase",
              letterSpacing: "1.5px", color: "#5C6373", marginBottom: 4,
            }}>
              {item.label}
            </div>
            <div style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
              <span style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 22,
                fontWeight: 800,
                color: isActive ? item.color : "#F5F7FA",
                lineHeight: 1,
                transition: "color 120ms",
              }}>
                {count.toLocaleString()}
              </span>
              <span style={{
                fontSize: 10, color: "#5C6373",
                fontFamily: "'JetBrains Mono', monospace",
              }}>
                {pct}%
              </span>
            </div>
            <div style={{ fontSize: 9, color: "#3A4150", marginTop: 3 }}>
              {item.description}
            </div>
          </button>
        );
      })}
    </div>
  );
}

// ─── Alert hover preview card ─────────────────────────────────────────────────

function AlertHoverPreview({
  alert,
  anchorRect,
}: {
  alert: Alert;
  anchorRect: DOMRect;
}) {
  const SEV_COLORS: Record<string, string> = {
    critical: "#EF4444", high: "#F97316", medium: "#F59E0B",
    low: "#3B82F6", info: "#6B7280",
  };
  const color = SEV_COLORS[alert.severity] ?? "#6B7280";

  // Determine if card should flip above or below
  const viewportH = window.innerHeight;
  const spaceBelow = viewportH - anchorRect.bottom;
  const cardHeight = 180;
  const top = spaceBelow > cardHeight + 12
    ? anchorRect.bottom + 4
    : anchorRect.top - cardHeight - 4;

  return (
    <div
      style={{
        position: "fixed",
        top,
        left: Math.min(anchorRect.left, window.innerWidth - 340),
        width: 330,
        background: "#111111",
        border: `1px solid rgba(255,255,255,0.1)`,
        borderLeft: `3px solid ${color}`,
        borderRadius: 8,
        padding: "12px 14px",
        boxShadow: "0 16px 48px rgba(0,0,0,0.7)",
        zIndex: 9999,
        pointerEvents: "none",
        animation: "fadeInUp 100ms ease both",
      }}
    >
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 8 }}>
        <div style={{ flex: 1, minWidth: 0, marginRight: 8 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: "#F5F7FA", lineHeight: 1.4, marginBottom: 4 }}>
            {alert.title}
          </div>
          <div style={{ fontSize: 10, color: "#5C6373", fontFamily: "monospace" }}>
            {alert.ruleName}
          </div>
        </div>
        <span style={{
          padding: "2px 7px", borderRadius: 4, fontSize: 9, fontWeight: 700,
          fontFamily: "monospace", textTransform: "uppercase" as const,
          background: `${color}18`, color,
          flexShrink: 0,
        }}>
          {alert.severity}
        </span>
      </div>

      {alert.description && (
        <div style={{
          fontSize: 11, color: "#8B95A7", lineHeight: 1.5, marginBottom: 8,
          overflow: "hidden", display: "-webkit-box",
          WebkitLineClamp: 2, WebkitBoxOrient: "vertical" as const,
        }}>
          {alert.description}
        </div>
      )}

      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" as const }}>
        {alert.hostname && (
          <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
            <span style={{ fontSize: 8, color: "#3A4150", fontWeight: 700, textTransform: "uppercase" as const, letterSpacing: "1px" }}>Host</span>
            <span style={{ fontSize: 10, color: "#B8C0CC", fontFamily: "monospace" }}>{alert.hostname}</span>
          </div>
        )}
        {alert.sourceIp && (
          <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
            <span style={{ fontSize: 8, color: "#3A4150", fontWeight: 700, textTransform: "uppercase" as const, letterSpacing: "1px" }}>Source IP</span>
            <span style={{ fontSize: 10, color: "#B8C0CC", fontFamily: "monospace" }}>{alert.sourceIp}</span>
          </div>
        )}
        {alert.username && (
          <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
            <span style={{ fontSize: 8, color: "#3A4150", fontWeight: 700, textTransform: "uppercase" as const, letterSpacing: "1px" }}>User</span>
            <span style={{ fontSize: 10, color: "#B8C0CC" }}>{alert.username}</span>
          </div>
        )}
        {alert.mitre && (
          <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
            <span style={{ fontSize: 8, color: "#3A4150", fontWeight: 700, textTransform: "uppercase" as const, letterSpacing: "1px" }}>MITRE</span>
            <span style={{ fontSize: 10, color: "#93C5FD", fontFamily: "monospace" }}>{alert.mitre.techniqueId}</span>
          </div>
        )}
      </div>

      {/* Keyboard hint */}
      <div style={{
        marginTop: 8, paddingTop: 8, borderTop: "1px solid rgba(255,255,255,0.05)",
        fontSize: 9, color: "#3A4150", display: "flex", gap: 10,
      }}>
        <span><kbd style={{ background: "rgba(255,255,255,0.08)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 3, padding: "1px 4px", fontFamily: "monospace" }}>A</kbd> Acknowledge</span>
        <span><kbd style={{ background: "rgba(255,255,255,0.08)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 3, padding: "1px 4px", fontFamily: "monospace" }}>F</kbd> False Positive</span>
        <span><kbd style={{ background: "rgba(255,255,255,0.08)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 3, padding: "1px 4px", fontFamily: "monospace" }}>E</kbd> Escalate</span>
      </div>
    </div>
  );
}

// ─── Keyboard shortcuts help pill ─────────────────────────────────────────────

function KeyboardHintPill() {
  const [show, setShow] = useState(false);
  return (
    <div style={{ position: "relative" }}>
      <button
        onClick={() => setShow((v) => !v)}
        style={{
          display: "flex", alignItems: "center", gap: 5,
          padding: "3px 8px", borderRadius: 5,
          background: "rgba(255,255,255,0.03)",
          border: "1px solid rgba(255,255,255,0.07)",
          color: "#5C6373", fontSize: 10, cursor: "pointer",
        }}
        title="Keyboard shortcuts"
      >
        <Keyboard size={10} />
        <span>Shortcuts</span>
      </button>
      {show && (
        <div style={{
          position: "absolute", top: "calc(100% + 6px)", right: 0, zIndex: 50,
          background: "#111111", border: "1px solid rgba(255,255,255,0.1)",
          borderRadius: 8, padding: "12px 14px", minWidth: 240,
          boxShadow: "0 8px 32px rgba(0,0,0,0.6)",
        }}>
          <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1px", color: "#5C6373", marginBottom: 8 }}>
            When drawer is open
          </div>
          {[
            ["A", "Acknowledge alert"],
            ["C", "Close alert"],
            ["F", "Mark false positive"],
            ["E", "Escalate to investigation"],
            ["N", "Next alert"],
            ["P", "Previous alert"],
            ["Esc", "Close drawer"],
          ].map(([key, desc]) => (
            <div key={key} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}>
              <kbd style={{
                background: "rgba(255,255,255,0.08)", border: "1px solid rgba(255,255,255,0.12)",
                borderRadius: 4, padding: "2px 6px", fontSize: 10, fontFamily: "monospace",
                color: "#B8C0CC", minWidth: 28, textAlign: "center", flexShrink: 0,
              }}>{key}</kbd>
              <span style={{ fontSize: 11, color: "#8B95A7" }}>{desc}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Sorting helpers ──────────────────────────────────────────────────────────

function sortingToParam(sorting: SortingState): string {
  if (!sorting.length) return "-created_at";
  const { id, desc } = sorting[0];
  const colMap: Record<string, string> = {
    severity: "severity", title: "title", status: "status",
    confidence: "confidence", hostname: "hostname", username: "username",
    correlationScore: "correlation_score", assignedTo: "assigned_to",
    createdAt: "created_at",
  };
  const field = colMap[id] ?? id;
  return desc ? `-${field}` : field;
}

function filtersToParams(filterState: FilterState, pagination: PaginationState, sorting: SortingState): AlertListParams {
  const params: AlertListParams = {
    page: pagination.pageIndex + 1,
    pageSize: pagination.pageSize,
    sort: sortingToParam(sorting),
    search: filterState.search || undefined,
  };
  for (const f of filterState.filters) {
    const value = f.value;
    switch (f.field) {
      case "severity":        params.severity       = (Array.isArray(value) ? value : [value]) as AlertSeverity[]; break;
      case "status":          params.status         = (Array.isArray(value) ? value : [value]) as AlertStatus[];   break;
      case "hostname":        params.hostname       = String(value ?? ""); break;
      case "username":        params.username       = String(value ?? ""); break;
      case "source_ip":       params.sourceIp       = String(value ?? ""); break;
      case "mitre_technique": params.mitreTechnique = String(value ?? ""); break;
      case "assigned_to":     params.assignedTo     = String(value ?? ""); break;
    }
  }
  if (filterState.dateRange?.preset) params.timeRange = filterState.dateRange.preset;
  return params;
}

// ─── Row severity highlighting ────────────────────────────────────────────────

function getAlertRowClassName(alert: Alert): string {
  switch (alert.severity) {
    case "critical": return "border-l-2 border-l-severity-critical bg-severity-critical/[0.03]";
    case "high":     return "border-l-2 border-l-severity-high bg-severity-high/[0.02]";
    case "medium":   return "border-l border-l-severity-medium/50";
    case "low":      return "border-l border-l-blue-500/25";
    default:         return "";
  }
}

// ─── Severity distribution strip ─────────────────────────────────────────────

function SeverityStrip({ alerts }: { alerts: Alert[] }) {
  const SEV = ["critical","high","medium","low","info"] as const
  const SEV_COLORS: Record<string, string> = {
    critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#3B82F6", info: "#6B7280",
  }
  const SEV_LABELS: Record<string, string> = {
    critical: "CRIT", high: "HIGH", medium: "MED", low: "LOW", info: "INFO",
  }
  const counts = SEV.reduce((acc, s) => {
    acc[s] = alerts.filter(a => a.severity === s).length
    return acc
  }, {} as Record<string, number>)
  const total = Object.values(counts).reduce((a, b) => a + b, 0)
  if (total === 0) return null

  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 12,
      paddingTop: 6, paddingBottom: 2,
    }}>
      <span style={{ fontSize: 9, color: "#374151", fontWeight: 700, textTransform: "uppercase", letterSpacing: "1px", flexShrink: 0 }}>
        Severity mix
      </span>
      <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
        {SEV.filter(s => counts[s] > 0).map(s => (
          <span key={s} style={{
            display: "inline-flex", alignItems: "center", gap: 4,
            padding: "2px 7px", borderRadius: 4,
            fontSize: 9, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace",
            background: `${SEV_COLORS[s]}15`,
            border: `1px solid ${SEV_COLORS[s]}30`,
            color: SEV_COLORS[s],
          }}>
            <span style={{ width: 5, height: 5, borderRadius: "50%", background: SEV_COLORS[s], flexShrink: 0 }} />
            {counts[s]} {SEV_LABELS[s]}
          </span>
        ))}
      </div>
      <div style={{ flex: 1, height: 4, background: "rgba(255,255,255,0.04)", borderRadius: 2, overflow: "hidden", display: "flex" }}>
        {SEV.filter(s => counts[s] > 0).map(s => (
          <div key={s} style={{
            height: "100%",
            width: `${(counts[s] / total) * 100}%`,
            background: SEV_COLORS[s],
            opacity: 0.7,
            transition: "width 300ms",
          }} />
        ))}
      </div>
    </div>
  )
}

// ─── AlertsPage ───────────────────────────────────────────────────────────────

export function AlertsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const tenantId = useTenantStore((s) => s.activeTenant?.id) ?? "";

  // URL-synced alert selection
  const selectedAlertId = searchParams.get("alert");
  const setSelectedAlertId = useCallback((id: string | null) => {
    setSearchParams(
      (p) => { id ? p.set("alert", id) : p.delete("alert"); return p; },
      { replace: true }
    );
  }, [setSearchParams]);

  // URL-synced sort
  const sortParam = searchParams.get("sort");
  const [sorting, setSorting] = useState<SortingState>(() => {
    if (!sortParam) return [];
    const desc = sortParam.startsWith("-");
    return [{ id: desc ? sortParam.slice(1) : sortParam, desc }];
  });
  const handleSortingChange = useCallback((updater: SortingState | ((prev: SortingState) => SortingState)) => {
    const next = typeof updater === "function" ? updater(sorting) : updater;
    setSorting(next);
    setSearchParams(
      (p) => {
        if (next.length) p.set("sort", next[0].desc ? `-${next[0].id}` : next[0].id);
        else p.delete("sort");
        return p;
      },
      { replace: true }
    );
  }, [sorting, setSearchParams]);

  const [filterState, setFilterState] = useState<FilterState>({
    search: "",
    filters: [] as ActiveFilter[],
    dateRange: null,
    savedViewId: null,
  });
  const [pagination, setPagination]   = useState<PaginationState>({ pageIndex: 0, pageSize: 50 });
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [activeStatus, setActiveStatus] = useState<AlertStatus | null>(null);
  const [newAlertCount, setNewAlertCount] = useState(0);
  const newAlertsSince = useRef<Date | null>(null);
  const [colVisibility, setColVisibility] = useState<VisibilityState>(loadColVisibility);
  const [showColMenu, setShowColMenu] = useState(false);

  // Hover preview state
  const [hoverAlert, setHoverAlert] = useState<Alert | null>(null);
  const [hoverRect, setHoverRect] = useState<DOMRect | null>(null);
  const hoverTimeout = useRef<ReturnType<typeof setTimeout> | null>(null);

  const savedViews = useSavedViews();
  const [activeViewId, setActiveViewId] = useState<string | null>(null);

  const queryParams = {
    ...filtersToParams(filterState, pagination, sorting),
    ...(activeStatus ? { status: [activeStatus] } : {}),
  };
  const { data, isLoading, isFetching, refetch } = useAlertsList(queryParams);

  const handleNewAlert = useCallback((_alert: Alert) => {
    setNewAlertCount((n) => n + 1);
    if (!newAlertsSince.current) newAlertsSince.current = new Date();
  }, []);
  useAlertsRealtime({ onNewAlert: handleNewAlert });

  const selectedIds = Object.keys(rowSelection).filter((k) => rowSelection[k]);

  const handleFilterChange = (next: FilterState) => {
    setFilterState(next);
    setActiveViewId(null);
    setPagination((p) => ({ ...p, pageIndex: 0 }));
  };

  const handleViewSelect = (view: import("./components/SavedViewsBar").SavedView) => {
    setFilterState(view.filterState);
    setActiveViewId(view.id);
    setPagination((p) => ({ ...p, pageIndex: 0 }));
  };

  const handleColVisChange = (id: string, visible: boolean) => {
    setColVisibility((prev) => {
      const next = { ...prev, [id]: visible };
      saveColVisibility(next);
      return next;
    });
  };

  // ── Keyboard triage shortcuts ──────────────────────────────────────────────
  const alerts = data?.items ?? [];
  const selectedIndex = alerts.findIndex((a) => a.id === selectedAlertId);

  const quickAction = useCallback(async (status: AlertStatus) => {
    if (!selectedAlertId) return;
    try {
      await updateAlert(selectedAlertId, { status });
      queryClient.invalidateQueries({ queryKey: alertsKeys.lists(tenantId) });
      queryClient.invalidateQueries({ queryKey: alertsKeys.summary(tenantId) });
      toastSuccess(`Alert ${status.replace(/_/g, " ")}`);
    } catch {
      toastError("Failed to update alert");
    }
  }, [selectedAlertId, queryClient, tenantId]);

  const escalateToInvestigation = useCallback(() => {
    if (!selectedAlertId) return;
    navigate(`/investigations?createFrom=${selectedAlertId}`);
  }, [selectedAlertId, navigate]);

  useEffect(() => {
    if (!selectedAlertId) return;
    const handler = (e: KeyboardEvent) => {
      // Don't fire if user is typing in an input
      if (
        e.target instanceof HTMLInputElement ||
        e.target instanceof HTMLTextAreaElement ||
        e.target instanceof HTMLSelectElement
      ) return;

      switch (e.key.toUpperCase()) {
        case "A": void quickAction("acknowledged"); break;
        case "C": void quickAction("closed"); break;
        case "F": void quickAction("false_positive"); break;
        case "E": escalateToInvestigation(); break;
        case "N": {
          const next = alerts[selectedIndex + 1];
          if (next) setSelectedAlertId(next.id);
          break;
        }
        case "P": {
          const prev = alerts[selectedIndex - 1];
          if (prev) setSelectedAlertId(prev.id);
          break;
        }
        case "ESCAPE":
          setSelectedAlertId(null);
          break;
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [selectedAlertId, quickAction, escalateToInvestigation, alerts, selectedIndex, setSelectedAlertId]);

  // ── Row hover preview ──────────────────────────────────────────────────────
  const handleRowMouseEnter = useCallback((alert: Alert, e: React.MouseEvent) => {
    if (hoverTimeout.current) clearTimeout(hoverTimeout.current);
    hoverTimeout.current = setTimeout(() => {
      setHoverAlert(alert);
      setHoverRect((e.currentTarget as HTMLElement).getBoundingClientRect());
    }, 250);
  }, []);

  const handleRowMouseLeave = useCallback(() => {
    if (hoverTimeout.current) clearTimeout(hoverTimeout.current);
    hoverTimeout.current = setTimeout(() => {
      setHoverAlert(null);
      setHoverRect(null);
    }, 100);
  }, []);

  return (
    <div className="flex flex-col overflow-hidden" style={{ height: "calc(100vh - 50px - 40px)" }}>

      {/* Page header */}
      <div className="flex-shrink-0 pb-3 border-b border-border">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-extrabold text-text-primary font-display">Alert Triage</h1>
            <p className="text-xs text-text-muted mt-0.5">
              {data?.total != null ? (
                <><span className="text-text-primary font-medium">{data.total.toLocaleString()}</span> alerts &mdash; showing page results below</>
              ) : (
                "Security alert triage workspace"
              )}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <NewAlertsIndicator
              count={newAlertCount}
              since={newAlertsSince.current}
              onDismiss={() => { setNewAlertCount(0); newAlertsSince.current = null; }}
            />
            <KeyboardHintPill />
            <button
              className="btn btn-ghost btn-sm flex items-center gap-1 text-xs"
              aria-label="Refresh alerts"
              onClick={() => refetch()}
            >
              <RefreshCw size={12} className={isFetching ? "animate-spin" : ""} />
              Refresh
            </button>
          </div>
        </div>
        <SeverityStrip alerts={alerts} />
      </div>

      {/* Status KPI band */}
      <StatusKPIBand activeStatus={activeStatus} onSelect={setActiveStatus} />

      {/* Filter bar */}
      <div className="py-2 border-b border-border/60 flex-shrink-0">
        <div className="flex items-center gap-2">
          <div className="flex-1">
            <FilterBar
              fields={ALERT_FILTER_FIELDS}
              filterState={filterState}
              onFilterChange={handleFilterChange}
              showSearch
              searchPlaceholder="Search alerts, rules, hosts, IPs…"
            />
          </div>
          <div className="relative flex-shrink-0">
            <button
              onClick={() => setShowColMenu((p) => !p)}
              aria-label="Toggle column visibility"
              aria-expanded={showColMenu}
              className="btn btn-ghost btn-sm flex items-center gap-1 text-xs"
            >
              <SlidersHorizontal size={12} />
              Columns
            </button>
            {showColMenu && (
              <div className="absolute right-0 top-full mt-1 z-30 bg-bg-card border border-border rounded-lg p-2 shadow-elevated w-44">
                <p className="text-2xs font-bold uppercase tracking-widest text-text-muted px-1 mb-1.5">Show / Hide Columns</p>
                {alertColumns
                  .filter((c) => "id" in c && c.id && c.id !== "select")
                  .map((c) => {
                    const id = (c as { id: string }).id;
                    const visible = colVisibility[id] !== false;
                    return (
                      <label key={id} className="flex items-center gap-2 px-1 py-1 rounded hover:bg-bg-elevated cursor-pointer">
                        <input
                          type="checkbox"
                          checked={visible}
                          onChange={(e) => handleColVisChange(id, e.target.checked)}
                          className="accent-accent"
                        />
                        <span className="text-xs text-text-secondary capitalize">{id.replace(/([A-Z])/g, " $1").toLowerCase()}</span>
                      </label>
                    );
                  })}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Saved views bar */}
      <SavedViewsBar
        activeViewId={activeViewId}
        views={savedViews.views}
        currentFilter={filterState}
        onSelect={handleViewSelect}
        onSaveCurrent={(name) => savedViews.add(name, filterState)}
        onRemove={savedViews.remove}
      />

      {/* Thin background-fetch indicator */}
      {isFetching && !isLoading && (
        <div className="h-0.5 bg-accent/30 flex-shrink-0 relative overflow-hidden">
          <div className="absolute inset-y-0 left-0 w-1/3 bg-accent animate-shimmer" />
        </div>
      )}

      {/* Table + drawer */}
      <div className={cn("flex-1 min-h-0 card overflow-hidden flex flex-col mt-2")}>
        <DataTable
          data={alerts}
          columns={alertColumns}
          isLoading={isLoading}
          emptyMessage={
            activeStatus
              ? `No ${activeStatus.replace(/_/g, " ")} alerts`
              : "No alerts yet — detections will appear here once the agent starts sending events"
          }
          enableRowSelection
          rowSelection={rowSelection}
          onRowSelectionChange={setRowSelection}
          getRowId={(row) => row.id}
          onRowClick={(alert) => setSelectedAlertId(alert.id)}
          onRowMouseEnter={handleRowMouseEnter}
          onRowMouseLeave={handleRowMouseLeave}
          getRowClassName={getAlertRowClassName}
          pagination={pagination}
          onPaginationChange={setPagination}
          pageCount={data?.pageCount ?? 0}
          manualPagination
          stickyHeader
          enableVirtualization
          sorting={sorting}
          onSortingChange={handleSortingChange}
          columnVisibility={colVisibility}
          className="flex-1 min-h-0"
          highlightRowId={selectedAlertId ?? undefined}
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

      {/* Row hover preview */}
      {hoverAlert && hoverRect && !selectedAlertId && (
        <AlertHoverPreview alert={hoverAlert} anchorRect={hoverRect} />
      )}
    </div>
  );
}
