import { memo } from "react";
import { formatDistanceToNowStrict } from "date-fns";
import { createColumnHelper } from "@tanstack/react-table";
import type { ColumnDef } from "@tanstack/react-table";
import {
  Shield, User, Monitor, Tag, Brain, Link2, Clock,
  AlertTriangle, Check, XCircle, ArrowUpRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge, SeverityBadge } from "@/components/ui/Badge";
import { Checkbox } from "@/components/ui/Checkbox";
import type { Alert, AlertStatus, AIVerdictType } from "./types";

// ─── SLA targets by severity ──────────────────────────────────────────────────
// respond_ms = time-to-first-acknowledgment target
// resolve_ms = time-to-close target

const SLA_MS: Record<string, { respond: number; resolve: number }> = {
  critical: { respond:   15 * 60_000, resolve:  120 * 60_000 },
  high:     { respond:   60 * 60_000, resolve:  240 * 60_000 },
  medium:   { respond:  240 * 60_000, resolve:  480 * 60_000 },
  low:      { respond: 1440 * 60_000, resolve: 4320 * 60_000 },
};

const SLA_TERMINAL = new Set<AlertStatus>(["closed", "false_positive"]);

function SLABadge({ alert }: { alert: Alert }) {
  const isTerminal = SLA_TERMINAL.has(alert.status);
  const targets = SLA_MS[alert.severity] ?? SLA_MS.medium;

  const startMs = new Date(alert.createdAt).getTime();
  const endMs = isTerminal && alert.closedAt
    ? new Date(alert.closedAt).getTime()
    : Date.now();
  const elapsedMs = endMs - startMs;

  // Open → measured against respond SLA; Acknowledged → measured against resolve SLA
  const targetMs = (alert.status === "acknowledged" || isTerminal)
    ? targets.resolve
    : targets.respond;

  const ratio = elapsedMs / targetMs;
  const isBreach = !isTerminal && ratio >= 1.0;
  const isWarn   = !isTerminal && !isBreach && ratio >= 0.7;

  const h = Math.floor(elapsedMs / 3_600_000);
  const m = Math.floor((elapsedMs % 3_600_000) / 60_000);
  const label = h > 0 ? `${h}h${m}m` : `${m}m`;

  const slaHint = `Respond <${targets.respond / 60_000}m · Resolve <${targets.resolve / 60_000}m`;

  return (
    <div
      title={slaHint}
      className={cn(
        "flex items-center gap-1 px-1.5 py-0.5 rounded text-2xs font-mono font-bold whitespace-nowrap",
        isBreach
          ? "bg-red-500/15 text-red-400 border border-red-500/30"
          : isWarn
          ? "bg-amber-500/15 text-amber-400 border border-amber-500/30"
          : isTerminal
          ? "bg-bg-elevated text-text-disabled border border-transparent"
          : "bg-bg-elevated text-text-muted border border-border",
      )}
    >
      {isBreach
        ? <AlertTriangle size={9} className="flex-shrink-0" />
        : <Clock size={9} className="flex-shrink-0" />}
      <span>{label}</span>
      {isBreach && <span className="text-2xs uppercase tracking-wider">BREACH</span>}
    </div>
  );
}

// ─── Status display ───────────────────────────────────────────────────────────

const STATUS_CONFIG: Record<AlertStatus, { label: string; variant: "default" | "primary" | "success" | "warning" | "info" }> = {
  open:           { label: "Open",           variant: "default" },
  acknowledged:   { label: "Acknowledged",   variant: "primary" },
  closed:         { label: "Closed",         variant: "success" },
  false_positive: { label: "False Positive", variant: "info" },
};

// ─── AI verdict display ───────────────────────────────────────────────────────

const VERDICT_CONFIG: Record<AIVerdictType, { label: string; variant: "error" | "success" | "info" | "warning" }> = {
  true_positive:  { label: "TP",      variant: "error" },
  false_positive: { label: "FP",      variant: "success" },
  benign:         { label: "Benign",  variant: "info" },
  pending:        { label: "Pending", variant: "warning" },
};

// ─── Confidence bar ───────────────────────────────────────────────────────────

const ConfidenceBar = memo(function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(100, value));
  const color =
    pct >= 80 ? "bg-severity-critical" :
    pct >= 50 ? "bg-severity-high" :
    "bg-severity-medium";
  return (
    <div className="flex items-center gap-1.5 w-full max-w-[80px]">
      <div className="flex-1 h-1.5 bg-bg-elevated rounded-full overflow-hidden">
        <div className={cn("h-full rounded-full", color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-text-muted tabular-nums w-6 text-right">{pct}</span>
    </div>
  );
});

// ─── Column builder options ───────────────────────────────────────────────────

export interface BuildAlertColumnsOpts {
  dedupeMap: Map<string, number>;
  onQuickAction: (alertId: string, status: AlertStatus) => void;
  onEscalate: (alertId: string) => void;
}

const helper = createColumnHelper<Alert>();

// ─── Column definitions (factory) ────────────────────────────────────────────

export function buildAlertColumns({
  dedupeMap,
  onQuickAction,
  onEscalate,
}: BuildAlertColumnsOpts): ColumnDef<Alert, unknown>[] {
  return [
    // 1. Select
    helper.display({
      id: "select",
      size: 40,
      enableSorting: false,
      header: ({ table }) => (
        <Checkbox
          checked={
            table.getIsAllPageRowsSelected()
              ? true
              : table.getIsSomePageRowsSelected()
              ? "indeterminate"
              : false
          }
          onCheckedChange={(v) => table.toggleAllPageRowsSelected(!!v)}
          aria-label="Select all"
        />
      ),
      cell: ({ row }) => (
        <Checkbox
          checked={row.getIsSelected()}
          onCheckedChange={(v) => row.toggleSelected(!!v)}
          onClick={(e) => e.stopPropagation()}
          aria-label="Select row"
        />
      ),
    }),

    // 2. Severity
    helper.accessor("severity", {
      id: "severity",
      size: 90,
      header: "Severity",
      enableSorting: true,
      cell: ({ getValue }) => <SeverityBadge severity={getValue()} />,
    }),

    // 3. Title — with chain badge + dedup count
    helper.accessor("title", {
      id: "title",
      size: 300,
      header: "Alert / Rule",
      enableSorting: true,
      cell: ({ row }) => {
        const a = row.original;
        const isChain = a.title.startsWith("[Attack Chain]");
        const displayTitle = isChain
          ? a.title.replace(/^\[Attack Chain\]\s*/, "")
          : a.title;
        const dedupeKey = `${a.ruleName ?? ""}::${a.hostname ?? ""}`;
        const dupeCount = dedupeMap.get(dedupeKey) ?? 1;

        return (
          <div className="flex flex-col min-w-0 gap-0.5">
            <div className="flex items-center gap-1.5 min-w-0">
              {isChain && (
                <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-2xs font-bold bg-purple-500/15 text-purple-400 border border-purple-500/25 flex-shrink-0">
                  <Link2 size={8} />
                  CHAIN
                </span>
              )}
              <span className="text-xs font-medium text-text-primary truncate">
                {displayTitle}
              </span>
              {dupeCount > 1 && (
                <span className="text-2xs font-mono font-bold text-text-muted bg-bg-elevated border border-border rounded px-1 flex-shrink-0 tabular-nums">
                  ×{dupeCount}
                </span>
              )}
            </div>
            <span className="text-2xs text-text-muted truncate">{a.ruleName}</span>
          </div>
        );
      },
    }),

    // 4. Status
    helper.accessor("status", {
      id: "status",
      size: 110,
      header: "Status",
      enableSorting: true,
      cell: ({ getValue }) => {
        const cfg = STATUS_CONFIG[getValue()];
        return <Badge variant={cfg.variant}>{cfg.label}</Badge>;
      },
    }),

    // 5. AI confidence
    helper.accessor((row) => row.aiVerdict?.confidence ?? 0, {
      id: "confidence",
      size: 110,
      header: "Confidence",
      enableSorting: true,
      cell: ({ getValue, row }) =>
        row.original.aiVerdict ? (
          <ConfidenceBar value={getValue()} />
        ) : (
          <span className="text-xs text-text-muted">—</span>
        ),
    }),

    // 6. Hostname
    helper.accessor("hostname", {
      id: "hostname",
      size: 150,
      header: () => (
        <div className="flex items-center gap-1">
          <Monitor className="w-3 h-3" />
          Host
        </div>
      ),
      enableSorting: true,
      cell: ({ getValue }) => (
        <span className="text-xs text-text-secondary font-mono truncate block max-w-[140px]">
          {getValue() || "—"}
        </span>
      ),
    }),

    // 7. Username
    helper.accessor("username", {
      id: "username",
      size: 130,
      header: () => (
        <div className="flex items-center gap-1">
          <User className="w-3 h-3" />
          User
        </div>
      ),
      enableSorting: true,
      cell: ({ getValue }) => (
        <span className="text-xs text-text-secondary truncate block max-w-[120px]">
          {getValue() || "—"}
        </span>
      ),
    }),

    // 8. Source IP
    helper.accessor("sourceIp", {
      id: "sourceIp",
      size: 130,
      header: "Source IP",
      enableSorting: false,
      cell: ({ getValue }) => (
        <span className="text-xs text-text-secondary font-mono">
          {getValue() || "—"}
        </span>
      ),
    }),

    // 9. MITRE technique
    helper.accessor((row) => row.mitre?.techniqueId, {
      id: "mitre",
      size: 120,
      header: () => (
        <div className="flex items-center gap-1">
          <Shield className="w-3 h-3" />
          MITRE
        </div>
      ),
      enableSorting: false,
      cell: ({ row }) => {
        const m = row.original.mitre;
        return m ? (
          <div className="flex flex-col min-w-0">
            <span className="text-2xs font-mono text-accent">{m.techniqueId}</span>
            <span className="text-2xs text-text-muted truncate max-w-[110px]">{m.techniqueName}</span>
          </div>
        ) : (
          <span className="text-xs text-text-muted">—</span>
        );
      },
    }),

    // 10. Correlation score
    helper.accessor("correlationScore", {
      id: "correlationScore",
      size: 110,
      header: () => (
        <div className="flex items-center gap-1">
          <Link2 className="w-3 h-3" />
          Correlated
        </div>
      ),
      enableSorting: true,
      cell: ({ getValue, row }) => {
        const score = getValue();
        if (!score) return <span className="text-xs text-text-muted">—</span>;
        return (
          <div className="flex flex-col gap-0.5">
            <ConfidenceBar value={score} />
            {row.original.correlationId && (
              <span className="text-2xs text-accent truncate">linked</span>
            )}
          </div>
        );
      },
    }),

    // 11. Assigned to
    helper.accessor("assignedToName", {
      id: "assignedTo",
      size: 120,
      header: "Assigned",
      enableSorting: true,
      cell: ({ getValue }) => (
        <span className="text-xs text-text-secondary truncate block max-w-[110px]">
          {getValue() || <span className="text-text-muted">Unassigned</span>}
        </span>
      ),
    }),

    // 12. AI verdict
    helper.accessor((row) => row.aiVerdict?.verdict, {
      id: "aiVerdict",
      size: 90,
      header: () => (
        <div className="flex items-center gap-1">
          <Brain className="w-3 h-3" />
          AI
        </div>
      ),
      enableSorting: false,
      cell: ({ getValue }) => {
        const v = getValue() as AIVerdictType | undefined;
        if (!v) return <span className="text-xs text-text-muted">—</span>;
        const cfg = VERDICT_CONFIG[v];
        return <Badge variant={cfg.variant}>{cfg.label}</Badge>;
      },
    }),

    // 13. Created at
    helper.accessor("createdAt", {
      id: "createdAt",
      size: 110,
      header: "Created",
      enableSorting: true,
      cell: ({ getValue }) => (
        <span className="text-xs text-text-muted whitespace-nowrap">
          {formatDistanceToNowStrict(new Date(getValue()), { addSuffix: true })}
        </span>
      ),
    }),

    // 14. SLA — severity-aware
    helper.display({
      id: "sla",
      size: 100,
      header: () => (
        <div className="flex items-center gap-1">
          <Clock className="w-3 h-3" />
          SLA
        </div>
      ),
      enableSorting: false,
      cell: ({ row }) => <SLABadge alert={row.original} />,
    }),

    // 15. Tags
    helper.accessor("tags", {
      id: "tags",
      size: 140,
      header: () => (
        <div className="flex items-center gap-1">
          <Tag className="w-3 h-3" />
          Tags
        </div>
      ),
      enableSorting: false,
      cell: ({ getValue }) => {
        const tags = getValue();
        if (!tags?.length) return <span className="text-xs text-text-muted">—</span>;
        return (
          <div className="flex flex-wrap gap-1">
            {tags.slice(0, 2).map((tag) => (
              <span
                key={tag}
                className="px-1 py-0.5 text-2xs bg-bg-elevated text-text-muted border border-border rounded"
              >
                {tag}
              </span>
            ))}
            {tags.length > 2 && (
              <span className="text-2xs text-text-muted">+{tags.length - 2}</span>
            )}
          </div>
        );
      },
    }),

    // 16. Quick actions — appear on row hover via group-hover
    helper.display({
      id: "actions",
      size: 84,
      header: "",
      enableSorting: false,
      cell: ({ row }) => {
        const a = row.original;
        const isTerminal = a.status === "closed" || a.status === "false_positive";
        return (
          <div className="flex items-center justify-end gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity duration-100">
            {!isTerminal && a.status === "open" && (
              <button
                title="Acknowledge (A)"
                onClick={(e) => { e.stopPropagation(); onQuickAction(a.id, "acknowledged"); }}
                className="p-1 rounded text-text-muted hover:text-emerald-400 hover:bg-emerald-500/15 transition-colors"
              >
                <Check size={13} />
              </button>
            )}
            {!isTerminal && (
              <button
                title="False Positive (F)"
                onClick={(e) => { e.stopPropagation(); onQuickAction(a.id, "false_positive"); }}
                className="p-1 rounded text-text-muted hover:text-blue-400 hover:bg-blue-500/15 transition-colors"
              >
                <XCircle size={13} />
              </button>
            )}
            <button
              title="Escalate to Investigation (E)"
              onClick={(e) => { e.stopPropagation(); onEscalate(a.id); }}
              className="p-1 rounded text-text-muted hover:text-purple-400 hover:bg-purple-500/15 transition-colors"
            >
              <ArrowUpRight size={13} />
            </button>
          </div>
        );
      },
    }),
  ] as ColumnDef<Alert, unknown>[];
}

// ─── Static default (zero-config, for components that don't need callbacks) ──

export const alertColumns = buildAlertColumns({
  dedupeMap: new Map(),
  onQuickAction: () => {},
  onEscalate: () => {},
});
