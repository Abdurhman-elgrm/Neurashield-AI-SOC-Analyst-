import { memo } from "react";
import { formatDistanceToNowStrict } from "date-fns";
import { createColumnHelper } from "@tanstack/react-table";
import type { ColumnDef } from "@tanstack/react-table";
import { Shield, User, Monitor, Tag, Brain, Link2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge, SeverityBadge } from "@/components/ui/Badge";
import { Checkbox } from "@/components/ui/Checkbox";
import type { Alert, AlertStatus, AIVerdictType } from "./types";

const helper = createColumnHelper<Alert>();

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

// ─── Column definitions ───────────────────────────────────────────────────────

export const alertColumns = [
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

  // 3. Title / Rule name
  helper.accessor("title", {
    id: "title",
    size: 280,
    header: "Alert / Rule",
    enableSorting: true,
    cell: ({ row }) => (
      <div className="flex flex-col min-w-0">
        <span className="text-xs font-medium text-text-primary truncate">{row.original.title}</span>
        <span className="text-2xs text-text-muted truncate">{row.original.ruleName}</span>
      </div>
    ),
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

  // 14. Tags
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
] as ColumnDef<Alert, unknown>[];
