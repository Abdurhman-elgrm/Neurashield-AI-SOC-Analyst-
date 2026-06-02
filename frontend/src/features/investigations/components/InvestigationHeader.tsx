import { useState } from "react";
import { formatDistanceToNowStrict } from "date-fns";
import {
  Shield, User, Clock, ChevronDown, Copy, CheckCheck,
  AlertTriangle, CheckCircle, XCircle, Minus, ExternalLink,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/Badge";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from "@/components/ui/Dropdown";
import { useUpdateStatus, useUpdateVerdict } from "../hooks/useInvestigation";
import type {
  Investigation,
  InvestigationStatus,
  InvestigationVerdict,
  InvestigationSeverity,
} from "../types/investigation";

// ─── Config maps ──────────────────────────────────────────────────────────────

const SEV_VARIANT: Record<InvestigationSeverity, "critical" | "high" | "medium" | "low"> = {
  critical: "critical", high: "high", medium: "medium", low: "low",
};

const STATUS_CONFIG: Record<InvestigationStatus, { label: string; variant: "default" | "primary" | "warning" | "success" | "info" }> = {
  open:        { label: "Open",        variant: "default" },
  in_progress: { label: "In Progress", variant: "primary" },
  escalated:   { label: "Escalated",   variant: "warning" },
  closed:      { label: "Closed",      variant: "success" },
  archived:    { label: "Archived",    variant: "info" },
};

const VERDICT_CONFIG: Record<InvestigationVerdict, { label: string; icon: React.ReactNode; className: string }> = {
  true_positive:  { label: "True Positive",  icon: <AlertTriangle className="w-3.5 h-3.5" />, className: "text-severity-critical" },
  false_positive: { label: "False Positive", icon: <XCircle className="w-3.5 h-3.5" />,       className: "text-status-online" },
  benign:         { label: "Benign",         icon: <CheckCircle className="w-3.5 h-3.5" />,    className: "text-text-muted" },
  inconclusive:   { label: "Inconclusive",   icon: <Minus className="w-3.5 h-3.5" />,          className: "text-severity-medium" },
  pending:        { label: "Pending",        icon: <Clock className="w-3.5 h-3.5" />,          className: "text-text-muted" },
};

const STATUS_OPTIONS: InvestigationStatus[] = ["open", "in_progress", "escalated", "closed", "archived"];
const VERDICT_OPTIONS: InvestigationVerdict[] = ["true_positive", "false_positive", "benign", "inconclusive"];

// ─── InvestigationHeader ──────────────────────────────────────────────────────

interface InvestigationHeaderProps {
  investigation: Investigation;
}

export function InvestigationHeader({ investigation: inv }: InvestigationHeaderProps) {
  const [copied, setCopied] = useState(false);
  const { mutate: setStatus } = useUpdateStatus(inv.id);
  const { mutate: setVerdict } = useUpdateVerdict(inv.id);

  const copyLink = () => {
    void navigator.clipboard.writeText(window.location.href);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const statusCfg = STATUS_CONFIG[inv.status];
  const verdictCfg = VERDICT_CONFIG[inv.verdict];

  return (
    <div className="border-b border-border bg-bg-surface px-6 py-4 flex-shrink-0">
      {/* Top row: title + actions */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <Badge variant={SEV_VARIANT[inv.severity]} dot>
              {inv.severity.charAt(0).toUpperCase() + inv.severity.slice(1)}
            </Badge>
            <h1 className="text-base font-semibold text-text-primary truncate">
              {inv.title}
            </h1>
          </div>
          {inv.description && (
            <p className="text-sm text-text-muted mt-0.5 line-clamp-1">{inv.description}</p>
          )}
        </div>

        {/* Quick actions */}
        <div className="flex items-center gap-2 flex-shrink-0">
          <button
            onClick={copyLink}
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-text-muted hover:text-text-secondary border border-border rounded-md hover:bg-bg-elevated transition-colors"
          >
            {copied ? <CheckCheck className="w-3.5 h-3.5 text-status-online" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? "Copied" : "Copy link"}
          </button>
          <button
            onClick={() => window.open(`/graph?investigation=${inv.id}`, "_blank")}
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-text-muted hover:text-text-secondary border border-border rounded-md hover:bg-bg-elevated transition-colors"
          >
            <ExternalLink className="w-3.5 h-3.5" />
            Full graph
          </button>
        </div>
      </div>

      {/* Metadata row */}
      <div className="flex items-center gap-4 mt-3 flex-wrap">
        {/* Status control */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button className="flex items-center gap-1.5">
              <Badge variant={statusCfg.variant}>{statusCfg.label}</Badge>
              <ChevronDown className="w-3 h-3 text-text-muted" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            {STATUS_OPTIONS.map((s) => (
              <DropdownMenuItem
                key={s}
                onClick={() => setStatus(s)}
                className={cn(s === inv.status && "text-accent")}
              >
                {STATUS_CONFIG[s].label}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Verdict control */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              className={cn(
                "flex items-center gap-1.5 text-xs font-medium",
                verdictCfg.className
              )}
            >
              {verdictCfg.icon}
              {verdictCfg.label}
              <ChevronDown className="w-3 h-3" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            {VERDICT_OPTIONS.map((v) => {
              const cfg = VERDICT_CONFIG[v];
              return (
                <DropdownMenuItem
                  key={v}
                  onClick={() => setVerdict({ verdict: v })}
                  className={cn("flex items-center gap-2", v === inv.verdict && "text-accent")}
                >
                  <span className={cfg.className}>{cfg.icon}</span>
                  {cfg.label}
                </DropdownMenuItem>
              );
            })}
          </DropdownMenuContent>
        </DropdownMenu>

        <DropdownMenuSeparator className="h-4 w-px bg-border" />

        {/* Assigned */}
        <div className="flex items-center gap-1.5 text-xs text-text-muted">
          <User className="w-3.5 h-3.5" />
          <span>{inv.assignedToName ?? "Unassigned"}</span>
        </div>

        {/* Alert count */}
        <div className="flex items-center gap-1.5 text-xs text-text-muted">
          <Shield className="w-3.5 h-3.5" />
          <span>{inv.alertCount} alerts</span>
        </div>

        {/* Created time */}
        <div className="flex items-center gap-1.5 text-xs text-text-muted ml-auto">
          <Clock className="w-3.5 h-3.5" />
          <span>
            Created {formatDistanceToNowStrict(new Date(inv.createdAt), { addSuffix: true })}
          </span>
        </div>
      </div>
    </div>
  );
}
