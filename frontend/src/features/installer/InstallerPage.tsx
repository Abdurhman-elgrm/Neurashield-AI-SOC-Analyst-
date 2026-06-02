import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Plus,
  Clock,
  CheckCircle,
  Ban,
  AlertTriangle,
  RotateCcw,
  Loader,
  ChevronLeft,
  ChevronRight,
  Server,
  RefreshCw,
  Info,
} from "lucide-react";
import { cn, formatDate, formatRelativeTime } from "@/lib/utils";
import { useTenantStore } from "@/stores/tenantStore";
import { useInstallerTokens } from "./useInstallerTokens";
import { GenerateTokenModal } from "./GenerateTokenModal";
import { TokenSuccessModal } from "./TokenSuccessModal";
import { TokenDetailModal } from "./TokenDetailModal";
import type {
  InstallerToken,
  InstallerTokenGenerateResponse,
  InstallerTokenStatus,
} from "@/types/installer";

// ─── Status helpers ───────────────────────────────────────────────────────────

const STATUS_CONFIG: Record<
  InstallerTokenStatus,
  { label: string; color: string; dot: string; icon: React.ElementType }
> = {
  pending: {
    label: "Pending",
    color: "bg-accent/10 text-accent border-accent/20",
    dot: "bg-accent",
    icon: Clock,
  },
  installing: {
    label: "Installing",
    color:
      "bg-severity-medium/10 text-severity-medium border-severity-medium/20",
    dot: "bg-severity-medium",
    icon: Loader,
  },
  active: {
    label: "Active",
    color: "bg-severity-low/10 text-severity-low border-severity-low/20",
    dot: "bg-severity-low",
    icon: CheckCircle,
  },
  expired: {
    label: "Expired",
    color: "bg-bg-elevated text-text-muted border-border",
    dot: "bg-text-muted",
    icon: RotateCcw,
  },
  revoked: {
    label: "Revoked",
    color:
      "bg-severity-critical/10 text-severity-critical border-severity-critical/20",
    dot: "bg-severity-critical",
    icon: Ban,
  },
  failed: {
    label: "Failed",
    color: "bg-severity-high/10 text-severity-high border-severity-high/20",
    dot: "bg-severity-high",
    icon: AlertTriangle,
  },
};

function StatusBadge({ status }: { status: InstallerTokenStatus }) {
  const cfg = STATUS_CONFIG[status];
  const Icon = cfg.icon;
  return (
    <span
      className={cn(
        "badge border gap-1.5",
        cfg.color,
        status === "installing" && "animate-pulse-subtle",
      )}
    >
      <Icon className={cn("w-3 h-3", status === "installing" && "animate-spin")} />
      {cfg.label}
    </span>
  );
}

// ─── Expiry cell — live for pending tokens ────────────────────────────────────

function ExpiryCell({ token }: { token: InstallerToken }) {
  if (token.status === "active" && token.installed_at) {
    return (
      <span className="text-xs text-text-secondary">
        {formatRelativeTime(token.installed_at)}
      </span>
    );
  }
  if (token.status === "revoked" && token.revoked_at) {
    return (
      <span className="text-xs text-severity-critical">
        Revoked {formatRelativeTime(token.revoked_at)}
      </span>
    );
  }
  if (token.status === "expired") {
    return <span className="text-xs text-text-muted">Expired</span>;
  }
  if (token.status === "pending" || token.status === "installing") {
    return <LiveCountdown expiresAt={token.expires_at} />;
  }
  return (
    <span className="text-xs text-text-muted">
      {formatDate(token.expires_at)}
    </span>
  );
}

function LiveCountdown({ expiresAt }: { expiresAt: string }) {
  const [display, setDisplay] = useState(() => calcDisplay(expiresAt));
  const [isUrgent, setIsUrgent] = useState(
    () => new Date(expiresAt).getTime() - Date.now() < 5 * 60 * 1000,
  );

  useEffect(() => {
    const tick = () => {
      const diff = new Date(expiresAt).getTime() - Date.now();
      setIsUrgent(diff < 5 * 60 * 1000);
      setDisplay(calcDisplay(expiresAt));
    };
    tick();
    const id = setInterval(tick, 1_000);
    return () => clearInterval(id);
  }, [expiresAt]);

  return (
    <span
      className={cn(
        "font-mono text-xs tabular-nums",
        isUrgent ? "text-severity-critical" : "text-severity-low",
      )}
    >
      {display}
    </span>
  );
}

function calcDisplay(expiresAt: string): string {
  const diff = new Date(expiresAt).getTime() - Date.now();
  if (diff <= 0) return "Expired";
  const h = Math.floor(diff / 3_600_000);
  const m = Math.floor((diff % 3_600_000) / 60_000);
  const s = Math.floor((diff % 60_000) / 1_000);
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

// ─── Filter tabs ──────────────────────────────────────────────────────────────

const FILTER_TABS: Array<{
  value: InstallerTokenStatus | "all";
  label: string;
}> = [
  { value: "all", label: "All" },
  { value: "pending", label: "Pending" },
  { value: "active", label: "Active" },
  { value: "installing", label: "Installing" },
  { value: "expired", label: "Expired" },
  { value: "revoked", label: "Revoked" },
];

// ─── Empty state ──────────────────────────────────────────────────────────────

function EmptyState({
  filtered,
  onGenerate,
  canGenerate,
}: {
  filtered: boolean;
  onGenerate: () => void;
  canGenerate: boolean;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      className="flex flex-col items-center justify-center py-16 text-center"
    >
      <div className="w-12 h-12 rounded-xl bg-bg-elevated border border-border flex items-center justify-center mb-4">
        <Server className="w-5 h-5 text-text-muted" />
      </div>
      <p className="text-sm font-medium text-text-primary mb-1">
        {filtered ? "No tokens match this filter" : "No installer tokens yet"}
      </p>
      <p className="text-xs text-text-muted max-w-[260px] leading-relaxed mb-5">
        {filtered
          ? "Try a different status filter to view tokens."
          : "Generate a one-time installer token to bootstrap a new agent on a machine."}
      </p>
      {!filtered && canGenerate && (
        <button
          type="button"
          onClick={onGenerate}
          className="btn-primary text-sm flex items-center gap-2"
        >
          <Plus className="w-4 h-4" />
          Generate Token
        </button>
      )}
    </motion.div>
  );
}

// ─── Token table row ──────────────────────────────────────────────────────────

function TokenRow({
  token,
  onClick,
}: {
  token: InstallerToken;
  onClick: () => void;
}) {
  return (
    <motion.tr
      layout
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.15 }}
      onClick={onClick}
      className="table-row-hover border-b border-border last:border-0"
    >
      {/* Token preview */}
      <td className="px-4 py-3">
        <span className="font-mono text-xs text-text-secondary">
          {token.token_preview}
          <span className="text-text-muted">…</span>
        </span>
      </td>

      {/* Machine */}
      <td className="px-4 py-3">
        <span className="text-xs font-medium text-text-primary">
          {token.machine_name}
        </span>
      </td>

      {/* Org */}
      <td className="px-4 py-3 hidden md:table-cell">
        <span className="text-xs text-text-secondary truncate max-w-[140px] block">
          {token.organization}
        </span>
      </td>

      {/* Status */}
      <td className="px-4 py-3">
        <StatusBadge status={token.status} />
      </td>

      {/* Expiry / lifecycle event */}
      <td className="px-4 py-3 hidden sm:table-cell">
        <ExpiryCell token={token} />
      </td>

      {/* Device ID */}
      <td className="px-4 py-3 hidden lg:table-cell">
        {token.device_id ? (
          <span className="font-mono text-xs text-text-secondary truncate max-w-[120px] block">
            {token.device_id}
          </span>
        ) : (
          <span className="text-xs text-text-muted">—</span>
        )}
      </td>

      {/* Created */}
      <td className="px-4 py-3 hidden xl:table-cell">
        <span className="text-xs text-text-muted">
          {formatRelativeTime(token.created_at)}
        </span>
      </td>

      {/* Action indicator */}
      <td className="px-4 py-3 text-right">
        <ChevronRight className="w-3.5 h-3.5 text-text-muted inline-block" />
      </td>
    </motion.tr>
  );
}

// ─── Pagination ───────────────────────────────────────────────────────────────

function Pagination({
  page,
  pages,
  total,
  limit,
  onPage,
}: {
  page: number;
  pages: number;
  total: number;
  limit: number;
  onPage: (p: number) => void;
}) {
  const start = (page - 1) * limit + 1;
  const end = Math.min(page * limit, total);

  return (
    <div className="flex items-center justify-between px-4 py-3 border-t border-border">
      <p className="text-xs text-text-muted">
        {total === 0 ? "No results" : `${start}–${end} of ${total}`}
      </p>
      <div className="flex items-center gap-1">
        <button
          type="button"
          onClick={() => onPage(page - 1)}
          disabled={page <= 1}
          className="btn-ghost p-1.5 disabled:opacity-30 disabled:cursor-not-allowed"
          aria-label="Previous page"
        >
          <ChevronLeft className="w-4 h-4" />
        </button>
        <span className="text-xs text-text-secondary px-2">
          {page} / {Math.max(pages, 1)}
        </span>
        <button
          type="button"
          onClick={() => onPage(page + 1)}
          disabled={page >= pages}
          className="btn-ghost p-1.5 disabled:opacity-30 disabled:cursor-not-allowed"
          aria-label="Next page"
        >
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

const PAGE_LIMIT = 25;

export function InstallerPage() {
  const hasRole = useTenantStore((s) => s.hasRole);
  const canManage = hasRole("admin");

  const [statusFilter, setStatusFilter] = useState<
    InstallerTokenStatus | "all"
  >("all");
  const [page, setPage] = useState(1);

  const [showGenerate, setShowGenerate] = useState(false);
  const [generatedToken, setGeneratedToken] =
    useState<InstallerTokenGenerateResponse | null>(null);
  const [showSuccess, setShowSuccess] = useState(false);
  const [selectedToken, setSelectedToken] = useState<InstallerToken | null>(
    null,
  );

  const { data, isLoading, isError, refetch, isFetching } =
    useInstallerTokens(page, PAGE_LIMIT, statusFilter);

  const tokens = data?.data ?? [];
  const pagination = data?.pagination;

  function handleFilterChange(f: InstallerTokenStatus | "all") {
    setStatusFilter(f);
    setPage(1);
  }

  function handleGenerateSuccess(token: InstallerTokenGenerateResponse) {
    setShowGenerate(false);
    setGeneratedToken(token);
    setShowSuccess(true);
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Page header */}
      <div className="page-header px-6 pt-6 pb-0 flex-shrink-0">
        <div>
          <h1 className="page-title">Installer Tokens</h1>
          <p className="text-xs text-text-muted mt-0.5">
            One-time bootstrap tokens for agent enrollment · single-use ·
            1-hour TTL
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => refetch()}
            className={cn(
              "btn-ghost p-2 rounded",
              isFetching && "text-accent",
            )}
            aria-label="Refresh"
            title="Refresh"
          >
            <RefreshCw
              className={cn("w-4 h-4", isFetching && "animate-spin")}
            />
          </button>
          {canManage && (
            <button
              type="button"
              onClick={() => setShowGenerate(true)}
              className="btn-primary text-sm flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />
              Generate Token
            </button>
          )}
        </div>
      </div>

      {/* Filter tabs */}
      <div className="px-6 mt-5 flex-shrink-0">
        <div className="flex items-center gap-1 border-b border-border">
          {FILTER_TABS.map((tab) => (
            <button
              key={tab.value}
              type="button"
              onClick={() => handleFilterChange(tab.value)}
              className={cn(
                "px-3 py-2 text-xs font-medium transition-colors duration-150 border-b-2 -mb-px",
                statusFilter === tab.value
                  ? "border-accent text-text-primary"
                  : "border-transparent text-text-muted hover:text-text-secondary",
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Table area */}
      <div className="flex-1 overflow-auto px-6 py-4 min-h-0">
        {isError ? (
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-start gap-3 p-4 rounded-lg bg-severity-critical/8 border border-severity-critical/20"
          >
            <AlertTriangle className="w-4 h-4 text-severity-critical mt-0.5 flex-shrink-0" />
            <div>
              <p className="text-sm font-medium text-severity-critical">
                Failed to load tokens
              </p>
              <button
                type="button"
                onClick={() => refetch()}
                className="text-xs text-text-muted hover:text-text-secondary mt-1 underline"
              >
                Retry
              </button>
            </div>
          </motion.div>
        ) : isLoading ? (
          <div className="flex items-center justify-center py-16">
            <div className="w-6 h-6 border-2 border-border-strong border-t-accent rounded-full animate-spin" />
          </div>
        ) : tokens.length === 0 ? (
          <EmptyState
            filtered={statusFilter !== "all"}
            onGenerate={() => setShowGenerate(true)}
            canGenerate={canManage}
          />
        ) : (
          <div className="card overflow-hidden">
            {/* Permission notice for viewers */}
            {!canManage && (
              <div className="flex items-center gap-2 px-4 py-2.5 bg-bg-elevated border-b border-border">
                <Info className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />
                <p className="text-xs text-text-muted">
                  Read-only view — admin role required to generate or revoke
                  tokens
                </p>
              </div>
            )}

            <table className="w-full">
              <thead>
                <tr className="border-b border-border bg-bg-elevated">
                  <th className="px-4 py-2.5 text-left text-2xs font-semibold uppercase tracking-wider text-text-muted">
                    Token
                  </th>
                  <th className="px-4 py-2.5 text-left text-2xs font-semibold uppercase tracking-wider text-text-muted">
                    Machine
                  </th>
                  <th className="px-4 py-2.5 text-left text-2xs font-semibold uppercase tracking-wider text-text-muted hidden md:table-cell">
                    Organization
                  </th>
                  <th className="px-4 py-2.5 text-left text-2xs font-semibold uppercase tracking-wider text-text-muted">
                    Status
                  </th>
                  <th className="px-4 py-2.5 text-left text-2xs font-semibold uppercase tracking-wider text-text-muted hidden sm:table-cell">
                    Expires / Event
                  </th>
                  <th className="px-4 py-2.5 text-left text-2xs font-semibold uppercase tracking-wider text-text-muted hidden lg:table-cell">
                    Device
                  </th>
                  <th className="px-4 py-2.5 text-left text-2xs font-semibold uppercase tracking-wider text-text-muted hidden xl:table-cell">
                    Created
                  </th>
                  <th className="px-4 py-2.5 w-8" />
                </tr>
              </thead>
              <tbody>
                <AnimatePresence initial={false}>
                  {tokens.map((token) => (
                    <TokenRow
                      key={token.id}
                      token={token}
                      onClick={() => setSelectedToken(token)}
                    />
                  ))}
                </AnimatePresence>
              </tbody>
            </table>

            {pagination && pagination.pages > 1 && (
              <Pagination
                page={page}
                pages={pagination.pages}
                total={pagination.total}
                limit={PAGE_LIMIT}
                onPage={setPage}
              />
            )}
          </div>
        )}
      </div>

      {/* Modals */}
      <GenerateTokenModal
        open={showGenerate}
        onClose={() => setShowGenerate(false)}
        onSuccess={handleGenerateSuccess}
      />

      <TokenSuccessModal
        open={showSuccess}
        token={generatedToken}
        onClose={() => {
          setShowSuccess(false);
          setGeneratedToken(null);
        }}
      />

      <TokenDetailModal
        open={selectedToken !== null}
        token={selectedToken}
        onClose={() => setSelectedToken(null)}
      />
    </div>
  );
}
