import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  X,
  Clock,
  Server,
  AlertTriangle,
  CheckCircle,
  Ban,
  Loader,
  RotateCcw,
  Calendar,
  MonitorCheck,
  Tag,
  Terminal,
} from "lucide-react";
import { cn, formatDate, extractApiError } from "@/lib/utils";
import { useRevokeToken } from "./useInstallerTokens";
import type { InstallerToken, InstallerTokenStatus } from "@/types/installer";

// ─── Status badge ─────────────────────────────────────────────────────────────

const STATUS_CONFIG: Record<
  InstallerTokenStatus,
  { label: string; color: string; icon: React.ElementType }
> = {
  pending: {
    label: "Pending",
    color: "bg-accent/10 text-accent border-accent/20",
    icon: Clock,
  },
  installing: {
    label: "Installing",
    color: "bg-severity-medium/10 text-severity-medium border-severity-medium/20",
    icon: Loader,
  },
  active: {
    label: "Active",
    color: "bg-severity-low/10 text-severity-low border-severity-low/20",
    icon: CheckCircle,
  },
  expired: {
    label: "Expired",
    color: "bg-bg-elevated text-text-muted border-border",
    icon: RotateCcw,
  },
  revoked: {
    label: "Revoked",
    color: "bg-severity-critical/10 text-severity-critical border-severity-critical/20",
    icon: Ban,
  },
  failed: {
    label: "Failed",
    color: "bg-severity-high/10 text-severity-high border-severity-high/20",
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
      <Icon className="w-3 h-3" />
      {cfg.label}
    </span>
  );
}

// ─── Detail row ───────────────────────────────────────────────────────────────

function Row({
  label,
  children,
  mono,
}: {
  label: string;
  children: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="flex items-start justify-between gap-4 py-2 border-b border-border last:border-0">
      <span className="text-xs text-text-muted flex-shrink-0 w-28">{label}</span>
      <span
        className={cn(
          "text-xs text-text-primary text-right break-all",
          mono && "font-mono",
        )}
      >
        {children}
      </span>
    </div>
  );
}

// ─── Revoke sub-form ──────────────────────────────────────────────────────────

function RevokeForm({
  token,
  onRevoked,
  onCancel,
}: {
  token: InstallerToken;
  onRevoked: () => void;
  onCancel: () => void;
}) {
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const revokeMutation = useRevokeToken();

  async function handleRevoke() {
    setError(null);
    try {
      await revokeMutation.mutateAsync({
        id: token.id,
        data: { reason: reason.trim() || undefined },
      });
      onRevoked();
    } catch (err) {
      setError(extractApiError(err));
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: "auto" }}
      exit={{ opacity: 0, height: 0 }}
      transition={{ duration: 0.15 }}
      className="overflow-hidden"
    >
      <div className="mt-4 p-4 rounded-lg bg-severity-critical/5 border border-severity-critical/20 space-y-3">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-3.5 h-3.5 text-severity-critical flex-shrink-0" />
          <p className="text-xs font-medium text-severity-critical">
            Confirm Revocation
          </p>
        </div>
        <p className="text-xs text-text-secondary leading-relaxed">
          This token will be permanently revoked and cannot be used to install
          an agent. This action cannot be undone.
        </p>

        {error && (
          <p className="text-xs text-severity-critical">{error}</p>
        )}

        <div>
          <label
            htmlFor="revoke-reason"
            className="block text-xs text-text-muted mb-1"
          >
            Reason{" "}
            <span className="text-text-muted font-normal">(optional)</span>
          </label>
          <input
            id="revoke-reason"
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            className="input-base text-xs"
            placeholder="e.g. Machine decommissioned"
            disabled={revokeMutation.isPending}
          />
        </div>

        <div className="flex items-center justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onCancel}
            className="btn-ghost text-xs"
            disabled={revokeMutation.isPending}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleRevoke}
            className={cn(
              "btn-danger text-xs flex items-center gap-1.5",
              revokeMutation.isPending && "opacity-70 cursor-not-allowed",
            )}
            disabled={revokeMutation.isPending}
          >
            {revokeMutation.isPending ? (
              <>
                <span className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Revoking…
              </>
            ) : (
              "Revoke Token"
            )}
          </button>
        </div>
      </div>
    </motion.div>
  );
}

// ─── Main modal ───────────────────────────────────────────────────────────────

interface Props {
  open: boolean;
  token: InstallerToken | null;
  onClose: () => void;
}

const REVOKABLE: InstallerTokenStatus[] = ["pending", "installing"];

export function TokenDetailModal({ open, token, onClose }: Props) {
  const [showRevoke, setShowRevoke] = useState(false);

  function handleClose() {
    setShowRevoke(false);
    onClose();
  }

  function handleRevoked() {
    setShowRevoke(false);
    onClose();
  }

  const canRevoke = token ? REVOKABLE.includes(token.status) : false;
  const showInstallCmd = token?.status === "pending";

  const installCmdPlaceholder = `powershell -ExecutionPolicy Bypass -File bootstrap.ps1 -Token <TOKEN>`;

  return (
    <AnimatePresence>
      {open && token && (
        <>
          {/* Backdrop */}
          <motion.div
            key="backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm"
            onClick={handleClose}
          />

          {/* Panel */}
          <motion.div
            key="panel"
            initial={{ opacity: 0, x: 32, scale: 0.99 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 32, scale: 0.99 }}
            transition={{ duration: 0.18, ease: "easeOut" }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            role="dialog"
            aria-modal="true"
            aria-labelledby="detail-modal-title"
          >
            <div className="card w-full max-w-md shadow-elevated overflow-hidden">
              {/* Header */}
              <div className="flex items-center justify-between px-5 py-4 border-b border-border">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="w-7 h-7 rounded-md bg-bg-elevated border border-border flex items-center justify-center flex-shrink-0">
                    <Server className="w-3.5 h-3.5 text-text-secondary" />
                  </div>
                  <div className="min-w-0">
                    <h2
                      id="detail-modal-title"
                      className="text-sm font-semibold text-text-primary truncate"
                    >
                      {token.machine_name}
                    </h2>
                    <p className="text-xs text-text-muted truncate">
                      {token.organization}
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleClose}
                  className="btn-ghost p-1.5 rounded flex-shrink-0 ml-3"
                  aria-label="Close"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Body */}
              <div className="p-5 overflow-y-auto max-h-[70vh]">
                {/* Status */}
                <div className="flex items-center justify-between mb-4">
                  <StatusBadge status={token.status} />
                  <span className="font-mono text-xs text-text-muted">
                    {token.token_preview}…
                  </span>
                </div>

                {/* Details grid */}
                <div className="mb-4">
                  <Row label="Machine">{token.machine_name}</Row>
                  <Row label="Organization">{token.organization}</Row>
                  {token.device_id && (
                    <Row label="Device ID" mono>
                      {token.device_id}
                    </Row>
                  )}
                  <Row label="Created">
                    <span className="flex items-center gap-1 justify-end">
                      <Calendar className="w-3 h-3 text-text-muted" />
                      {formatDate(token.created_at)}
                    </span>
                  </Row>
                  <Row label="Expires">
                    <span
                      className={cn(
                        "flex items-center gap-1 justify-end",
                        token.status === "pending" && "text-accent",
                        token.status === "expired" && "text-text-muted line-through",
                      )}
                    >
                      <Clock className="w-3 h-3" />
                      {formatDate(token.expires_at)}
                    </span>
                  </Row>
                  {token.used_at && (
                    <Row label="Used at">{formatDate(token.used_at)}</Row>
                  )}
                  {token.installed_at && (
                    <Row label="Installed">
                      <span className="flex items-center gap-1 justify-end">
                        <MonitorCheck className="w-3 h-3 text-severity-low" />
                        {formatDate(token.installed_at)}
                      </span>
                    </Row>
                  )}
                  {token.revoked_at && (
                    <Row label="Revoked at">
                      <span className="text-severity-critical">
                        {formatDate(token.revoked_at)}
                      </span>
                    </Row>
                  )}
                </div>

                {/* Tags / metadata */}
                {token.metadata &&
                  Object.keys(token.metadata).length > 0 && (
                    <div className="mb-4">
                      <p className="flex items-center gap-1.5 text-xs font-medium text-text-secondary mb-2">
                        <Tag className="w-3 h-3" />
                        Metadata
                      </p>
                      <div className="space-y-1">
                        {Object.entries(token.metadata).map(([k, v]) => (
                          <div
                            key={k}
                            className="flex items-center gap-2 px-2.5 py-1.5 rounded bg-bg-elevated border border-border"
                          >
                            <span className="text-xs text-text-muted w-20 flex-shrink-0">
                              {k}
                            </span>
                            <span className="text-xs text-text-primary font-mono">
                              {Array.isArray(v) ? v.join(", ") : String(v)}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                {/* Install command hint (pending only, no raw token) */}
                {showInstallCmd && (
                  <div className="mb-4">
                    <p className="flex items-center gap-1.5 text-xs font-medium text-text-secondary mb-2">
                      <Terminal className="w-3 h-3" />
                      Install Command Format
                    </p>
                    <div className="px-3 py-2 rounded bg-bg-base border border-border font-mono text-xs text-text-muted break-all">
                      {installCmdPlaceholder}
                    </div>
                    <p className="text-xs text-text-muted mt-1.5">
                      The full command with your token was shown at generation
                      time only.
                    </p>
                  </div>
                )}

                {/* Revoke section */}
                <AnimatePresence>
                  {canRevoke && (
                    <div>
                      {!showRevoke ? (
                        <button
                          type="button"
                          onClick={() => setShowRevoke(true)}
                          className="btn-ghost text-xs text-severity-critical hover:bg-severity-critical/10 hover:text-severity-critical w-full justify-center border border-severity-critical/20"
                        >
                          <Ban className="w-3.5 h-3.5 mr-1.5" />
                          Revoke Token
                        </button>
                      ) : (
                        <RevokeForm
                          token={token}
                          onRevoked={handleRevoked}
                          onCancel={() => setShowRevoke(false)}
                        />
                      )}
                    </div>
                  )}
                </AnimatePresence>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
