import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  X, UserCheck, CheckCircle, XCircle, Tag, Shield, ChevronDown,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useBulkAlerts } from "../hooks/useBulkAlerts";
import type { BulkAlertAction, AlertSeverity } from "../types";

interface BulkActionBarProps {
  selectedIds: string[];
  onClear: () => void;
}

interface ActionDef {
  id: BulkAlertAction;
  label: string;
  icon: React.ReactNode;
  variant?: "danger" | "success" | "default";
  requiresConfirm?: boolean;
}

const ACTIONS: ActionDef[] = [
  { id: "close",              label: "Close",         icon: <XCircle className="w-3.5 h-3.5" />,    requiresConfirm: true },
  { id: "reopen",             label: "Reopen",        icon: <CheckCircle className="w-3.5 h-3.5" /> },
  { id: "mark_true_positive", label: "Mark TP",       icon: <Shield className="w-3.5 h-3.5" />,     variant: "danger",   requiresConfirm: true },
  { id: "mark_false_positive",label: "Mark FP",       icon: <CheckCircle className="w-3.5 h-3.5" />, variant: "success" },
  { id: "assign",             label: "Assign",        icon: <UserCheck className="w-3.5 h-3.5" /> },
  { id: "add_tag",            label: "Tag",           icon: <Tag className="w-3.5 h-3.5" /> },
];

const SEVERITY_OPTIONS: AlertSeverity[] = ["critical", "high", "medium", "low", "info"];

export function BulkActionBar({ selectedIds, onClear }: BulkActionBarProps) {
  const { mutate, isPending } = useBulkAlerts();
  const [confirmAction, setConfirmAction] = useState<BulkAlertAction | null>(null);
  const [showSeverity, setShowSeverity] = useState(false);

  const dispatch = (action: BulkAlertAction, extra?: { assignTo?: string; tag?: string; severity?: AlertSeverity }) => {
    mutate(
      { alertIds: selectedIds, action, ...extra },
      { onSuccess: () => onClear() }
    );
  };

  const handleAction = (def: ActionDef) => {
    if (def.id === "assign") return; // TODO: open assign modal
    if (def.id === "add_tag") return; // TODO: open tag input
    if (def.requiresConfirm) {
      setConfirmAction(def.id);
    } else {
      dispatch(def.id);
    }
  };

  return (
    <AnimatePresence>
      {selectedIds.length > 0 && (
        <motion.div
          initial={{ y: 80, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: 80, opacity: 0 }}
          transition={{ type: "spring", stiffness: 400, damping: 30 }}
          className="fixed bottom-6 left-1/2 -translate-x-1/2 z-40"
        >
          <div className="flex items-center gap-2 px-4 py-2.5 rounded-xl border border-border bg-bg-surface shadow-xl shadow-black/30 backdrop-blur-sm">
            {/* Selection count */}
            <div className="flex items-center gap-2 pr-3 border-r border-border">
              <span className="text-sm font-semibold text-text-primary tabular-nums">
                {selectedIds.length}
              </span>
              <span className="text-xs text-text-muted">selected</span>
              <button
                onClick={onClear}
                className="ml-1 text-text-muted hover:text-text-primary transition-colors"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Action buttons */}
            {ACTIONS.map((def) => (
              <button
                key={def.id}
                onClick={() => handleAction(def)}
                disabled={isPending}
                className={cn(
                  "flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-md transition-colors disabled:opacity-50",
                  def.variant === "danger"
                    ? "text-severity-critical hover:bg-severity-critical/10"
                    : def.variant === "success"
                    ? "text-status-online hover:bg-status-online/10"
                    : "text-text-secondary hover:bg-bg-elevated"
                )}
              >
                {def.icon}
                {def.label}
              </button>
            ))}

            {/* Severity dropdown */}
            <div className="relative">
              <button
                onClick={() => setShowSeverity((v) => !v)}
                disabled={isPending}
                className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-text-secondary hover:bg-bg-elevated rounded-md transition-colors disabled:opacity-50"
              >
                <Shield className="w-3.5 h-3.5" />
                Severity
                <ChevronDown className="w-3 h-3" />
              </button>

              <AnimatePresence>
                {showSeverity && (
                  <motion.div
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 4 }}
                    className="absolute bottom-full mb-2 left-0 w-32 bg-bg-surface border border-border rounded-lg shadow-xl overflow-hidden z-50"
                  >
                    {SEVERITY_OPTIONS.map((sev) => (
                      <button
                        key={sev}
                        onClick={() => {
                          dispatch("update_severity", { severity: sev });
                          setShowSeverity(false);
                        }}
                        className="w-full px-3 py-2 text-xs text-left text-text-secondary hover:bg-bg-elevated capitalize transition-colors"
                      >
                        {sev}
                      </button>
                    ))}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>

          {/* Confirm modal */}
          <AnimatePresence>
            {confirmAction && (
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="absolute bottom-full mb-3 left-1/2 -translate-x-1/2 w-72 bg-bg-surface border border-border rounded-xl shadow-2xl p-4 z-50"
              >
                <p className="text-sm font-medium text-text-primary mb-1">Confirm action</p>
                <p className="text-xs text-text-muted mb-4">
                  Apply "{confirmAction.replace(/_/g, " ")}" to{" "}
                  <span className="text-text-primary font-medium">{selectedIds.length}</span> alerts?
                </p>
                <div className="flex gap-2">
                  <button
                    onClick={() => setConfirmAction(null)}
                    className="flex-1 py-1.5 text-xs rounded-md border border-border text-text-muted hover:bg-bg-elevated transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => {
                      dispatch(confirmAction);
                      setConfirmAction(null);
                    }}
                    className="flex-1 py-1.5 text-xs rounded-md bg-severity-critical text-white hover:bg-severity-critical/90 transition-colors"
                  >
                    Confirm
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
