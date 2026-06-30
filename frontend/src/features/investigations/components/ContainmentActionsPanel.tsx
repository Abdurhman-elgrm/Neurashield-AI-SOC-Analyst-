import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { ShieldAlert, WifiOff, RefreshCw, ChevronDown, ChevronUp } from "lucide-react";
import { apiClient } from "@/api/client";
import { cn } from "@/lib/utils";
import { toastError, toastSuccess } from "@/lib/toast";
import { extractApiError } from "@/lib/utils";
import { useTenantStore } from "@/stores/tenantStore";
import * as Dialog from "@radix-ui/react-dialog";

// ─── API ──────────────────────────────────────────────────────────────────────

interface ContainmentPayload {
  investigation_id: string;
  action: "isolate" | "unisolate" | "block_ip";
  hostname: string;
  reason?: string;
}

async function runContainment(payload: ContainmentPayload) {
  return apiClient
    .post(`/investigations/${payload.investigation_id}/containment`, {
      action: payload.action,
      hostname: payload.hostname,
      reason: payload.reason,
    })
    .then((r) => r.data);
}

// ─── ContainmentActionsPanel ──────────────────────────────────────────────────

interface Props {
  investigationId: string;
  hostnames: string[];
}

export function ContainmentActionsPanel({ investigationId, hostnames }: Props) {
  const hasRole  = useTenantStore((s) => s.hasRole);
  const [open,   setOpen]   = useState(false);
  const [confirm, setConfirm] = useState<{ action: ContainmentPayload["action"]; hostname: string } | null>(null);

  const mutation = useMutation({
    mutationFn: runContainment,
    onSuccess: (_, vars) => {
      toastSuccess(`${vars.action} completed`, "Containment");
      setConfirm(null);
    },
    onError: (e) => toastError(extractApiError(e), "Containment failed"),
  });

  if (!hasRole("analyst")) return null;

  const actions = [
    { action: "isolate"   as const, label: "Isolate Host",  icon: WifiOff,      danger: true  },
    { action: "unisolate" as const, label: "Unisolate Host", icon: RefreshCw,    danger: false },
    { action: "block_ip"  as const, label: "Block Source IP", icon: ShieldAlert, danger: true  },
  ];

  return (
    <div className="border border-border rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-2 px-4 py-2.5 bg-bg-card hover:bg-bg-elevated transition-colors"
      >
        <ShieldAlert size={13} className="text-severity-high" />
        <span className="text-xs font-bold text-text-secondary">Containment Actions</span>
        <span className="ml-auto">{open ? <ChevronUp size={12} className="text-text-muted" /> : <ChevronDown size={12} className="text-text-muted" />}</span>
      </button>

      {open && (
        <div className="bg-bg-card border-t border-border px-4 py-3 space-y-2">
          {hostnames.length === 0 && (
            <p className="text-xs text-text-muted">No hosts identified in this investigation.</p>
          )}
          {hostnames.map((host) => (
            <div key={host} className="space-y-1">
              <p className="text-2xs font-bold text-text-muted uppercase tracking-wider font-mono">{host}</p>
              <div className="flex flex-wrap gap-1.5">
                {actions.map(({ action, label, icon: Icon, danger }) => (
                  <button
                    key={action}
                    onClick={() => setConfirm({ action, hostname: host })}
                    disabled={mutation.isPending}
                    className={cn(
                      "flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-medium transition-colors",
                      danger
                        ? "bg-severity-critical/10 text-severity-critical hover:bg-severity-critical/20 border border-severity-critical/20"
                        : "bg-bg-elevated text-text-secondary hover:bg-bg-surface border border-border",
                    )}
                  >
                    <Icon size={11} />
                    {label}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Confirm dialog */}
      <Dialog.Root open={!!confirm} onOpenChange={(v) => !v && setConfirm(null)}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content
            role="dialog" aria-modal="true"
            className="fixed left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 w-80 rounded-xl border border-border bg-bg-card shadow-elevated p-5"
            onEscapeKeyDown={() => setConfirm(null)}
          >
            <p className="text-sm font-semibold text-text-primary mb-2">Confirm containment action</p>
            <p className="text-xs text-text-muted mb-4">
              Apply <strong className="text-text-primary">{confirm?.action?.replace(/_/g, " ")}</strong> to{" "}
              <strong className="text-text-primary font-mono">{confirm?.hostname}</strong>?
              This action may impact operations.
            </p>
            <div className="flex gap-2">
              <button onClick={() => setConfirm(null)} className="flex-1 btn btn-ghost btn-sm">Cancel</button>
              <button
                disabled={mutation.isPending}
                onClick={() => confirm && mutation.mutate({ investigation_id: investigationId, action: confirm.action, hostname: confirm.hostname })}
                className="flex-1 py-1.5 text-xs rounded-md bg-severity-critical text-white hover:bg-severity-critical/90 transition-colors"
              >
                {mutation.isPending ? "Running…" : "Confirm"}
              </button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}
