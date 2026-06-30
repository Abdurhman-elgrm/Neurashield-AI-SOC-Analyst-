import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import * as Dialog from "@radix-ui/react-dialog";
import * as Select from "@radix-ui/react-select";
import { Ticket, ExternalLink, X, ChevronDown, Loader2 } from "lucide-react";
import { ticketingApi } from "@/api/ticketing";
import type { TicketProvider } from "@/api/ticketing";
import type { InvestigationDetail } from "../hooks/useInvestigationDetail";
import { cn } from "@/lib/utils";
import { toastError, toastSuccess } from "@/lib/toast";
import { extractApiError } from "@/lib/utils";

// ─── Provider icons (text-based) ─────────────────────────────────────────────

const PROVIDERS: { value: TicketProvider; label: string; color: string }[] = [
  { value: "jira",        label: "Jira",        color: "#0052CC" },
  { value: "servicenow",  label: "ServiceNow",  color: "#81B5A1" },
  { value: "pagerduty",   label: "PagerDuty",   color: "#06AC38" },
];

function caseId(id: string): string {
  return `INC-${id.replace(/-/g, "").slice(0, 8).toUpperCase()}`;
}

// ─── Ticket badge ─────────────────────────────────────────────────────────────

function TicketBadge({ ticketKey, url, provider }: { ticketKey: string; url: string; provider: TicketProvider }) {
  const p = PROVIDERS.find((x) => x.value === provider);
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded border border-border bg-bg-elevated text-xs text-text-secondary hover:text-text-primary transition-colors"
      title={`Open in ${p?.label ?? provider}`}
    >
      <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: p?.color ?? "#8B95A7" }} />
      {ticketKey}
      <ExternalLink size={10} className="flex-shrink-0" />
    </a>
  );
}

// ─── TicketingIntegrationPanel ────────────────────────────────────────────────

interface Props {
  inv: InvestigationDetail;
}

const selectTriggerCls = cn(
  "flex items-center gap-2 w-full px-2.5 py-1.5 rounded-lg text-sm",
  "bg-bg-elevated border border-border text-text-secondary",
  "hover:border-border-hover transition-colors",
  "focus:outline-none focus:ring-1 focus:ring-accent",
);

export function TicketingIntegrationPanel({ inv }: Props) {
  const [dialogOpen, setDialogOpen] = useState(false);
  const [provider, setProvider]     = useState<TicketProvider>("jira");
  const [summary,  setSummary]      = useState(`[${caseId(inv.investigation_id)}] ${inv.title ?? "Investigation"}`);
  const [assignee, setAssignee]     = useState("");

  const { data: existingTickets } = useQuery({
    queryKey: ["tickets", inv.investigation_id],
    queryFn: () => ticketingApi.getTicketsForInvestigation(inv.investigation_id),
    staleTime: 120_000,
    retry: false,
  });

  const mutation = useMutation({
    mutationFn: ticketingApi.createTicket,
    onSuccess: () => {
      toastSuccess("Ticket created", "Ticketing");
      setDialogOpen(false);
    },
    onError: (e) => toastError(extractApiError(e), "Ticket creation failed"),
  });

  const handleCreate = () => {
    mutation.mutate({
      provider,
      investigation_id: inv.investigation_id,
      fields: {
        summary,
        description: inv.executive_summary ?? "",
        severity: inv.threat_score >= 80 ? "critical" : inv.threat_score >= 60 ? "high" : "medium",
        assignee: assignee || undefined,
      },
    });
  };

  return (
    <>
      <div className="flex items-center gap-2 flex-wrap">
        {(existingTickets ?? []).map((t) => (
          <TicketBadge key={t.id} ticketKey={t.ticket_key} url={t.url} provider={t.provider} />
        ))}
        <button
          onClick={() => setDialogOpen(true)}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium text-text-secondary hover:text-text-primary border border-border hover:border-border-hover transition-all"
        >
          <Ticket size={12} />
          Create Ticket
        </button>
      </div>

      <Dialog.Root open={dialogOpen} onOpenChange={(v) => !v && setDialogOpen(false)}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content
            role="dialog" aria-modal="true" onEscapeKeyDown={() => setDialogOpen(false)}
            className="fixed left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 w-full max-w-md rounded-xl border border-border bg-bg-card shadow-elevated"
          >
            <div className="flex items-center justify-between px-5 py-4 border-b border-border">
              <Dialog.Title className="text-sm font-bold text-text-primary">Create Ticket</Dialog.Title>
              <Dialog.Close asChild>
                <button className="text-text-muted hover:text-text-primary"><X size={14} /></button>
              </Dialog.Close>
            </div>

            <div className="p-5 space-y-4">
              {/* Provider */}
              <div className="space-y-1.5">
                <label className="text-2xs font-bold uppercase tracking-widest text-text-muted">Provider</label>
                <div className="grid grid-cols-3 gap-2">
                  {PROVIDERS.map((p) => (
                    <button
                      key={p.value} type="button"
                      onClick={() => setProvider(p.value)}
                      className={cn("py-2 rounded-lg border text-xs font-semibold transition-all",
                        provider === p.value ? "border-accent bg-accent/8 text-text-primary" : "border-border text-text-muted hover:border-border-hover"
                      )}
                    >
                      {p.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Summary */}
              <div className="space-y-1.5">
                <label className="text-2xs font-bold uppercase tracking-widest text-text-muted">Summary</label>
                <input
                  className="w-full bg-bg-elevated border border-border rounded-lg px-3 py-1.5 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
                  value={summary}
                  onChange={(e) => setSummary(e.target.value)}
                />
              </div>

              {/* Description preview */}
              <div className="space-y-1.5">
                <label className="text-2xs font-bold uppercase tracking-widest text-text-muted">Description (auto-populated)</label>
                <div className="bg-bg-elevated border border-border rounded-lg px-3 py-2 text-xs text-text-muted max-h-24 overflow-y-auto">
                  {inv.executive_summary ?? "No executive summary available."}
                </div>
              </div>

              {/* Severity */}
              <div className="space-y-1.5">
                <label className="text-2xs font-bold uppercase tracking-widest text-text-muted">Severity Mapping</label>
                <Select.Root value={inv.threat_score >= 80 ? "critical" : inv.threat_score >= 60 ? "high" : "medium"}>
                  <Select.Trigger className={selectTriggerCls} aria-label="Severity">
                    <Select.Value />
                    <Select.Icon asChild className="ml-auto text-text-muted"><ChevronDown size={12} /></Select.Icon>
                  </Select.Trigger>
                  <Select.Portal>
                    <Select.Content className="z-[60] min-w-[160px] overflow-hidden rounded-lg border border-border bg-bg-card shadow-elevated" position="popper" sideOffset={4}>
                      <Select.Viewport className="p-1">
                        {["critical","high","medium","low"].map((s) => (
                          <Select.Item key={s} value={s} className="flex items-center px-2.5 py-1.5 text-xs text-text-secondary cursor-pointer select-none hover:bg-bg-elevated focus:outline-none data-[highlighted]:bg-bg-elevated">
                            <Select.ItemText className="capitalize">{s}</Select.ItemText>
                          </Select.Item>
                        ))}
                      </Select.Viewport>
                    </Select.Content>
                  </Select.Portal>
                </Select.Root>
              </div>

              {/* Assignee */}
              <div className="space-y-1.5">
                <label className="text-2xs font-bold uppercase tracking-widest text-text-muted">Assignee (optional)</label>
                <input
                  className="w-full bg-bg-elevated border border-border rounded-lg px-3 py-1.5 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
                  value={assignee}
                  onChange={(e) => setAssignee(e.target.value)}
                  placeholder="username or email"
                />
              </div>
            </div>

            <div className="flex gap-2 px-5 pb-5">
              <button onClick={() => setDialogOpen(false)} className="flex-1 btn btn-ghost btn-sm">Cancel</button>
              <button disabled={!summary.trim() || mutation.isPending} onClick={handleCreate} className="flex-1 btn btn-primary btn-sm">
                {mutation.isPending ? <><Loader2 size={12} className="animate-spin" /> Creating…</> : "Create Ticket"}
              </button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </>
  );
}
