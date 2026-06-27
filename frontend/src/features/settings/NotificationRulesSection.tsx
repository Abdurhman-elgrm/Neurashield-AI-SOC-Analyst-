import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, Bell } from "lucide-react";
import { apiClient } from "@/api/client";
import type { APIResponse } from "@/types/api";
import { cn } from "@/lib/utils";
import { toastError, toastSuccess } from "@/lib/toast";
import { extractApiError } from "@/lib/utils";

// ─── Types ────────────────────────────────────────────────────────────────────

type Channel = "email" | "slack" | "pagerduty" | "webhook";
type SeverityLevel = "critical" | "high" | "medium" | "low";

// Backend shape from /notification-channels
interface ChannelResponse {
  id: string;
  name: string;
  type: string;
  enabled: boolean;
  min_severity: string;
  created_at: string;
  updated_at: string;
}

interface NotificationRule {
  id: string;
  name: string;
  channel: Channel;
  destination: string;
  min_severity: SeverityLevel;
  enabled: boolean;
}

interface CreateRulePayload {
  name: string;
  channel: Channel;
  destination: string;
  min_severity: SeverityLevel;
}

const CHANNELS: { value: Channel; label: string }[] = [
  { value: "email",     label: "Email"    },
  { value: "slack",     label: "Slack"    },
  { value: "pagerduty", label: "PagerDuty" },
  { value: "webhook",   label: "Webhook"  },
];

const SEVERITIES: { value: SeverityLevel; label: string; color: string }[] = [
  { value: "critical", label: "Critical", color: "text-severity-critical" },
  { value: "high",     label: "High",     color: "text-severity-high"     },
  { value: "medium",   label: "Medium",   color: "text-severity-medium"   },
  { value: "low",      label: "Low",      color: "text-severity-low"      },
];

const PLACEHOLDER: Record<Channel, string> = {
  email:     "analyst@company.com",
  slack:     "https://hooks.slack.com/services/...",
  pagerduty: "routing-key",
  webhook:   "https://hooks.example.com/...",
};

// Map backend ChannelResponse → frontend NotificationRule
function adaptChannel(ch: ChannelResponse): NotificationRule {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const configRaw = (ch as any).config ?? {};
  let destination = "";
  if (ch.type === "slack" || ch.type === "teams") destination = configRaw.webhook_url ?? "";
  else if (ch.type === "webhook")    destination = configRaw.url ?? "";
  else if (ch.type === "pagerduty")  destination = configRaw.integration_key ?? configRaw.routing_key ?? "";
  else if (ch.type === "email")      destination = Array.isArray(configRaw.recipients) ? configRaw.recipients[0] ?? "" : configRaw.recipients ?? "";
  return {
    id:           ch.id,
    name:         ch.name,
    channel:      (ch.type as Channel) ?? "webhook",
    destination,
    min_severity: (ch.min_severity as SeverityLevel) ?? "high",
    enabled:      ch.enabled,
  };
}

// Map frontend payload → backend ChannelCreateRequest
function toBackendPayload(p: CreateRulePayload) {
  let config: Record<string, unknown> = {};
  if (p.channel === "slack")      config = { webhook_url: p.destination };
  else if (p.channel === "webhook")    config = { url: p.destination };
  else if (p.channel === "pagerduty")  config = { integration_key: p.destination };
  else if (p.channel === "email")      config = { recipients: [p.destination] };
  return { name: p.name, type: p.channel, config, min_severity: p.min_severity, enabled: true };
}

// ─── NotificationRulesSection ─────────────────────────────────────────────────

export function NotificationRulesSection() {
  const qc = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState<CreateRulePayload>({
    name: "", channel: "email", destination: "", min_severity: "high",
  });

  const { data: rules = [], isLoading } = useQuery({
    queryKey: ["notification-channels"],
    queryFn: () =>
      apiClient
        .get<APIResponse<ChannelResponse[]>>("/notification-channels")
        .then((r) => (r.data.data ?? []).map(adaptChannel)),
    staleTime: 60_000,
  });

  const createMut = useMutation({
    mutationFn: (payload: CreateRulePayload) =>
      apiClient
        .post<APIResponse<ChannelResponse>>("/notification-channels", toBackendPayload(payload))
        .then((r) => r.data.data),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["notification-channels"] });
      toastSuccess("Notification rule created");
      setAdding(false);
      setForm({ name: "", channel: "email", destination: "", min_severity: "high" });
    },
    onError: (e) => toastError(extractApiError(e), "Failed to create rule"),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => apiClient.delete(`/notification-channels/${id}`),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["notification-channels"] }),
    onError: (e) => toastError(extractApiError(e)),
  });

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiClient.patch(`/notification-channels/${id}`, { enabled }).then((r) => r.data),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["notification-channels"] }),
    onError: (e) => toastError(extractApiError(e)),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-bold text-text-primary">Notification Rules</h3>
          <p className="text-xs text-text-muted mt-0.5">Route alerts to email, Slack, PagerDuty, or webhooks by severity.</p>
        </div>
        <button
          onClick={() => setAdding((v) => !v)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-accent/10 text-accent hover:bg-accent/20 border border-accent/20 transition-all"
        >
          <Plus size={12} /> Add Rule
        </button>
      </div>

      {/* Add form */}
      {adding && (
        <div className="rounded-xl border border-accent/30 bg-bg-elevated p-4 space-y-3">
          <h4 className="text-xs font-bold text-text-secondary">New Notification Rule</h4>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="text-2xs uppercase tracking-widest text-text-muted">Rule Name</label>
              <input
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="e.g. Critical to PagerDuty"
                className="w-full px-2.5 py-1.5 rounded-lg bg-bg-card border border-border text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
              />
            </div>
            <div className="space-y-1">
              <label className="text-2xs uppercase tracking-widest text-text-muted">Channel</label>
              <select
                value={form.channel}
                onChange={(e) => setForm((f) => ({ ...f, channel: e.target.value as Channel }))}
                className="w-full px-2.5 py-1.5 rounded-lg bg-bg-card border border-border text-sm text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
              >
                {CHANNELS.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
              </select>
            </div>
            <div className="space-y-1">
              <label className="text-2xs uppercase tracking-widest text-text-muted">Destination</label>
              <input
                value={form.destination}
                onChange={(e) => setForm((f) => ({ ...f, destination: e.target.value }))}
                placeholder={PLACEHOLDER[form.channel]}
                className="w-full px-2.5 py-1.5 rounded-lg bg-bg-card border border-border text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
              />
            </div>
            <div className="space-y-1">
              <label className="text-2xs uppercase tracking-widest text-text-muted">Min Severity</label>
              <select
                value={form.min_severity}
                onChange={(e) => setForm((f) => ({ ...f, min_severity: e.target.value as SeverityLevel }))}
                className="w-full px-2.5 py-1.5 rounded-lg bg-bg-card border border-border text-sm text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
              >
                {SEVERITIES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
              </select>
            </div>
          </div>
          <div className="flex gap-2 justify-end">
            <button onClick={() => setAdding(false)} className="px-3 py-1.5 rounded-lg text-xs text-text-muted hover:text-text-primary border border-border transition-colors">Cancel</button>
            <button
              disabled={!form.name.trim() || !form.destination.trim() || createMut.isPending}
              onClick={() => createMut.mutate(form)}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-accent text-white hover:bg-accent/90 disabled:opacity-50 transition-colors"
            >
              {createMut.isPending ? "Saving…" : "Save Rule"}
            </button>
          </div>
        </div>
      )}

      {/* Rules list */}
      {isLoading ? (
        <div className="space-y-2">{[1,2].map((i) => <div key={i} className="skel h-12 rounded-xl animate-pulse" />)}</div>
      ) : rules.length === 0 && !adding ? (
        <div className="border-2 border-dashed border-border rounded-xl py-8 flex flex-col items-center gap-2">
          <Bell size={20} className="text-text-muted" />
          <p className="text-sm text-text-muted">No notification rules configured.</p>
        </div>
      ) : (
        <div className="divide-y divide-border border border-border rounded-xl overflow-hidden">
          {rules.map((rule) => {
            const sev = SEVERITIES.find((s) => s.value === rule.min_severity);
            const ch  = CHANNELS.find((c) => c.value === rule.channel);
            return (
              <div key={rule.id} className="flex items-center gap-3 px-4 py-3 bg-bg-card">
                <button
                  onClick={() => toggleMut.mutate({ id: rule.id, enabled: !rule.enabled })}
                  aria-label={rule.enabled ? "Disable rule" : "Enable rule"}
                  className={cn(
                    "relative w-8 h-4 rounded-full flex-shrink-0 transition-colors",
                    rule.enabled ? "bg-accent" : "bg-bg-elevated border border-border",
                  )}
                >
                  <span className={cn("absolute top-0.5 w-3 h-3 rounded-full bg-white shadow transition-transform", rule.enabled ? "translate-x-4" : "translate-x-0.5")} />
                </button>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-text-primary truncate">{rule.name}</p>
                  <p className="text-2xs text-text-muted truncate">
                    {ch?.label} → <span className="font-mono">{rule.destination}</span>
                  </p>
                </div>
                <span className={cn("text-2xs font-bold", sev?.color ?? "text-text-muted")}>≥ {sev?.label}</span>
                <button
                  onClick={() => deleteMut.mutate(rule.id)}
                  className="text-text-muted hover:text-severity-critical transition-colors"
                  aria-label="Delete rule"
                >
                  <Trash2 size={12} />
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
