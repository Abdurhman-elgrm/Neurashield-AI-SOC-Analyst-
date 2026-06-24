import { useEffect, useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Edit2, Trash2, Shield, X, Search, Clock, VolumeX } from "lucide-react";
import * as Dialog from "@radix-ui/react-dialog";
import { suppressionApi } from "@/api/suppression";
import type {
  SuppressionRule, CreateSuppressionPayload, SuppressionCondition,
  SuppressionDuration, SuppressionReason,
} from "@/api/suppression";
import { cn } from "@/lib/utils";
import { toastError, toastSuccess } from "@/lib/toast";
import { extractApiError } from "@/lib/utils";

// ─── Form ─────────────────────────────────────────────────────────────────────

const DURATION_OPTS: { value: SuppressionDuration; label: string }[] = [
  { value: "1h",         label: "1 hour"       },
  { value: "4h",         label: "4 hours"      },
  { value: "24h",        label: "24 hours"     },
  { value: "7d",         label: "7 days"       },
  { value: "30d",        label: "30 days"      },
  { value: "indefinite", label: "Indefinitely" },
];

const REASON_OPTS: { value: SuppressionReason; label: string }[] = [
  { value: "testing",            label: "Testing"            },
  { value: "known_good",         label: "Known good"         },
  { value: "noisy_rule",         label: "Noisy rule"         },
  { value: "maintenance_window", label: "Maintenance window" },
  { value: "other",              label: "Other"              },
];

const COND_FIELD_OPTS: SuppressionCondition["field"][] = [
  "hostname_glob", "username_glob", "rule_name_contains", "source_ip_cidr", "mitre_technique",
];

const FIELD_LABELS: Record<string, string> = {
  hostname_glob:        "Hostname (glob)",
  username_glob:        "Username (glob)",
  rule_name_contains:   "Rule name contains",
  source_ip_cidr:       "Source IP (CIDR)",
  mitre_technique:      "MITRE technique",
};

interface FormState {
  name: string;
  duration: SuppressionDuration;
  reason: SuppressionReason;
  notes: string;
  conditions: SuppressionCondition[];
}

const DEFAULT_FORM: FormState = {
  name: "", duration: "24h", reason: "testing", notes: "",
  conditions: [{ field: "hostname_glob", value: "" }],
};

function RuleForm({
  initial,
  onSubmit,
  onCancel,
  loading,
}: {
  initial?: FormState;
  onSubmit: (f: FormState) => void;
  onCancel: () => void;
  loading?: boolean;
}) {
  const [form, setForm] = useState<FormState>(initial ?? DEFAULT_FORM);

  const addCond = () => setForm((f) => ({
    ...f,
    conditions: [...f.conditions, { field: "hostname_glob", value: "" }],
  }));

  const updateCond = (i: number, patch: Partial<SuppressionCondition>) =>
    setForm((f) => ({
      ...f,
      conditions: f.conditions.map((c, idx) => idx === i ? { ...c, ...patch } : c),
    }));

  const removeCond = (i: number) =>
    setForm((f) => ({ ...f, conditions: f.conditions.filter((_, idx) => idx !== i) }));

  const valid = form.name.trim() && form.conditions.length >= 1 &&
    form.conditions.every((c) => c.value.trim());

  const inputCls = "w-full bg-bg-elevated border border-border rounded-lg px-3 py-1.5 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent";
  const selectCls = "w-full bg-bg-elevated border border-border rounded-lg px-3 py-1.5 text-sm text-text-secondary focus:outline-none focus:ring-1 focus:ring-accent";

  return (
    <div className="space-y-4">
      <div className="space-y-1">
        <label className="text-2xs font-bold uppercase tracking-widest text-text-muted">Rule Name *</label>
        <input className={inputCls} value={form.name} onChange={(e) => setForm(f => ({ ...f, name: e.target.value }))} placeholder="Describe what this rule suppresses…" />
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <label className="text-2xs font-bold uppercase tracking-widest text-text-muted">Conditions *</label>
          <button type="button" onClick={addCond} className="text-xs text-accent hover:underline flex items-center gap-1">
            <Plus size={11} /> Add condition
          </button>
        </div>
        {form.conditions.map((c, i) => (
          <div key={i} className="flex items-center gap-2">
            <select
              value={c.field}
              onChange={(e) => updateCond(i, { field: e.target.value as SuppressionCondition["field"] })}
              className={cn(selectCls, "w-44 flex-shrink-0")}
            >
              {COND_FIELD_OPTS.map((f) => <option key={f} value={f}>{FIELD_LABELS[f]}</option>)}
            </select>
            <input
              className={cn(inputCls, "flex-1")}
              value={c.value}
              onChange={(e) => updateCond(i, { value: e.target.value })}
              placeholder="Value…"
            />
            {form.conditions.length > 1 && (
              <button type="button" onClick={() => removeCond(i)} className="text-text-muted hover:text-severity-critical transition-colors flex-shrink-0">
                <X size={13} />
              </button>
            )}
          </div>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <label className="text-2xs font-bold uppercase tracking-widest text-text-muted">Duration *</label>
          <select className={selectCls} value={form.duration} onChange={(e) => setForm(f => ({ ...f, duration: e.target.value as SuppressionDuration }))}>
            {DURATION_OPTS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
        <div className="space-y-1">
          <label className="text-2xs font-bold uppercase tracking-widest text-text-muted">Reason *</label>
          <select className={selectCls} value={form.reason} onChange={(e) => setForm(f => ({ ...f, reason: e.target.value as SuppressionReason }))}>
            {REASON_OPTS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
      </div>

      <div className="space-y-1">
        <label className="text-2xs font-bold uppercase tracking-widest text-text-muted">Notes</label>
        <textarea className={cn(inputCls, "resize-none")} rows={2} value={form.notes}
          onChange={(e) => setForm(f => ({ ...f, notes: e.target.value }))} placeholder="Optional context…" />
      </div>

      <div className="flex items-center justify-end gap-2 pt-2 border-t border-border">
        <button onClick={onCancel} className="btn btn-ghost btn-sm">Cancel</button>
        <button disabled={!valid || loading} onClick={() => onSubmit(form)} className="btn btn-primary btn-sm">
          {loading ? "Saving…" : "Save Rule"}
        </button>
      </div>
    </div>
  );
}

// ─── SuppressionRulesPage ─────────────────────────────────────────────────────

export function SuppressionRulesPage() {
  useEffect(() => { document.title = "Suppression Rules — NEURASHIELD"; }, []);

  const qc = useQueryClient();
  const [dialogOpen,   setDialogOpen]   = useState(false);
  const [editTarget,   setEditTarget]   = useState<SuppressionRule | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<SuppressionRule | null>(null);

  const [search,       setSearch]       = useState("");
  const [statusFilter, setStatusFilter] = useState<"" | "active" | "expired">("");

  const { data: rules = [], isLoading } = useQuery({
    queryKey: ["suppression"],
    queryFn: suppressionApi.list,
    staleTime: 30_000,
  });

  const filteredRules = useMemo(() => {
    let list = rules;
    if (search.trim()) list = list.filter(r => r.name.toLowerCase().includes(search.toLowerCase()));
    if (statusFilter) list = list.filter(r => r.status === statusFilter);
    return list;
  }, [rules, search, statusFilter]);

  const activeCount       = rules.filter(r => r.status === "active").length;
  const totalSuppressed   = rules.reduce((s, r) => s + r.alert_count, 0);
  const indefiniteCount   = rules.filter(r => r.duration === "indefinite").length;

  const createMutation = useMutation({
    mutationFn: (p: CreateSuppressionPayload) => suppressionApi.create(p),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["suppression"] }); setDialogOpen(false); toastSuccess("Rule created", "Suppression"); },
    onError: (e) => toastError(extractApiError(e), "Create failed"),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => suppressionApi.delete(id),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["suppression"] }); setDeleteTarget(null); toastSuccess("Rule deleted", "Suppression"); },
    onError: (e) => toastError(extractApiError(e), "Delete failed"),
  });

  const handleSubmit = (form: FormState) => {
    createMutation.mutate({ name: form.name, conditions: form.conditions, duration: form.duration, reason: form.reason, notes: form.notes || undefined });
  };

  const openCreate = () => { setEditTarget(null); setDialogOpen(true); };

  return (
    <div className="pb-6">
      <div className="flex items-start justify-between mb-5 flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-extrabold text-text-primary font-display">Suppression Rules</h1>
          <p className="text-xs text-text-muted mt-0.5">Mute noisy detections during testing and maintenance</p>
        </div>
        <button onClick={openCreate} className="btn btn-primary btn-sm flex items-center gap-1.5">
          <Plus size={13} /> New Rule
        </button>
      </div>

      {/* KPI strip */}
      {!isLoading && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginBottom: 14 }}>
          {[
            { label: "Total Rules",     value: rules.length,     color: "#8B95A7", icon: Shield,    sublabel: "configured" },
            { label: "Active",          value: activeCount,      color: "#10B981", icon: Shield,    sublabel: "currently muting" },
            { label: "Alerts Muted",    value: totalSuppressed,  color: "#3B82F6", icon: VolumeX,   sublabel: "lifetime count" },
            { label: "Indefinite",      value: indefiniteCount,  color: "#F59E0B", icon: Clock,     sublabel: "no expiry set" },
          ].map(({ label, value, color, icon: Icon, sublabel }) => (
            <div key={label} style={{
              background: "#0D0D0D", border: "1px solid rgba(255,255,255,0.06)",
              borderLeft: `3px solid ${color}`, borderRadius: 8, padding: "12px 14px",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                <Icon size={11} style={{ color, flexShrink: 0 }} />
                <span style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1.2px", color: "#5C6373" }}>{label}</span>
              </div>
              <div style={{ fontSize: 22, fontWeight: 800, color, fontFamily: "'JetBrains Mono', monospace", lineHeight: 1 }}>{value}</div>
              <div style={{ fontSize: 10, color: "#3A4150", marginTop: 4 }}>{sublabel}</div>
            </div>
          ))}
        </div>
      )}

      {/* Search + filter toolbar */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
        <div style={{ position: "relative", flex: 1, maxWidth: 300 }}>
          <Search size={12} style={{ position: "absolute", left: 8, top: "50%", transform: "translateY(-50%)", color: "#5C6373", pointerEvents: "none" }} />
          <input
            value={search} onChange={e => setSearch(e.target.value)} placeholder="Search rules…"
            style={{
              width: "100%", paddingLeft: 26, height: 30, borderRadius: 6, fontSize: 12,
              background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.07)",
              color: "#F5F7FA", outline: "none", boxSizing: "border-box",
            }}
          />
        </div>
        <div style={{ display: "flex", gap: 2, background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 6, padding: 2 }}>
          {[
            { value: "" as const,        label: "All",     color: "#8B95A7" },
            { value: "active" as const,  label: "Active",  color: "#10B981" },
            { value: "expired" as const, label: "Expired", color: "#5C6373" },
          ].map(({ value, label, color }) => (
            <button key={value || "all"} onClick={() => setStatusFilter(value)} style={{
              padding: "3px 10px", borderRadius: 4, border: "none", cursor: "pointer",
              fontSize: 11, fontWeight: 600, transition: "all 100ms",
              background: statusFilter === value ? `${color}18` : "transparent",
              color: statusFilter === value ? color : "#5C6373",
            }}>{label}</button>
          ))}
        </div>
      </div>

      <div className="bg-bg-card border border-border rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-bg-elevated border-b border-border">
            <tr>
              {["Rule Name","Conditions","Duration","Created By","Expires","Count","Status"].map((h) => (
                <th key={h} className="text-left px-3 py-2.5 text-text-muted font-semibold uppercase tracking-wider text-2xs">{h}</th>
              ))}
              <th className="w-16" />
            </tr>
          </thead>
          <tbody>
            {isLoading ? Array.from({ length: 4 }, (_, i) => (
              <tr key={i} className="border-b border-border/50">
                {Array.from({ length: 8 }, (_, j) => <td key={j} className="px-3 py-2.5"><div className="skel h-4 rounded" /></td>)}
              </tr>
            )) : filteredRules.length === 0 ? (
              <tr><td colSpan={8} className="px-4 py-12 text-center text-sm text-text-muted">
                {search || statusFilter ? "No rules match your filters." : "No suppression rules yet. Create one to mute noisy alerts."}
              </td></tr>
            ) : filteredRules.map((r) => (
              <tr key={r.id} className="border-b border-border/50 hover:bg-bg-elevated/50 transition-colors">
                <td className="px-3 py-2.5 font-medium text-text-primary">{r.name}</td>
                <td className="px-3 py-2.5 text-text-muted">
                  {r.conditions.slice(0, 2).map((c, i) => (
                    <span key={i} className="inline-block bg-bg-elevated px-1.5 py-0.5 rounded text-2xs mr-1">
                      {FIELD_LABELS[c.field]}: {c.value}
                    </span>
                  ))}
                </td>
                <td className="px-3 py-2.5 text-text-secondary">{DURATION_OPTS.find(d => d.value === r.duration)?.label ?? r.duration}</td>
                <td className="px-3 py-2.5 text-text-muted">{r.created_by}</td>
                <td className="px-3 py-2.5 text-text-muted font-mono text-2xs">
                  {r.expires_at ? new Date(r.expires_at).toLocaleDateString() : "Never"}
                </td>
                <td className="px-3 py-2.5 font-mono text-accent">{r.alert_count}</td>
                <td className="px-3 py-2.5">
                  <span className={cn("px-1.5 py-0.5 rounded text-2xs font-bold",
                    r.status === "active" ? "bg-status-online/15 text-status-online" : "bg-bg-elevated text-text-muted"
                  )}>{r.status}</span>
                </td>
                <td className="px-3 py-2.5">
                  <div className="flex items-center gap-1">
                    <button onClick={() => { setEditTarget(r); setDialogOpen(true); }}
                      className="text-text-muted hover:text-text-primary transition-colors p-0.5">
                      <Edit2 size={12} />
                    </button>
                    <button onClick={() => setDeleteTarget(r)}
                      className="text-text-muted hover:text-severity-critical transition-colors p-0.5">
                      <Trash2 size={12} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Create/Edit dialog */}
      <Dialog.Root open={dialogOpen} onOpenChange={(v) => !v && setDialogOpen(false)}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content
            role="dialog" aria-modal="true"
            className="fixed left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 w-full max-w-lg rounded-xl border border-border bg-bg-card shadow-elevated"
            onEscapeKeyDown={() => setDialogOpen(false)}
          >
            <div className="flex items-center gap-2 px-5 py-4 border-b border-border">
              <Shield size={14} className="text-accent" />
              <Dialog.Title className="text-sm font-bold text-text-primary">
                {editTarget ? "Edit Suppression Rule" : "New Suppression Rule"}
              </Dialog.Title>
              <Dialog.Close asChild>
                <button className="ml-auto text-text-muted hover:text-text-primary transition-colors"><X size={14} /></button>
              </Dialog.Close>
            </div>
            <div className="p-5">
              <RuleForm
                initial={editTarget ? {
                  name: editTarget.name, duration: editTarget.duration,
                  reason: editTarget.reason, notes: editTarget.notes,
                  conditions: editTarget.conditions,
                } : undefined}
                onSubmit={handleSubmit}
                onCancel={() => setDialogOpen(false)}
                loading={createMutation.isPending}
              />
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* Delete confirm */}
      <Dialog.Root open={!!deleteTarget} onOpenChange={(v) => !v && setDeleteTarget(null)}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content
            role="dialog" aria-modal="true"
            className="fixed left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 w-80 rounded-xl border border-border bg-bg-card shadow-elevated p-5"
            onEscapeKeyDown={() => setDeleteTarget(null)}
          >
            <p className="text-sm font-semibold text-text-primary mb-2">Delete "{deleteTarget?.name}"?</p>
            <p className="text-xs text-text-muted mb-4">This cannot be undone. Suppressed alerts will resume matching existing rules.</p>
            <div className="flex gap-2">
              <button onClick={() => setDeleteTarget(null)} className="flex-1 btn btn-ghost btn-sm">Cancel</button>
              <button
                disabled={deleteMutation.isPending}
                onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
                className="flex-1 py-1.5 text-xs rounded-md bg-severity-critical text-white hover:bg-severity-critical/90 transition-colors"
              >
                {deleteMutation.isPending ? "Deleting…" : "Delete"}
              </button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}
