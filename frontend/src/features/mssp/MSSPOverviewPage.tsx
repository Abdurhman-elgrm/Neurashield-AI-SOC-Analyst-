import { useEffect, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { Plus, X, AlertTriangle, CheckCircle, Building } from "lucide-react";
import * as Dialog from "@radix-ui/react-dialog";
import { msspApi } from "@/api/mssp";
import type { TenantHealthCard } from "@/api/mssp";
import { useTenantStore } from "@/stores/tenantStore";
import { useAuthStore } from "@/stores/authStore";
import { useQueryClient } from "@tanstack/react-query";
import { cn } from "@/lib/utils";
import { toastError, toastSuccess } from "@/lib/toast";
import { extractApiError } from "@/lib/utils";
import type { MemberRole } from "@/types/tenant";

// ─── Tenant health card ───────────────────────────────────────────────────────

const BREACH_COLORS: Record<string, string> = {
  green: "border-status-online/30 bg-status-online/5",
  amber: "border-severity-medium/30 bg-severity-medium/5",
  red:   "border-severity-critical/30 bg-severity-critical/5",
};

const BREACH_ICONS: Record<string, React.ElementType> = {
  green: CheckCircle,
  amber: AlertTriangle,
  red:   AlertTriangle,
};

const BREACH_ICON_COLORS: Record<string, string> = {
  green: "text-status-online",
  amber: "text-severity-medium",
  red:   "text-severity-critical",
};

function TenantCard({ tenant }: { tenant: TenantHealthCard }) {
  const setStoreTenant = useTenantStore((s) => s.setActiveTenant);
  const setAuthTenant  = useAuthStore((s) => s.setActiveTenant);
  const qc             = useQueryClient();
  const Icon           = BREACH_ICONS[tenant.breach_status] ?? CheckCircle;

  const handleSwitch = () => {
    setStoreTenant({ id: tenant.tenant_id, name: tenant.tenant_name, slug: tenant.tenant_id, is_active: true, created_at: new Date().toISOString(), member_role: "owner" as MemberRole }, "owner");
    setAuthTenant(tenant.tenant_id);
    qc.clear();
    toastSuccess(`Switched to ${tenant.tenant_name}`, "MSSP");
  };

  return (
    <button
      onClick={handleSwitch}
      className={cn(
        "border rounded-xl p-4 text-left transition-all hover:scale-[1.01] hover:shadow-lg w-full",
        BREACH_COLORS[tenant.breach_status] ?? BREACH_COLORS.green,
      )}
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <Building size={14} className="text-text-muted flex-shrink-0" />
          <span className="text-sm font-bold text-text-primary">{tenant.tenant_name}</span>
        </div>
        <Icon size={14} className={cn(BREACH_ICON_COLORS[tenant.breach_status] ?? "")} />
      </div>
      <div className="grid grid-cols-3 gap-2">
        <div className="text-center">
          <p className="text-xl font-extrabold font-mono text-severity-critical">{tenant.open_critical_alerts}</p>
          <p className="text-2xs text-text-muted">Critical Alerts</p>
        </div>
        <div className="text-center">
          <p className="text-xl font-extrabold font-mono text-text-primary">{tenant.unresolved_investigations}</p>
          <p className="text-2xs text-text-muted">Open Investigations</p>
        </div>
        <div className="text-center">
          <p className="text-xl font-extrabold font-mono text-status-online">{tenant.agents_online}</p>
          <p className="text-2xs text-text-muted">Agents Online</p>
        </div>
      </div>
      {tenant.last_event_at && (
        <p className="text-2xs text-text-muted mt-2">
          Last event: {new Date(tenant.last_event_at).toLocaleString([], { dateStyle: "short", timeStyle: "short" })}
        </p>
      )}
    </button>
  );
}

// ─── Create tenant dialog ─────────────────────────────────────────────────────

function CreateTenantDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const mutation = useMutation({
    mutationFn: (n: string) => msspApi.createTenant(n),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["mssp", "overview"] });
      toastSuccess("Tenant created", "MSSP");
      setName(""); onClose();
    },
    onError: (e) => toastError(extractApiError(e), "Create failed"),
  });

  return (
    <Dialog.Root open={open} onOpenChange={(v) => !v && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
        <Dialog.Content
          role="dialog" aria-modal="true" onEscapeKeyDown={onClose}
          className="fixed left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 w-80 rounded-xl border border-border bg-bg-card shadow-elevated p-5"
        >
          <div className="flex items-center justify-between mb-4">
            <Dialog.Title className="text-sm font-bold text-text-primary">New Tenant</Dialog.Title>
            <Dialog.Close asChild><button className="text-text-muted hover:text-text-primary"><X size={14} /></button></Dialog.Close>
          </div>
          <input
            className="w-full bg-bg-elevated border border-border rounded-lg px-3 py-1.5 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent mb-4"
            placeholder="Workspace name…"
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && name.trim() && mutation.mutate(name.trim())}
          />
          <div className="flex gap-2">
            <button onClick={onClose} className="flex-1 btn btn-ghost btn-sm">Cancel</button>
            <button disabled={!name.trim() || mutation.isPending}
              onClick={() => mutation.mutate(name.trim())} className="flex-1 btn btn-primary btn-sm">
              {mutation.isPending ? "Creating…" : "Create"}
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// ─── Aggregate KPI row ────────────────────────────────────────────────────────

function AggregateKPIs({ tenants }: { tenants: TenantHealthCard[] }) {
  const totalCritical = tenants.reduce((s, t) => s + t.open_critical_alerts, 0);
  const totalOpen     = tenants.reduce((s, t) => s + t.unresolved_investigations, 0);
  const totalAgents   = tenants.reduce((s, t) => s + t.agents_online, 0);
  const breachedCount = tenants.filter((t) => t.breach_status === "red").length;
  const atRiskCount   = tenants.filter((t) => t.breach_status === "amber").length;

  const kpis = [
    { label: "Critical Alerts",        value: totalCritical, color: "#EF4444", icon: AlertTriangle },
    { label: "Open Investigations",     value: totalOpen,     color: "#F59E0B", icon: CheckCircle  },
    { label: "Agents Online",           value: totalAgents,   color: "#10B981", icon: CheckCircle  },
    { label: "SLA Breached Tenants",    value: breachedCount, color: "#EF4444", icon: AlertTriangle },
    { label: "At-Risk Tenants",         value: atRiskCount,   color: "#F97316", icon: AlertTriangle },
    { label: "Healthy Tenants",         value: tenants.length - breachedCount - atRiskCount, color: "#10B981", icon: CheckCircle },
  ];

  return (
    <div className="grid grid-cols-6 gap-2 mb-4">
      {kpis.map(({ label, value, color, icon: Icon }) => (
        <div key={label} style={{
          background: "#0D0D0D",
          border: `1px solid ${value > 0 && color !== "#10B981" ? `${color}22` : "rgba(255,255,255,0.06)"}`,
          borderRadius: 8, padding: "12px 14px",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
            <Icon size={11} style={{ color: value > 0 ? color : "#3A4150" }} />
            <span style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1px", color: "#5C6373" }}>
              {label}
            </span>
          </div>
          <div style={{ fontSize: 22, fontWeight: 800, color: value > 0 ? color : "#3A4150", fontFamily: "'JetBrains Mono', monospace", lineHeight: 1 }}>
            {value}
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── MSSPOverviewPage ─────────────────────────────────────────────────────────

export function MSSPOverviewPage() {
  useEffect(() => { document.title = "MSSP Portal — NEURASHIELD"; }, []);
  const [createOpen, setCreateOpen] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ["mssp", "overview"],
    queryFn: msspApi.getOverview,
    staleTime: 60_000,
    refetchInterval: 60_000,
  });

  const sortedTenants = [...(data?.tenants ?? [])].sort((a, b) => {
    const order = { red: 0, amber: 1, green: 2 };
    return (order[a.breach_status as keyof typeof order] ?? 2) - (order[b.breach_status as keyof typeof order] ?? 2);
  });
  const chartTenantNames = data?.tenants.map((t) => t.tenant_name) ?? [];

  return (
    <div className="pb-6">
      <div className="flex items-start justify-between mb-5 flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-extrabold text-text-primary font-display">MSSP Portal</h1>
          <p className="text-xs text-text-muted mt-0.5">
            Cross-tenant health overview — <span className="text-text-secondary font-semibold">{data?.tenants.length ?? 0} workspaces</span>
          </p>
        </div>
        <button onClick={() => setCreateOpen(true)} className="btn btn-primary btn-sm flex items-center gap-1.5">
          <Plus size={13} /> New Tenant
        </button>
      </div>

      {/* Aggregate KPIs */}
      {!isLoading && data?.tenants && <AggregateKPIs tenants={data.tenants} />}
      {isLoading && <div className="grid grid-cols-6 gap-2 mb-4">{Array.from({ length: 6 }, (_, i) => <div key={i} className="skel h-16 rounded-lg" />)}</div>}

      {/* Tenant cards grid — sorted by breach status */}
      {isLoading ? (
        <div className="grid grid-cols-3 gap-3 mb-4">
          {Array.from({ length: 6 }, (_, i) => <div key={i} className="skel h-36 rounded-xl" />)}
        </div>
      ) : sortedTenants.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 gap-4">
          <Building size={36} className="text-text-disabled opacity-30" />
          <div className="text-sm text-text-muted">No tenants yet</div>
          <button onClick={() => setCreateOpen(true)} className="btn btn-primary btn-sm">
            <Plus size={13} /> Create First Tenant
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-3 gap-3 mb-4">
          {sortedTenants.map((t) => <TenantCard key={t.tenant_id} tenant={t} />)}
        </div>
      )}

      {/* Cross-tenant alert trend */}
      <div className="bg-bg-card border border-border rounded-xl p-4">
        <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted mb-3">Alert Volume by Tenant (7d)</h3>
        {isLoading ? <div className="skel h-40 rounded-lg" /> : (
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={data?.alert_trend ?? []} margin={{ top: 4, right: 8, bottom: 0, left: -15 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
              <XAxis dataKey="date" tick={{ fill: "#5C6373", fontSize: 9 }} tickFormatter={(v: string) => v.slice(5)} />
              <YAxis tick={{ fill: "#5C6373", fontSize: 9 }} />
              <Tooltip contentStyle={{ background: "#111", border: "1px solid #1F2937", fontSize: 11 }} />
              {chartTenantNames.map((name, i) => (
                <Bar key={name} dataKey={`tenants.${name}`} name={name} stackId="a" fill={`hsl(${(i * 60) % 360},60%,55%)`} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      <CreateTenantDialog open={createOpen} onClose={() => setCreateOpen(false)} />
    </div>
  );
}
