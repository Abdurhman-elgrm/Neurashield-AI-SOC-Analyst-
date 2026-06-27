import { useQuery } from "@tanstack/react-query";
import { apiClient } from "@/api/client";
import { Database, Users, Cpu, Activity } from "lucide-react";
import { cn } from "@/lib/utils";

// ─── Types ────────────────────────────────────────────────────────────────────

interface QuotaMetric {
  name: string;
  used: number;
  limit: number;
  unit: string;
}

interface QuotaData {
  plan: string;
  renewal_date: string;
  ingestion_rate_eps: number;
  ingestion_limit_eps: number;
  agents_active: number;
  agents_total: number;
  members_active: number;
  storage_used_gb: number;
  storage_limit_gb: number;
}

// ─── Usage bar ────────────────────────────────────────────────────────────────

function UsageBar({ metric }: { metric: QuotaMetric }) {
  const pct = metric.limit > 0 ? Math.min((metric.used / metric.limit) * 100, 100) : 0;
  const color =
    pct >= 90 ? "bg-severity-critical"
    : pct >= 75 ? "bg-severity-high"
    : pct >= 50 ? "bg-severity-medium"
    : "bg-accent";

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-text-secondary">{metric.name}</span>
        <span className="text-xs font-mono text-text-muted">
          {metric.used.toLocaleString()} / {metric.limit.toLocaleString()} {metric.unit}
        </span>
      </div>
      <div className="h-2 rounded-full bg-bg-elevated overflow-hidden">
        <div
          className={cn("h-full rounded-full transition-all", color)}
          style={{ width: `${pct}%` }}
        />
      </div>
      <p className="text-2xs text-text-muted text-right">{Math.round(pct)}% used</p>
    </div>
  );
}

// ─── QuotaDashboardSection ────────────────────────────────────────────────────

const ICONS: Record<string, typeof Database> = {
  "Storage": Database,
  "Analysts": Users,
  "Agents": Cpu,
  "Events": Activity,
};

export function QuotaDashboardSection() {
  const { data, isLoading } = useQuery({
    queryKey: ["quota-dashboard"],
    queryFn: () => apiClient.get<{ data: QuotaData }>("/settings/quota").then((r) => r.data.data),
    staleTime: 60_000,
  });

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-sm font-bold text-text-primary">Quota & Usage</h3>
        <p className="text-xs text-text-muted mt-0.5">Current plan usage across storage, users, agents, and events.</p>
      </div>

      {/* Plan header */}
      <div className="flex items-center justify-between rounded-xl border border-border bg-bg-elevated p-4">
        <div>
          <p className="text-xs text-text-muted">Active Plan</p>
          <p className="text-base font-bold text-text-primary capitalize">{data?.plan ?? "—"}</p>
        </div>
        <div className="text-right">
          <p className="text-xs text-text-muted">Ingestion Rate</p>
          <p className="text-sm font-mono text-text-secondary">
            {data?.ingestion_rate_eps.toLocaleString() ?? "—"} / {data?.ingestion_limit_eps.toLocaleString() ?? "—"} EPS
          </p>
        </div>
        <div className="text-right">
          <p className="text-xs text-text-muted">Renews</p>
          <p className="text-sm text-text-secondary">{data?.renewal_date ? new Date(data.renewal_date).toLocaleDateString() : "—"}</p>
        </div>
      </div>

      {/* Usage bars */}
      {isLoading ? (
        <div className="space-y-4">
          {[1,2,3,4].map((i) => <div key={i} className="skel h-12 rounded-lg animate-pulse" />)}
        </div>
      ) : (
        <div className="rounded-xl border border-border bg-bg-card p-4 space-y-5">
          {data ? ([
            { name: "Agents",  used: data.agents_active,  limit: data.agents_total || data.agents_active || 1, unit: "online" },
            { name: "Analysts", used: data.members_active, limit: Math.max(data.members_active, 50),            unit: "users"  },
            { name: "Storage", used: data.storage_used_gb, limit: data.storage_limit_gb,                        unit: "GB"     },
          ] as QuotaMetric[]).map((metric) => {
            const Icon = ICONS[metric.name] ?? Activity;
            return (
              <div key={metric.name} className="space-y-1">
                <div className="flex items-center gap-1.5 mb-0.5">
                  <Icon size={12} className="text-text-muted" />
                  <span className="text-xs font-semibold text-text-muted uppercase tracking-wider">{metric.name}</span>
                </div>
                <UsageBar metric={metric} />
              </div>
            );
          }) : (
            <p className="text-xs text-text-muted text-center py-4">Quota data unavailable.</p>
          )}
        </div>
      )}

      {/* Upgrade CTA */}
      <div className="rounded-xl border border-accent/20 bg-accent/4 p-4 text-center">
        <p className="text-xs text-text-secondary">Need more capacity?</p>
        <a
          href="mailto:sales@neurashield.com"
          className="text-xs font-semibold text-accent hover:underline mt-0.5 block"
        >
          Contact Sales to upgrade →
        </a>
      </div>
    </div>
  );
}
