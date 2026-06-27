import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Monitor, User, Globe } from "lucide-react";
import { apiClient } from "@/api/client";
import type { DashboardTimeRange } from "../types/dashboard";

interface TopEntity {
  name: string;
  count: number;
  severity_max: string;
  delta?: number;
}

interface TopEntitiesData {
  hosts: TopEntity[];
  users: TopEntity[];
  ips:   TopEntity[];
}

const SEV_COLORS: Record<string, string> = {
  critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#6B7280",
};

const SEV_BG: Record<string, string> = {
  critical: "rgba(239,68,68,0.08)",
  high:     "rgba(249,115,22,0.08)",
  medium:   "rgba(245,158,11,0.08)",
  low:      "rgba(107,114,128,0.08)",
};


type Tab = "hosts" | "users" | "ips";

const TABS: { key: Tab; label: string; icon: React.ElementType; navParam: string }[] = [
  { key: "hosts", label: "Hosts", icon: Monitor, navParam: "hostname"  },
  { key: "users", label: "Users", icon: User,    navParam: "username"  },
  { key: "ips",   label: "IPs",   icon: Globe,   navParam: "source_ip" },
];

function cx(...classes: (string | false | undefined | null)[]): string {
  return classes.filter(Boolean).join(" ");
}

interface Props {
  timeRange: DashboardTimeRange;
}

export function TopEntitiesWidget({ timeRange }: Props) {
  const navigate  = useNavigate();
  const [tab, setTab] = useState<Tab>("hosts");
  void timeRange;

  const empty: TopEntitiesData = { hosts: [], users: [], ips: [] };

  const { data, isLoading } = useQuery({
    queryKey: ["dashboard", "top-entities", timeRange],
    queryFn: () =>
      apiClient.get(`/dashboard/top-entities?timeRange=${timeRange}`)
         
        .then((r) => ((r.data as any).data ?? r.data) as TopEntitiesData)
        .catch(() => empty),
    staleTime: 120_000,
    placeholderData: empty,
  });

  const display    = data ?? empty;
  const tabCfg     = TABS.find((t) => t.key === tab)!;
  const items      = display[tab];
  const maxCount   = Math.max(1, ...items.map((e) => e.count));
  const totalCount = items.reduce((s, e) => s + e.count, 0);

  return (
    <div className="bg-bg-card border border-border rounded-xl p-4 flex flex-col gap-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted">Top by Alert Volume</h3>
        <span className="text-2xs text-text-disabled">{totalCount} alerts</span>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 bg-bg-elevated rounded-lg p-0.5">
        {TABS.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={cx(
              "flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 rounded-md text-2xs font-semibold transition-all",
              tab === key
                ? "bg-bg-card text-text-primary shadow-sm"
                : "text-text-muted hover:text-text-secondary",
            )}
          >
            <Icon size={10} />
            {label}
          </button>
        ))}
      </div>

      {/* Entity rows */}
      {isLoading ? (
        <div className="space-y-2">
          {[1,2,3,4,5].map(i => <div key={i} className="skel h-8 rounded-md" />)}
        </div>
      ) : (
        <div className="space-y-1.5">
          {items.slice(0, 5).map((e, rank) => {
            const color = SEV_COLORS[e.severity_max] ?? SEV_COLORS.low;
            const bg    = SEV_BG[e.severity_max]     ?? SEV_BG.low;
            const pct   = (e.count / maxCount) * 100;
            const delta = e.delta ?? 0;
            return (
              <button
                key={e.name}
                onClick={() => navigate(`/alerts?${tabCfg.navParam}=${encodeURIComponent(e.name)}`)}
                className="flex items-center gap-2 w-full group px-2 py-1.5 rounded-md hover:bg-bg-elevated transition-colors"
              >
                {/* Rank */}
                <span
                  className="w-4 h-4 rounded text-2xs font-bold flex items-center justify-center flex-shrink-0"
                  style={{ background: rank === 0 ? bg : "transparent", color: rank === 0 ? color : "#3A4150" }}
                >
                  {rank + 1}
                </span>

                {/* Name */}
                <span className="text-xs text-text-secondary font-mono truncate flex-1 text-left group-hover:text-text-primary transition-colors">
                  {e.name}
                </span>

                {/* Delta */}
                {delta !== 0 && (
                  <span
                    className="text-2xs font-bold flex-shrink-0 tabular-nums"
                    style={{ color: delta > 0 ? "#EF4444" : "#10B981" }}
                  >
                    {delta > 0 ? `+${delta}` : delta}
                  </span>
                )}

                {/* Count */}
                <span className="text-xs font-mono font-bold flex-shrink-0" style={{ color }}>
                  {e.count}
                </span>

                {/* Bar */}
                <div className="w-14 flex-shrink-0 bg-bg-elevated rounded-full h-1.5 overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{ width: `${pct}%`, background: color, opacity: 0.75 }}
                  />
                </div>
              </button>
            );
          })}
        </div>
      )}

      <p className="text-2xs text-text-disabled -mt-1">Click to filter alerts · Δ vs prior 24h</p>
    </div>
  );
}
