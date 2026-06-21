import {
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Server,
  Activity,
  GitMerge,
  Brain,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import { KPICard, KPICardSkeleton } from "./KPICard";
import { useKPISummary } from "@/features/dashboard/hooks/useDashboardData";
import type { DashboardTimeRange } from "@/features/dashboard/types/dashboard";

interface KPIMetricsRowProps {
  timeRange: DashboardTimeRange;
}

export function KPIMetricsRow({ timeRange }: KPIMetricsRowProps) {
  const { data, isPlaceholderData } = useKPISummary(timeRange);
  const navigate = useNavigate();

  // Show skeleton only on the very first load before any data (real or placeholder) is cached
  if (!data) {
    return (
      <div className="grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-8 gap-3">
        {Array.from({ length: 8 }).map((_, i) => (
          <KPICardSkeleton key={i} />
        ))}
      </div>
    );
  }

  const s = data;

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-8 gap-3">
      <KPICard
        label="Total Alerts"
        value={s.alerts.total}
        deltaPercent={s.alerts.delta24h}
        icon={<AlertTriangle className="w-4 h-4" />}
        colorVariant="accent"
        isLive
        isLoading={isPlaceholderData}
        onClick={() => navigate("/alerts")}
      />
      <KPICard
        label="Critical Alerts"
        value={s.alerts.critical}
        deltaPercent={s.alerts.criticalDelta24h}
        icon={<ShieldAlert className="w-4 h-4" />}
        colorVariant={s.alerts.critical > 0 ? "critical" : "default"}
        isLoading={isPlaceholderData}
        onClick={() => navigate("/alerts?severity=critical")}
      />
      <KPICard
        label="Active Investigations"
        value={s.investigations.active}
        deltaPercent={s.investigations.delta24h}
        icon={<ShieldCheck className="w-4 h-4" />}
        colorVariant="accent"
        isLoading={isPlaceholderData}
        onClick={() => navigate("/investigations")}
      />
      <KPICard
        label="Events / Sec"
        value={s.ingestion.epsNow}
        deltaPercent={s.ingestion.deltaPercent}
        icon={<Zap className="w-4 h-4" />}
        colorVariant="low"
        isLive
        isLoading={isPlaceholderData}
        formatter={(v) => v >= 1000 ? `${(v / 1000).toFixed(1)}K` : String(v)}
      />
      <KPICard
        label="Online Agents"
        value={s.agents.online}
        icon={<Server className="w-4 h-4" />}
        colorVariant={s.agents.offline > 0 ? "high" : "low"}
        suffix={`/ ${s.agents.total}`}
        isLoading={isPlaceholderData}
        onClick={() => navigate("/agents")}
      />
      <KPICard
        label="Rules Triggered"
        value={s.detection.rulesTriggered}
        deltaPercent={s.detection.delta24h}
        icon={<Activity className="w-4 h-4" />}
        colorVariant="accent"
        isLoading={isPlaceholderData}
      />
      <KPICard
        label="Correlated"
        value={s.investigations.correlated}
        icon={<GitMerge className="w-4 h-4" />}
        colorVariant="medium"
        isLoading={isPlaceholderData}
        onClick={() => navigate("/investigations")}
      />
      <KPICard
        label="AI Queue"
        value={s.investigations.aiPending}
        icon={<Brain className="w-4 h-4" />}
        colorVariant={s.investigations.aiPending > 50 ? "high" : "accent"}
        isLoading={isPlaceholderData}
        onClick={() => navigate("/copilot")}
      />
    </div>
  );
}
