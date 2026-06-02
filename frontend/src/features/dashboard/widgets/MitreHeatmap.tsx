import { memo, useState } from "react";
import { Shield } from "lucide-react";
import { cn } from "@/lib/utils";
import { WidgetRefreshButton } from "./KPICard";
import { EmptyState } from "@/components/ui/EmptyState";
import { useMitreCoverage } from "@/features/dashboard/hooks/useDashboardData";
import { MITRE_TACTICS } from "@/data/mitre-framework";
import {
  getHeatmapIntensity,
  HEATMAP_CELL_CLASSES,
  type MitreTechnique,
  type TechniqueStat,
} from "@/features/dashboard/types/mitre";
import type { DashboardTimeRange } from "@/features/dashboard/types/dashboard";

// ─── Technique cell ───────────────────────────────────────────────────────────

const TechniqueCell = memo(function TechniqueCell({
  technique,
  stat,
  isSelected,
  onSelect,
}: {
  technique: MitreTechnique;
  stat?: TechniqueStat;
  isSelected: boolean;
  onSelect: (id: string | null) => void;
}) {
  const count = stat?.count ?? 0;
  const intensity = getHeatmapIntensity(count);

  return (
    <div className="relative group">
      <button
        onClick={() => onSelect(isSelected ? null : technique.id)}
        className={cn(
          "w-full h-7 text-2xs rounded border transition-all duration-150",
          "flex items-center justify-center px-1 truncate",
          HEATMAP_CELL_CLASSES[intensity],
          isSelected && "ring-1 ring-accent ring-offset-1 ring-offset-bg-surface",
          count === 0 && "opacity-40"
        )}
        title={technique.name}
        aria-label={`${technique.id}: ${technique.name} — ${count} alerts`}
      >
        <span className="truncate font-mono" style={{ fontSize: 9 }}>{technique.id}</span>
        {count > 0 && (
          <span className="ml-0.5 flex-shrink-0 font-bold" style={{ fontSize: 9 }}>
            {count > 99 ? "99+" : count}
          </span>
        )}
      </button>

      {/* Tooltip */}
      <div className={cn(
        "absolute z-50 bottom-full left-1/2 -translate-x-1/2 mb-2",
        "pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity duration-100",
        "w-48 p-2.5 rounded-lg border border-border bg-bg-elevated shadow-elevated"
      )}>
        <p className="text-xs font-medium text-text-primary">{technique.id}</p>
        <p className="text-xs text-text-secondary mt-0.5 leading-tight">{technique.name}</p>
        {stat ? (
          <div className="mt-1.5 pt-1.5 border-t border-border space-y-0.5">
            <div className="flex justify-between text-2xs">
              <span className="text-text-muted">Total alerts</span>
              <span className="text-text-primary font-medium">{stat.count}</span>
            </div>
            {stat.criticalCount > 0 && (
              <div className="flex justify-between text-2xs">
                <span className="text-text-muted">Critical</span>
                <span className="text-severity-critical font-medium">{stat.criticalCount}</span>
              </div>
            )}
          </div>
        ) : (
          <p className="text-2xs text-text-muted mt-1">No detections</p>
        )}
      </div>
    </div>
  );
});

// ─── MitreHeatmap ─────────────────────────────────────────────────────────────

interface MitreHeatmapProps {
  timeRange: DashboardTimeRange;
}

export function MitreHeatmap({ timeRange }: MitreHeatmapProps) {
  const { data, isLoading, isRefetching, refetch } = useMitreCoverage(timeRange);
  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null);

  const counts = data?.techniqueCounts ?? {};
  const covered = data?.coveredTechniques ?? 0;
  const total   = MITRE_TACTICS.reduce((s, t) => s + t.techniques.length, 0);

  return (
    <div className="card flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <Shield className="w-3.5 h-3.5 text-accent" />
          <h3 className="text-sm font-semibold text-text-primary">MITRE ATT&CK</h3>
          {!isLoading && (
            <span className="text-xs text-text-muted">
              {covered}/{total} techniques detected
            </span>
          )}
        </div>

        <div className="flex items-center gap-3">
          {/* Legend */}
          <div className="hidden sm:flex items-center gap-2 text-2xs text-text-muted">
            {(["none", "low", "medium", "high", "critical"] as const).map((i) => (
              <span key={i} className="flex items-center gap-1">
                <span className={cn("w-3 h-3 rounded border", HEATMAP_CELL_CLASSES[i])} />
                {i}
              </span>
            ))}
          </div>
          <WidgetRefreshButton onClick={() => void refetch()} isRefetching={isRefetching} />
        </div>
      </div>

      <div className="flex-1 overflow-x-auto p-4 min-h-0">
        {isLoading ? (
          <div className="flex gap-2 h-full">
            {MITRE_TACTICS.map((tactic) => (
              <div key={tactic.id} className="flex flex-col gap-1" style={{ minWidth: 72 }}>
                <div className="h-5 rounded bg-bg-subtle animate-pulse" />
                {tactic.techniques.map((t) => (
                  <div key={t.id} className="h-7 rounded bg-bg-subtle animate-pulse opacity-50" />
                ))}
              </div>
            ))}
          </div>
        ) : data?.totalAlerts === 0 ? (
          <EmptyState
            icon={<Shield className="w-6 h-6" />}
            title="No MITRE coverage data"
            description="Detection activity will populate the ATT&CK matrix."
            className="h-full"
          />
        ) : (
          <div className="flex gap-1.5 min-w-max">
            {MITRE_TACTICS.map((tactic) => (
              <div key={tactic.id} className="flex flex-col gap-1" style={{ minWidth: 72 }}>
                {/* Tactic column header */}
                <div
                  className="h-6 flex items-center justify-center rounded bg-accent/10 border border-accent/20 px-1"
                  title={tactic.name}
                >
                  <span
                    className="text-accent font-semibold truncate"
                    style={{ fontSize: 9 }}
                  >
                    {tactic.shortName}
                  </span>
                </div>

                {/* Technique cells */}
                {tactic.techniques.map((technique) => (
                  <TechniqueCell
                    key={technique.id}
                    technique={technique}
                    stat={counts[technique.id]}
                    isSelected={selectedTechnique === technique.id}
                    onSelect={setSelectedTechnique}
                  />
                ))}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Selected technique detail */}
      {selectedTechnique && counts[selectedTechnique] && (
        <div className="px-4 py-2.5 border-t border-border flex items-center justify-between flex-shrink-0">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-accent">{selectedTechnique}</span>
            <span className="text-xs text-text-secondary">
              {counts[selectedTechnique].count} alerts
              {counts[selectedTechnique].criticalCount > 0 && (
                <span className="ml-1 text-severity-critical">
                  ({counts[selectedTechnique].criticalCount} critical)
                </span>
              )}
            </span>
          </div>
          <button
            onClick={() => setSelectedTechnique(null)}
            className="text-2xs text-text-muted hover:text-text-primary"
          >
            clear
          </button>
        </div>
      )}
    </div>
  );
}
