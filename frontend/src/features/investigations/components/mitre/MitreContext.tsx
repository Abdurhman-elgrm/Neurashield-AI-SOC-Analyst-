import { Shield } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import type { MITRETechnique, InvestigationSeverity } from "../../types/investigation";

const SEV_VARIANT: Record<InvestigationSeverity, "critical" | "high" | "medium" | "low"> = {
  critical: "critical", high: "high", medium: "medium", low: "low",
};

interface MitreContextProps {
  techniques: MITRETechnique[];
  compact?: boolean;
}

export function MitreContext({ techniques, compact = false }: MitreContextProps) {
  if (!techniques.length) {
    return (
      <EmptyState
        icon={<Shield className="w-5 h-5" />}
        title="No MITRE techniques"
        description="Techniques will be mapped as alerts are analyzed."
        className="py-6"
      />
    );
  }

  // Group by tactic
  const byTactic = techniques.reduce<Record<string, MITRETechnique[]>>((acc, t) => {
    (acc[t.tacticId] ??= []).push(t);
    return acc;
  }, {});

  return (
    <div className="space-y-3">
      {Object.entries(byTactic).map(([tacticId, techs]) => (
        <div key={tacticId}>
          <div className="flex items-center gap-1.5 mb-1.5">
            <span className="text-2xs font-mono text-accent">{tacticId}</span>
            <span className="text-2xs text-text-muted font-medium uppercase tracking-wider">
              {techs[0].tacticName}
            </span>
          </div>
          <div className="space-y-1">
            {techs.map((t) => (
              <div
                key={t.techniqueId}
                className={cn(
                  "flex items-center justify-between gap-2 rounded-md",
                  compact ? "px-2 py-1" : "px-3 py-2",
                  "bg-bg-subtle border border-border"
                )}
              >
                <div className="flex items-center gap-2 min-w-0">
                  <span className="text-xs font-mono text-accent flex-shrink-0">{t.techniqueId}</span>
                  <span className="text-xs text-text-secondary truncate">{t.techniqueName}</span>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className="text-2xs text-text-muted tabular-nums">{t.alertCount}</span>
                  <Badge variant={SEV_VARIANT[t.severity]} className="text-2xs">
                    {t.severity}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
