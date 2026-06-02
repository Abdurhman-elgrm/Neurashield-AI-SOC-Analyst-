// ─── Static MITRE ATT&CK reference types ─────────────────────────────────────

export interface MitreTechnique {
  id: string;       // e.g. "T1566"
  name: string;     // e.g. "Phishing"
  tacticId: string; // parent tactic e.g. "TA0001"
  url?: string;     // ATT&CK URL
}

export interface MitreTactic {
  id: string;           // e.g. "TA0001"
  name: string;         // e.g. "Initial Access"
  shortName: string;    // abbreviated for column header
  techniques: MitreTechnique[];
}

// ─── Dynamic coverage from API ────────────────────────────────────────────────

export interface TechniqueStat {
  techniqueId: string;
  count: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  latestAt: string;
}

export interface MitreCoverageData {
  techniqueCounts: Record<string, TechniqueStat>; // keyed by technique ID
  totalAlerts: number;
  coveredTechniques: number;
  topTechnique: string | null;
  generatedAt: string;
}

// ─── Rendering helpers ────────────────────────────────────────────────────────

export type HeatmapIntensity = "none" | "low" | "medium" | "high" | "critical";

export function getHeatmapIntensity(count: number): HeatmapIntensity {
  if (count === 0) return "none";
  if (count <= 5)  return "low";
  if (count <= 20) return "medium";
  if (count <= 50) return "high";
  return "critical";
}

export const HEATMAP_CELL_CLASSES: Record<HeatmapIntensity, string> = {
  none:     "bg-bg-elevated border-border text-text-muted",
  low:      "bg-accent/10 border-accent/20 text-accent",
  medium:   "bg-severity-medium/20 border-severity-medium/30 text-severity-medium",
  high:     "bg-severity-high/20 border-severity-high/30 text-severity-high",
  critical: "bg-severity-critical/30 border-severity-critical/50 text-severity-critical",
};
