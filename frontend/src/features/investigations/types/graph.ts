export type NodeType = "host" | "user" | "process" | "ip" | "file" | "domain" | "alert";

export type EdgeType = "network" | "process" | "file" | "auth" | "alert" | "lateral";

export interface GraphNode {
  id: string;
  type: NodeType;
  label: string;
  sublabel?: string;
  suspicious: boolean;
  riskScore: number;    // 0-100
  metadata: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  type: EdgeType;
  suspicious: boolean;
  weight: number;       // 0-1 (line thickness)
}

export interface InvestigationGraph {
  investigationId: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  generatedAt: string;
}

// ─── Node layout position (computed client-side) ──────────────────────────────

export interface LayoutNode extends GraphNode {
  x: number;
  y: number;
  radius: number;
}

// ─── Placeholder ──────────────────────────────────────────────────────────────

export const PLACEHOLDER_GRAPH: InvestigationGraph = {
  investigationId: "",
  nodes: [],
  edges: [],
  generatedAt: new Date().toISOString(),
};
