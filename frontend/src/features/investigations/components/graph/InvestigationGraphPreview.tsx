import { useRef, useEffect, useMemo, useState, memo } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ExternalLink, Monitor, User, Globe, Activity, FileText, Shield, Bell } from "lucide-react";
import { SkeletonText } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/ui/EmptyState";
import { getInvestigationGraph } from "../../api/investigationsApi";
import { PLACEHOLDER_GRAPH } from "../../types/graph";
import { investigationKeys } from "../../hooks/useInvestigation";
import type { GraphNode, GraphEdge, LayoutNode, NodeType } from "../../types/graph";

// ─── Node config ──────────────────────────────────────────────────────────────

const NODE_COLORS: Record<NodeType, { fill: string; stroke: string; icon: React.ReactNode }> = {
  host:    { fill: "#1e3a5f", stroke: "#3b82f6", icon: <Monitor className="w-3 h-3" /> },
  user:    { fill: "#1a3a2a", stroke: "#22c55e", icon: <User className="w-3 h-3" /> },
  ip:      { fill: "#3a1e1e", stroke: "#ef4444", icon: <Globe className="w-3 h-3" /> },
  process: { fill: "#2d2a1e", stroke: "#eab308", icon: <Activity className="w-3 h-3" /> },
  file:    { fill: "#2a2a2a", stroke: "#94a3b8", icon: <FileText className="w-3 h-3" /> },
  domain:  { fill: "#2d1e3a", stroke: "#a78bfa", icon: <Globe className="w-3 h-3" /> },
  alert:   { fill: "#3a1e1e", stroke: "#ef4444", icon: <Bell className="w-3 h-3" /> },
};

// ─── Layout: circular with type-based grouping ────────────────────────────────

function computeLayout(nodes: GraphNode[], width: number, height: number): LayoutNode[] {
  if (!nodes.length) return [];

  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.min(cx, cy) * 0.7;
  const NODE_RADIUS = 22;

  return nodes.map((node, i) => {
    const angle = (2 * Math.PI * i) / nodes.length - Math.PI / 2;
    return {
      ...node,
      x: nodes.length === 1 ? cx : cx + radius * Math.cos(angle),
      y: nodes.length === 1 ? cy : cy + radius * Math.sin(angle),
      radius: NODE_RADIUS,
    };
  });
}

// ─── SVG graph renderer ───────────────────────────────────────────────────────

const GraphRenderer = memo(function GraphRenderer({
  nodes,
  edges,
  width,
  height,
}: {
  nodes: LayoutNode[];
  edges: GraphEdge[];
  width: number;
  height: number;
}) {
  const nodeMap = useMemo(
    () => new Map(nodes.map((n) => [n.id, n])),
    [nodes]
  );

  return (
    <svg width={width} height={height} className="w-full h-full">
      <defs>
        <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
          <polygon points="0 0, 8 3, 0 6" fill="#334155" />
        </marker>
      </defs>

      {/* Edges */}
      {edges.map((edge) => {
        const src = nodeMap.get(edge.source);
        const tgt = nodeMap.get(edge.target);
        if (!src || !tgt) return null;

        // Offset endpoints to node rim
        const dx = tgt.x - src.x;
        const dy = tgt.y - src.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const x1 = src.x + (dx / dist) * src.radius;
        const y1 = src.y + (dy / dist) * src.radius;
        const x2 = tgt.x - (dx / dist) * (tgt.radius + 6);
        const y2 = tgt.y - (dy / dist) * (tgt.radius + 6);

        return (
          <g key={edge.id}>
            <line
              x1={x1} y1={y1} x2={x2} y2={y2}
              stroke={edge.suspicious ? "#ef4444" : "#334155"}
              strokeWidth={edge.suspicious ? 1.5 : 1}
              strokeDasharray={edge.suspicious ? "4 2" : undefined}
              markerEnd="url(#arrowhead)"
              opacity={0.7}
            />
            {edge.label && (
              <text
                x={(x1 + x2) / 2}
                y={(y1 + y2) / 2 - 4}
                textAnchor="middle"
                fontSize={9}
                fill="#64748b"
              >
                {edge.label}
              </text>
            )}
          </g>
        );
      })}

      {/* Nodes */}
      {nodes.map((node) => {
        const config = NODE_COLORS[node.type];
        return (
          <g key={node.id} transform={`translate(${node.x},${node.y})`}>
            {/* Suspicious pulse ring */}
            {node.suspicious && (
              <circle r={node.radius + 4} fill="none" stroke="#ef4444" strokeWidth={1} opacity={0.4} />
            )}
            <circle
              r={node.radius}
              fill={config.fill}
              stroke={node.suspicious ? "#ef4444" : config.stroke}
              strokeWidth={node.suspicious ? 2 : 1.5}
            />
            <text
              textAnchor="middle"
              dominantBaseline="middle"
              fontSize={9}
              fill={config.stroke}
              fontWeight={500}
            >
              {node.label.length > 12 ? node.label.slice(0, 11) + "…" : node.label}
            </text>
            <text
              y={node.radius + 12}
              textAnchor="middle"
              fontSize={8}
              fill="#64748b"
            >
              {node.type}
            </text>
          </g>
        );
      })}
    </svg>
  );
});

// ─── InvestigationGraphPreview ────────────────────────────────────────────────

interface InvestigationGraphPreviewProps {
  investigationId: string;
}

export function InvestigationGraphPreview({ investigationId }: InvestigationGraphPreviewProps) {
  const navigate = useNavigate();
  const containerRef = useRef<HTMLDivElement>(null);
  const [dims, setDims] = useState({ width: 400, height: 280 });

  const { data: graph, isLoading } = useQuery({
    queryKey: investigationKeys.graph(investigationId),
    queryFn: () => getInvestigationGraph(investigationId),
    placeholderData: PLACEHOLDER_GRAPH,
    staleTime: 60_000,
    enabled: !!investigationId,
  });

  useEffect(() => {
    if (!containerRef.current) return;
    const ro = new ResizeObserver(([entry]) => {
      setDims({
        width: entry.contentRect.width,
        height: entry.contentRect.height,
      });
    });
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  const layoutNodes = useMemo(
    () => computeLayout(graph?.nodes ?? [], dims.width, dims.height),
    [graph?.nodes, dims]
  );

  return (
    <div className="card flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <Shield className="w-3.5 h-3.5 text-accent" />
          <h3 className="text-sm font-semibold text-text-primary">Entity Graph</h3>
          {graph && (
            <span className="text-2xs text-text-muted">
              {graph.nodes.length} nodes · {graph.edges.length} edges
            </span>
          )}
        </div>
        <button
          onClick={() => navigate(`/graph?investigation=${investigationId}`)}
          className="flex items-center gap-1 text-xs text-accent hover:underline"
        >
          Full graph <ExternalLink className="w-3 h-3" />
        </button>
      </div>

      <div ref={containerRef} className="flex-1 overflow-hidden">
        {isLoading ? (
          <div className="p-4"><SkeletonText lines={5} /></div>
        ) : !graph?.nodes.length ? (
          <EmptyState
            icon={<Shield className="w-5 h-5" />}
            title="No graph data"
            description="Entity relationships will appear as alerts are analyzed."
            className="py-8"
          />
        ) : (
          <GraphRenderer
            nodes={layoutNodes}
            edges={graph.edges}
            width={dims.width}
            height={dims.height}
          />
        )}
      </div>
    </div>
  );
}
