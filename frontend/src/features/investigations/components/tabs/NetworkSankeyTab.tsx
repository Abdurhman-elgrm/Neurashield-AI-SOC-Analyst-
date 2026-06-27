import { useQuery } from "@tanstack/react-query";
import { useRef, useMemo } from "react";
import { apiClient } from "@/api/client";

// ─── Types ────────────────────────────────────────────────────────────────────

interface NetworkFlow {
  source: string;
  target: string;
  bytes: number;
  packets: number;
  proto: "TCP" | "UDP" | "ICMP" | "OTHER";
  is_lateral?: boolean;
  is_exfil?: boolean;
}

interface NetworkFlowResponse {
  flows: NetworkFlow[];
  start_time: string;
  end_time: string;
}


// ─── Sankey layout engine (simple) ───────────────────────────────────────────

interface SankeyNode {
  id: string;
  x: number;
  y: number;
  height: number;
  totalBytes: number;
  isSource: boolean;
  isSink: boolean;
}

interface SankeyLink {
  source: SankeyNode;
  target: SankeyNode;
  bytes: number;
  width: number;
  path: string;
  flow: NetworkFlow;
}

function buildSankey(flows: NetworkFlow[], svgW: number, svgH: number): { nodes: SankeyNode[]; links: SankeyLink[] } {
  if (!flows.length) return { nodes: [], links: [] };

  const NODE_W = 140;
  const COL_LEFT = 10;
  const COL_RIGHT = svgW - NODE_W - 10;
  const PAD = 8;

  // Collect unique nodes
  const sourceIds = [...new Set(flows.map((f) => f.source))];
  const targetIds = [...new Set(flows.map((f) => f.target))];
  const sinkOnly  = targetIds.filter((t) => !sourceIds.includes(t));
  const sourceOnly = sourceIds.filter((s) => !targetIds.includes(s));
  const both       = sourceIds.filter((s) => targetIds.includes(s));

  const nodeBytes = new Map<string, number>();
  for (const f of flows) {
    nodeBytes.set(f.source, (nodeBytes.get(f.source) ?? 0) + f.bytes);
    nodeBytes.set(f.target, (nodeBytes.get(f.target) ?? 0) + f.bytes);
  }

  const usableH = svgH - PAD * 2;
  const minNodeH = 20;

  const leftIds = sourceOnly.concat(both);
  const leftFinal = leftIds.filter((id) => !sinkOnly.includes(id) || sourceOnly.includes(id));
  const rightFinal = [...new Set([...sinkOnly, ...both])];

  function layoutColumn(ids: string[], x: number): SankeyNode[] {
    const total = ids.reduce((s, id) => s + (nodeBytes.get(id) ?? 0), 0) || 1;
    const nodes: SankeyNode[] = [];
    let yOff = PAD;
    for (const id of ids) {
      const bytes = nodeBytes.get(id) ?? 0;
      const ratio = bytes / total;
      const h = Math.max(minNodeH, ratio * usableH - PAD);
      nodes.push({
        id,
        x,
        y: yOff,
        height: h,
        totalBytes: bytes,
        isSource: sourceIds.includes(id),
        isSink:   sinkOnly.includes(id),
      });
      yOff += h + PAD;
    }
    return nodes;
  }

  const leftNodes  = layoutColumn(leftFinal,  COL_LEFT);
  const rightNodes = layoutColumn(rightFinal, COL_RIGHT);
  const allNodes   = [...leftNodes, ...rightNodes];
  const nodeMap    = new Map(allNodes.map((n) => [n.id, n]));

  // Source/target y-offset tracking for link placement
  const srcYOff = new Map<string, number>(allNodes.map((n) => [n.id, n.y]));
  const tgtYOff = new Map<string, number>(allNodes.map((n) => [n.id, n.y]));

  const links: SankeyLink[] = [];
  for (const flow of flows) {
    const src = nodeMap.get(flow.source);
    const tgt = nodeMap.get(flow.target);
    if (!src || !tgt) continue;

    const maxFlow = Math.max(1, flows.reduce((s, f) => s + f.bytes, 0));
    const linkW = Math.max(2, (flow.bytes / maxFlow) * (Math.min(src.height, 40)));

    const sy = (srcYOff.get(src.id) ?? src.y) + linkW / 2;
    const ty = (tgtYOff.get(tgt.id) ?? tgt.y) + linkW / 2;
    srcYOff.set(src.id, sy + linkW / 2 + 2);
    tgtYOff.set(tgt.id, ty + linkW / 2 + 2);

    const x1 = src.x + NODE_W;
    const x2 = tgt.x;
    const cx = (x1 + x2) / 2;
    const path = `M${x1},${sy} C${cx},${sy} ${cx},${ty} ${x2},${ty}`;

    links.push({ source: src, target: tgt, bytes: flow.bytes, width: linkW, path, flow });
  }

  return { nodes: allNodes, links };
}

function fmtBytes(b: number): string {
  return b >= 1_000_000 ? `${(b / 1_000_000).toFixed(1)} MB`
    : b >= 1_000 ? `${(b / 1_000).toFixed(0)} KB`
    : `${b} B`;
}

// ─── NetworkSankeyTab ─────────────────────────────────────────────────────────

interface Props {
  id: string;
  isActive: boolean;
}

export function NetworkSankeyTab({ id, isActive }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);
  const W = 820;
  const H = 380;

  const { data, isLoading } = useQuery({
    queryKey: ["inv-network-flows", id],
    queryFn: () =>
      apiClient
        .get<{ data: NetworkFlowResponse }>(`/investigations/${id}/network-flows`)
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .then((r) => (r.data as any).data ?? r.data)
        .catch(() => ({ flows: [] as NetworkFlow[], start_time: null, end_time: null })),
    enabled: isActive,
    staleTime: 120_000,
  });

  const { nodes, links } = useMemo(
    () => buildSankey(data?.flows ?? [], W, H),
    [data],
  );

  const NODE_W = 140;

  function linkColor(flow: NetworkFlow): string {
    if (flow.is_exfil)   return "rgba(239,68,68,0.5)";
    if (flow.is_lateral) return "rgba(245,158,11,0.5)";
    return "rgba(59,130,246,0.3)";
  }

  function nodeColor(node: SankeyNode): string {
    if (!node.isSource) return "rgba(99,102,241,0.8)";
    if (node.isSink)    return "rgba(239,68,68,0.8)";
    return "rgba(59,130,246,0.8)";
  }

  return (
    <div className="space-y-3">
      <div>
        <h3 className="text-sm font-bold text-text-primary">Network Flow Sankey</h3>
        <p className="text-xs text-text-muted mt-0.5">
          Traffic volume between hosts during the investigation window.
          Width ∝ bytes transferred.
        </p>
      </div>

      {/* Legend */}
      <div className="flex gap-4 text-2xs text-text-muted">
        {[
          { color: "rgba(239,68,68,0.7)", label: "Exfiltration" },
          { color: "rgba(245,158,11,0.7)", label: "Lateral Movement" },
          { color: "rgba(59,130,246,0.5)", label: "Normal traffic" },
        ].map(({ color, label }) => (
          <span key={label} className="flex items-center gap-1.5">
            <span className="w-6 h-2 rounded-sm flex-shrink-0" style={{ background: color }} />
            {label}
          </span>
        ))}
      </div>

      <div className="rounded-xl border border-border bg-bg-card overflow-hidden">
        {isLoading ? (
          <div className="skel w-full h-96 animate-pulse" />
        ) : (
          <svg
            ref={svgRef}
            viewBox={`0 0 ${W} ${H}`}
            className="w-full"
            style={{ height: H, maxHeight: H }}
            role="img"
            aria-label="Network flow Sankey diagram"
          >
            {/* Links */}
            {links.map((link, i) => (
              <g key={i}>
                <path
                  d={link.path}
                  fill="none"
                  stroke={linkColor(link.flow)}
                  strokeWidth={link.width}
                  strokeLinecap="round"
                  opacity={0.8}
                >
                  <title>{`${link.flow.source} → ${link.flow.target}: ${fmtBytes(link.bytes)} (${link.flow.proto})`}</title>
                </path>
              </g>
            ))}

            {/* Nodes */}
            {nodes.map((node) => (
              <g key={node.id}>
                <rect
                  x={node.x}
                  y={node.y}
                  width={NODE_W}
                  height={node.height}
                  rx={4}
                  fill={nodeColor(node)}
                  opacity={0.85}
                />
                {/* Node label */}
                <foreignObject x={node.x + 4} y={node.y + 4} width={NODE_W - 8} height={node.height - 8}>
                  <div
                    style={{
                      fontSize: 10,
                      fontFamily: "'JetBrains Mono', monospace",
                      color: "#F5F7FA",
                      lineHeight: 1.3,
                      wordBreak: "break-all",
                      overflow: "hidden",
                      display: "-webkit-box",
                      WebkitLineClamp: 2,
                      WebkitBoxOrient: "vertical",
                    }}
                  >
                    {node.id}
                  </div>
                  <div style={{ fontSize: 9, color: "rgba(245,247,250,0.65)", marginTop: 2, fontFamily: "'JetBrains Mono', monospace" }}>
                    {fmtBytes(node.totalBytes)}
                  </div>
                </foreignObject>
              </g>
            ))}
          </svg>
        )}
      </div>

      {/* Flow table */}
      {data && data.flows.length > 0 && (
        <div className="rounded-xl border border-border overflow-hidden">
          <div className="grid px-4 py-2 bg-bg-elevated border-b border-border text-2xs font-bold uppercase tracking-widest text-text-muted" style={{ gridTemplateColumns: "1fr 1fr 80px 80px 70px 80px" }}>
            {["Source", "Destination", "Bytes", "Packets", "Proto", "Type"].map((h) => <span key={h}>{h}</span>)}
          </div>
          {data.flows.map((flow: NetworkFlow, i: number) => (
            <div key={i} className="grid items-center px-4 py-2 border-b border-border/50 last:border-0 hover:bg-bg-elevated/50 transition-colors text-xs" style={{ gridTemplateColumns: "1fr 1fr 80px 80px 70px 80px" }}>
              <span className="font-mono text-text-secondary truncate pr-2">{flow.source}</span>
              <span className="font-mono text-text-secondary truncate pr-2">{flow.target}</span>
              <span className="text-text-muted tabular-nums">{fmtBytes(flow.bytes)}</span>
              <span className="text-text-muted tabular-nums">{flow.packets.toLocaleString()}</span>
              <span className="text-text-muted">{flow.proto}</span>
              <span>
                {flow.is_exfil   && <span className="text-2xs px-1.5 py-0.5 rounded bg-severity-critical/15 text-severity-critical border border-severity-critical/30">Exfil</span>}
                {flow.is_lateral && <span className="text-2xs px-1.5 py-0.5 rounded bg-severity-high/15 text-severity-high border border-severity-high/30">Lateral</span>}
                {!flow.is_exfil && !flow.is_lateral && <span className="text-text-disabled">—</span>}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
