import { useMemo } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  ReactFlowProvider,
  type Node,
  type Edge,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import Dagre from '@dagrejs/dagre'
import type { GraphNodeOut, GraphEdgeOut } from '../../hooks/useInvestigationDetail'

const NODE_COLORS: Record<string, string> = {
  host:    '#60A5FA',
  user:    '#C084FC',
  ip:      '#34D399',
  process: '#FBBF24',
  file:    '#FB923C',
  domain:  '#22D3EE',
}

const SUSPICIOUS_EDGE_TYPES = new Set(['executes', 'writes', 'injects', 'downloads', 'spawns'])

function getLayoutedElements(
  rawNodes: GraphNodeOut[],
  rawEdges: GraphEdgeOut[],
): { nodes: Node[]; edges: Edge[] } {
  const g = new Dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))
  g.setGraph({ rankdir: 'LR', nodesep: 60, ranksep: 120 })

  rawNodes.forEach(n => g.setNode(n.node_id, { width: 140, height: 50 }))
  rawEdges.forEach(e => g.setEdge(e.source, e.target))

  Dagre.layout(g)

  const nodes: Node[] = rawNodes.map(n => {
    const pos = g.node(n.node_id)
    const color = NODE_COLORS[n.node_type] ?? '#8B95A7'
    return {
      id: n.node_id,
      position: {
        x: pos ? pos.x - 70 : 0,
        y: pos ? pos.y - 25 : 0,
      },
      data: {
        label: (
          <div style={{ padding: '4px 8px', textAlign: 'center' }}>
            <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', color, letterSpacing: '0.06em' }}>
              {n.node_type}
            </div>
            <div style={{ fontSize: 11, color: '#F5F7FA', marginTop: 2, maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {n.label}
            </div>
            {n.event_count > 0 && (
              <div style={{ fontSize: 9, color: '#5C6373', marginTop: 1 }}>{n.event_count} evt</div>
            )}
          </div>
        ),
      },
      style: {
        background: 'rgba(10,10,10,0.95)',
        border: `2px solid ${color}`,
        borderRadius: 8,
        width: 140,
        padding: 0,
      },
    }
  })

  const edges: Edge[] = rawEdges.map((e, i) => {
    const suspicious = SUSPICIOUS_EDGE_TYPES.has(e.edge_type)
    return {
      id: `e-${i}-${e.source}-${e.target}`,
      source: e.source,
      target: e.target,
      label: e.edge_type,
      animated: suspicious,
      labelStyle: { fontSize: 9, fill: '#5C6373' },
      style: suspicious
        ? { stroke: '#EF4444', strokeDasharray: '4 2', strokeWidth: 2 }
        : { stroke: '#3A4150', strokeWidth: 1.5 },
    }
  })

  return { nodes, edges }
}

function GraphInner({ nodes: rawNodes, edges: rawEdges }: {
  nodes: GraphNodeOut[]
  edges: GraphEdgeOut[]
}) {
  const { nodes, edges } = useMemo(
    () => getLayoutedElements(rawNodes, rawEdges),
    [rawNodes, rawEdges],
  )

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      fitView
      proOptions={{ hideAttribution: true }}
      style={{ background: '#0A0A0A' }}
      nodesDraggable
      nodesConnectable={false}
    >
      <Background color="#1A1A1A" gap={24} size={1} />
      <Controls
        style={{
          background: '#111',
          border: '1px solid rgba(255,255,255,0.08)',
        }}
      />
    </ReactFlow>
  )
}

export function GraphView({ nodes, edges }: {
  nodes: GraphNodeOut[]
  edges: GraphEdgeOut[]
}) {
  return (
    <div style={{
      height: 520,
      background: '#0A0A0A',
      borderRadius: 8,
      border: '1px solid rgba(255,255,255,0.06)',
      overflow: 'hidden',
    }}>
      <ReactFlowProvider>
        <GraphInner nodes={nodes} edges={edges} />
      </ReactFlowProvider>
    </div>
  )
}
