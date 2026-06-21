import { useState, useMemo, useCallback, type ComponentType } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  ReactFlow, ReactFlowProvider, Background, Controls, MiniMap,
  type Node, type Edge, type NodeTypes, type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import Dagre from '@dagrejs/dagre'
import {
  Monitor, User, Globe, Cpu, FileText, Link2, AlertTriangle,
  Search, X, ChevronRight, ChevronDown, SlidersHorizontal,
  Layers, CornerDownRight, RefreshCw, ExternalLink, ShieldAlert,
} from 'lucide-react'
import { apiClient } from '@/api/client'
import { listInvestigations } from '@/features/investigations/api/investigationsApi'
import type { InvestigationListItem } from '@/features/investigations/api/investigationsApi'
import type { GraphNodeOut, GraphEdgeOut, GraphResponse } from '@/features/investigations/hooks/useInvestigationDetail'

// ─── Node type config ─────────────────────────────────────────────────────────

const NODE_CFG: Record<string, { color: string; icon: React.ElementType; bg: string }> = {
  host:    { color: '#60A5FA', icon: Monitor,       bg: 'rgba(96,165,250,0.10)' },
  user:    { color: '#C084FC', icon: User,          bg: 'rgba(192,132,252,0.10)' },
  ip:      { color: '#34D399', icon: Globe,         bg: 'rgba(52,211,153,0.10)' },
  process: { color: '#FBBF24', icon: Cpu,           bg: 'rgba(251,191,36,0.10)' },
  file:    { color: '#FB923C', icon: FileText,      bg: 'rgba(251,146,60,0.10)' },
  domain:  { color: '#22D3EE', icon: Link2,         bg: 'rgba(34,211,238,0.10)' },
  alert:   { color: '#F87171', icon: AlertTriangle, bg: 'rgba(248,113,113,0.10)' },
}

const SUSPICIOUS_EDGES = new Set(['executes', 'injects', 'downloads', 'spawns', 'writes'])

// ─── Custom ReactFlow node ────────────────────────────────────────────────────

type SocNodeData = { raw: GraphNodeOut; isSelected: boolean }

function CustomNode({ data }: NodeProps & { data: SocNodeData }) {
  const n    = data.raw
  const cfg  = NODE_CFG[n.node_type] ?? NODE_CFG.host
  const Icon = cfg.icon as React.ElementType
  const isSuspicious = (n.attributes?.suspicious as boolean) ?? false

  return (
    <div style={{
      background: data.isSelected ? 'rgba(59,130,246,0.18)' : cfg.bg,
      border: `1.5px solid ${data.isSelected ? '#3B82F6' : cfg.color}`,
      borderRadius: 10, padding: '6px 10px',
      minWidth: 140, maxWidth: 180,
      boxShadow: data.isSelected
        ? '0 0 0 2px rgba(59,130,246,0.35), 0 4px 16px rgba(0,0,0,0.5)'
        : '0 2px 8px rgba(0,0,0,0.4)',
      position: 'relative', cursor: 'pointer', transition: 'all 120ms',
    }}>
      {isSuspicious && (
        <div style={{
          position: 'absolute', top: -6, right: -6,
          width: 14, height: 14, borderRadius: '50%',
          background: '#EF4444', border: '2px solid #0A0A0A',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <ShieldAlert size={8} color="#fff" />
        </div>
      )}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
        <div style={{
          width: 22, height: 22, borderRadius: 5, background: `${cfg.color}20`,
          display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
        }}>
          <Icon size={11} color={cfg.color} />
        </div>
        <span style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: cfg.color }}>
          {n.node_type}
        </span>
      </div>
      <div style={{ fontSize: 11, fontWeight: 600, color: '#F5F7FA', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 160 }}>
        {n.label}
      </div>
      {n.event_count > 0 && (
        <div style={{ marginTop: 4, fontSize: 9, color: '#5C6373' }}>
          {n.event_count} event{n.event_count !== 1 ? 's' : ''}
        </div>
      )}
    </div>
  )
}

const NODE_TYPES: NodeTypes = { soc: CustomNode as ComponentType<NodeProps> }

// ─── Dagre layout ─────────────────────────────────────────────────────────────

function buildLayout(
  rawNodes: GraphNodeOut[],
  rawEdges: GraphEdgeOut[],
  selectedNodeId: string | null,
): { nodes: Node[]; edges: Edge[] } {
  if (rawNodes.length === 0) return { nodes: [], edges: [] }

  const g = new Dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))
  g.setGraph({ rankdir: 'LR', nodesep: 70, ranksep: 150 })
  rawNodes.forEach(n => g.setNode(n.node_id, { width: 180, height: 60 }))
  rawEdges.forEach(e => {
    if (g.hasNode(e.source) && g.hasNode(e.target)) g.setEdge(e.source, e.target)
  })
  Dagre.layout(g)

  const nodeIdSet = new Set(rawNodes.map(n => n.node_id))
  const edgeSet   = new Set(rawEdges.map(e => `${e.source}→${e.target}`))

  const nodes: Node[] = rawNodes.map(n => {
    const pos = g.node(n.node_id)
    return {
      id: n.node_id, type: 'soc',
      position: { x: pos ? pos.x - 90 : 0, y: pos ? pos.y - 30 : 0 },
      data: { raw: n, isSelected: n.node_id === selectedNodeId } satisfies SocNodeData,
    }
  })

  const edges: Edge[] = rawEdges
    .filter(e => nodeIdSet.has(e.source) && nodeIdSet.has(e.target))
    .map((e, i) => {
      const suspicious     = SUSPICIOUS_EDGES.has(e.edge_type)
      const isBidirectional = edgeSet.has(`${e.target}→${e.source}`)
      return {
        id: `e-${i}-${e.source}-${e.target}`,
        source: e.source, target: e.target,
        label: e.edge_type.replace(/_/g, ' '),
        type: 'smoothstep', animated: suspicious,
        markerEnd: { type: 'arrowclosed' as never, color: suspicious ? '#EF4444' : '#3A4150' },
        labelStyle: { fontSize: 9, fill: '#5C6373', fontFamily: 'monospace' },
        labelBgStyle: { fill: '#0A0A0A', fillOpacity: 0.85 },
        style: {
          stroke: suspicious ? '#EF4444' : '#3A4150',
          strokeWidth: isBidirectional ? 1 : Math.max(1, Math.min(3, e.weight)),
          strokeDasharray: suspicious ? '5 3' : undefined,
        },
      }
    })

  return { nodes, edges }
}

// ─── Score badge ──────────────────────────────────────────────────────────────

function ScoreBadge({ score }: { score: number }) {
  const color = score >= 75 ? '#EF4444' : score >= 50 ? '#F97316' : score >= 25 ? '#F59E0B' : '#10B981'
  const bg    = score >= 75 ? 'rgba(239,68,68,0.12)' : score >= 50 ? 'rgba(249,115,22,0.12)' : score >= 25 ? 'rgba(245,158,11,0.12)' : 'rgba(16,185,129,0.12)'
  return (
    <span style={{ fontSize: 9, fontWeight: 800, fontFamily: 'JetBrains Mono, monospace', color, background: bg, borderRadius: 4, padding: '2px 5px', border: `1px solid ${color}33` }}>
      {score}
    </span>
  )
}

// ─── Node detail panel ────────────────────────────────────────────────────────

function NodeDetailPanel({ node, invId, onClose }: { node: GraphNodeOut; invId: string; onClose: () => void }) {
  const navigate = useNavigate()
  const cfg  = NODE_CFG[node.node_type] ?? NODE_CFG.host
  const Icon = cfg.icon as React.ElementType
  const attrs = node.attributes ?? {}
  const fmtTs = (ts: number) => ts > 0 ? new Date(ts * 1000).toLocaleString() : '—'

  return (
    <div style={{ width: 280, flexShrink: 0, background: '#0D0D0D', borderLeft: '1px solid rgba(255,255,255,0.07)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <div style={{ width: 32, height: 32, borderRadius: 8, background: cfg.bg, border: `1px solid ${cfg.color}40`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
          <Icon size={15} color={cfg.color} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 9, fontWeight: 700, color: cfg.color, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{node.node_type}</div>
          <div style={{ fontSize: 12, fontWeight: 700, color: '#F5F7FA', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{node.label}</div>
        </div>
        <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#5C6373', padding: 2 }}>
          <X size={14} />
        </button>
      </div>

      {/* Stats */}
      <div style={{ padding: '10px 14px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
        {[
          { label: 'Events',     value: node.event_count.toString() },
          { label: 'First seen', value: fmtTs(node.first_seen) },
          { label: 'Last seen',  value: fmtTs(node.last_seen) },
        ].map(({ label, value }) => (
          <div key={label} style={{ marginBottom: 8 }}>
            <div style={{ fontSize: 9, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 2 }}>{label}</div>
            <div style={{ fontSize: 11, color: '#B8C0CC' }}>{value}</div>
          </div>
        ))}
      </div>

      {/* Attributes */}
      {Object.keys(attrs).length > 0 && (
        <div style={{ padding: '10px 14px', borderBottom: '1px solid rgba(255,255,255,0.05)', flex: 1, overflowY: 'auto' }}>
          <div style={{ fontSize: 9, fontWeight: 700, color: '#5C6373', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 8 }}>Attributes</div>
          {Object.entries(attrs).filter(([, v]) => v !== null && v !== undefined && v !== '').map(([k, v]) => (
            <div key={k} style={{ marginBottom: 6 }}>
              <div style={{ fontSize: 9, color: '#3A4150', textTransform: 'uppercase', letterSpacing: '0.07em' }}>{k.replace(/_/g, ' ')}</div>
              <div style={{ fontSize: 11, color: '#8B95A7', wordBreak: 'break-all' }}>{String(v)}</div>
            </div>
          ))}
        </div>
      )}

      {/* Action */}
      <div style={{ padding: '10px 14px' }}>
        <button
          onClick={() => navigate(`/investigations/${invId}`)}
          style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%', padding: '7px 10px', borderRadius: 6, fontSize: 11, fontWeight: 600, background: 'rgba(59,130,246,0.1)', border: '1px solid rgba(59,130,246,0.25)', color: '#93C5FD', cursor: 'pointer' }}
        >
          <ExternalLink size={11} />
          Open Investigation
        </button>
      </div>
    </div>
  )
}

// ─── Attack paths panel ───────────────────────────────────────────────────────

function AttackPathsPanel({ paths, nodes, onClose }: { paths: string[][], nodes: GraphNodeOut[], onClose: () => void }) {
  const nodeMap = useMemo(() => {
    const m: Record<string, GraphNodeOut> = {}
    nodes.forEach(n => { m[n.node_id] = n })
    return m
  }, [nodes])

  return (
    <div style={{ position: 'absolute', bottom: 0, left: 0, right: 0, background: 'rgba(10,10,10,0.97)', borderTop: '1px solid rgba(59,130,246,0.25)', zIndex: 10, maxHeight: 180, display: 'flex', flexDirection: 'column', backdropFilter: 'blur(8px)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 14px', borderBottom: '1px solid rgba(255,255,255,0.05)', flexShrink: 0 }}>
        <ShieldAlert size={13} color="#F59E0B" />
        <span style={{ fontSize: 11, fontWeight: 700, color: '#F5F7FA' }}>Attack Paths ({paths.length})</span>
        <span style={{ fontSize: 10, color: '#5C6373' }}>— BFS shortest paths from user nodes to IP nodes</span>
        <button onClick={onClose} style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: '#5C6373' }}>
          <X size={13} />
        </button>
      </div>
      <div style={{ overflowY: 'auto', padding: '8px 14px', flex: 1 }}>
        {paths.map((path, pi) => (
          <div key={pi} style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 4, marginBottom: 6, paddingBottom: 6, borderBottom: pi < paths.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none' }}>
            <span style={{ fontSize: 9, color: '#5C6373', fontWeight: 700, minWidth: 20 }}>{pi + 1}.</span>
            {path.map((nodeId, ni) => {
              const n = nodeMap[nodeId]
              const cfg = NODE_CFG[n?.node_type ?? 'host'] ?? NODE_CFG.host
              return (
                <div key={nodeId} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span style={{ fontSize: 10, fontWeight: 600, color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.color}30`, borderRadius: 4, padding: '1px 6px', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {n?.label ?? nodeId}
                  </span>
                  {ni < path.length - 1 && (
                    <CornerDownRight size={10} color="#3A4150" style={{ transform: 'rotate(-90deg)' }} />
                  )}
                </div>
              )
            })}
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── ReactFlow canvas ─────────────────────────────────────────────────────────

function GraphCanvas({ nodes, edges, onNodeSelect }: { nodes: Node[]; edges: Edge[]; onNodeSelect: (raw: GraphNodeOut) => void }) {
  const handleNodeClick = useCallback((_: unknown, node: Node) => {
    onNodeSelect((node.data as SocNodeData).raw)
  }, [onNodeSelect])

  return (
    <ReactFlow
      nodes={nodes} edges={edges}
      nodeTypes={NODE_TYPES}
      onNodeClick={handleNodeClick}
      fitView fitViewOptions={{ padding: 0.15 }}
      proOptions={{ hideAttribution: true }}
      style={{ background: '#070707' }}
      minZoom={0.12} maxZoom={3}
      deleteKeyCode={null}
    >
      <Background color="#1A1A1A" gap={28} size={1} />
      <Controls style={{ background: '#111', border: '1px solid rgba(255,255,255,0.08)' }} showInteractive={false} />
      <MiniMap
        nodeColor={n => NODE_CFG[(n.data as SocNodeData).raw?.node_type ?? 'host']?.color ?? '#8B95A7'}
        style={{ background: '#0D0D0D', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6 }}
        maskColor="rgba(0,0,0,0.65)"
      />
    </ReactFlow>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function GraphPage() {
  const [searchParams] = useSearchParams()
  const [selectedId,   setSelectedId]   = useState<string | null>(searchParams.get('investigation'))
  const [selectedNode, setSelectedNode] = useState<GraphNodeOut | null>(null)
  const [depth,        setDepth]        = useState(5)
  const [collapseIps,  setCollapseIps]  = useState(false)
  const [hiddenTypes,  setHiddenTypes]  = useState<Set<string>>(new Set())
  const [searchInv,    setSearchInv]    = useState('')
  const [showPaths,    setShowPaths]    = useState(false)
  const [showControls, setShowControls] = useState(false)

  // Investigations list
  const { data: invListRaw, isLoading: invLoading } = useQuery({
    queryKey: ['graph-inv-list'],
    queryFn:  () => listInvestigations({ limit: 50 }),
    staleTime: 30_000,
  })
  // InvestigationListResponse.data contains the array of items (keyed by investigation_id)
  const invList: InvestigationListItem[] = invListRaw?.data ?? []

  // Graph data
  const { data: graphData, isLoading: graphLoading, refetch: refetchGraph } = useQuery({
    queryKey: ['graph-data', selectedId, depth, collapseIps],
    queryFn:  async () => {
      const resp = await apiClient.get<{ data: GraphResponse }>(
        `/investigations/${selectedId}/graph`,
        { params: { depth, collapse_ips: collapseIps } },
      )
      return resp.data.data!
    },
    enabled:   !!selectedId,
    staleTime: 30_000,
  })

  // Filter by hidden node types
  const filteredData = useMemo(() => {
    if (!graphData) return null
    if (hiddenTypes.size === 0) return graphData
    const nodes = graphData.nodes.filter(n => !hiddenTypes.has(n.node_type))
    const ids   = new Set(nodes.map(n => n.node_id))
    const edges = graphData.edges.filter(e => ids.has(e.source) && ids.has(e.target))
    return { ...graphData, nodes, edges, node_count: nodes.length, edge_count: edges.length }
  }, [graphData, hiddenTypes])

  // Dagre layout — recomputes when data or selection changes
  const layoutData = useMemo(
    () => filteredData ? buildLayout(filteredData.nodes, filteredData.edges, selectedNode?.node_id ?? null) : null,
    [filteredData, selectedNode?.node_id],
  )

  // Filtered investigation list
  const filteredInvs = useMemo(() => {
    if (!searchInv.trim()) return invList
    const q = searchInv.toLowerCase()
    return invList.filter(inv => (inv.title ?? inv.executive_summary ?? '').toLowerCase().includes(q))
  }, [invList, searchInv])

  const allTypes = useMemo(() => {
    const s = new Set<string>()
    graphData?.nodes.forEach(n => s.add(n.node_type))
    return [...s]
  }, [graphData])

  const toggleType = (t: string) => setHiddenTypes(prev => {
    const next = new Set(prev)
    if (next.has(t)) next.delete(t); else next.add(t)
    return next
  })

  const handleNodeSelect = useCallback((raw: GraphNodeOut) => {
    setSelectedNode(prev => prev?.node_id === raw.node_id ? null : raw)
  }, [])

  const selectedInv = invList.find(i => i.investigation_id === selectedId)
  const statusColor = (s: string) =>
    ({ open: '#F59E0B', in_progress: '#60A5FA', closed: '#10B981' }[s] ?? '#5C6373')

  return (
    <div style={{ display: 'flex', height: '100%', overflow: 'hidden', background: '#0A0A0A' }}>

      {/* ── Left sidebar ── */}
      <div style={{ width: 258, flexShrink: 0, borderRight: '1px solid rgba(255,255,255,0.07)', display: 'flex', flexDirection: 'column', background: '#0D0D0D' }}>
        {/* Search */}
        <div style={{ padding: '14px 14px 10px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#F5F7FA', marginBottom: 8 }}>Investigations</div>
          <div style={{ position: 'relative' }}>
            <Search size={11} style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', color: '#3A4150' }} />
            <input
              value={searchInv}
              onChange={e => setSearchInv(e.target.value)}
              placeholder="Search…"
              style={{ width: '100%', boxSizing: 'border-box', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 6, padding: '5px 8px 5px 26px', fontSize: 11, color: '#F5F7FA', outline: 'none' }}
            />
            {searchInv && (
              <button onClick={() => setSearchInv('')} style={{ position: 'absolute', right: 6, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#5C6373', padding: 0 }}>
                <X size={10} />
              </button>
            )}
          </div>
        </div>

        {/* List */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {invLoading ? (
            <div style={{ padding: '24px 14px', color: '#3A4150', fontSize: 11, textAlign: 'center' }}>
              <RefreshCw size={14} className="animate-spin" style={{ margin: '0 auto 6px', display: 'block' }} />
              Loading…
            </div>
          ) : filteredInvs.length === 0 ? (
            <div style={{ padding: '24px 14px', color: '#3A4150', fontSize: 11, textAlign: 'center' }}>
              {searchInv ? 'No results.' : 'No investigations.'}
            </div>
          ) : filteredInvs.map((inv: InvestigationListItem) => {
            const isActive = inv.investigation_id === selectedId
            const label = inv.title || inv.executive_summary?.slice(0, 60) || inv.investigation_id.slice(0, 12)
            return (
              <button
                key={inv.investigation_id}
                onClick={() => { setSelectedId(inv.investigation_id); setSelectedNode(null); setShowPaths(false) }}
                style={{
                  display: 'block', width: '100%', textAlign: 'left',
                  padding: '9px 12px 9px 14px',
                  background: isActive ? 'rgba(59,130,246,0.08)' : 'transparent',
                  borderLeft: `2px solid ${isActive ? '#3B82F6' : 'transparent'}`,
                  border: 'none', borderBottom: '1px solid rgba(255,255,255,0.04)',
                  cursor: 'pointer',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 3 }}>
                  <ScoreBadge score={inv.threat_score} />
                  <span style={{ fontSize: 8, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: statusColor(inv.status) }}>
                    {inv.status}
                  </span>
                </div>
                <div style={{ fontSize: 11, fontWeight: isActive ? 600 : 400, color: isActive ? '#F5F7FA' : '#8B95A7', overflow: 'hidden', textOverflow: 'ellipsis', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', lineHeight: 1.4 }}>
                  {label}
                </div>
                <div style={{ marginTop: 3, fontSize: 9, color: '#3A4150' }}>
                  {new Date(inv.created_at).toLocaleDateString()}
                </div>
              </button>
            )
          })}
        </div>
      </div>

      {/* ── Center graph area ── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', position: 'relative' }}>

        {/* Toolbar */}
        <div style={{ height: 44, flexShrink: 0, display: 'flex', alignItems: 'center', gap: 10, padding: '0 14px', borderBottom: '1px solid rgba(255,255,255,0.06)', background: '#0D0D0D' }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#F5F7FA', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {selectedInv ? (selectedInv.title || selectedInv.executive_summary?.slice(0, 40) || 'Graph') : 'Select an investigation'}
          </div>

          {filteredData && (
            <>
              <div style={{ width: 1, height: 16, background: 'rgba(255,255,255,0.08)' }} />
              {[
                { label: 'Nodes', value: filteredData.node_count, color: '#60A5FA' },
                { label: 'Edges', value: filteredData.edge_count, color: '#C084FC' },
                { label: 'Depth', value: filteredData.max_depth,  color: '#34D399' },
              ].map(({ label, value, color }) => (
                <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span style={{ fontSize: 9, color: '#3A4150', textTransform: 'uppercase', letterSpacing: '0.07em' }}>{label}</span>
                  <span style={{ fontSize: 11, fontWeight: 700, color, fontFamily: 'monospace' }}>{value}</span>
                </div>
              ))}

              {graphData && graphData.attack_paths.length > 0 && (
                <>
                  <div style={{ width: 1, height: 16, background: 'rgba(255,255,255,0.08)' }} />
                  <button
                    onClick={() => setShowPaths(p => !p)}
                    style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, fontWeight: 600, color: showPaths ? '#FCD34D' : '#F59E0B', background: showPaths ? 'rgba(245,158,11,0.15)' : 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: 5, padding: '3px 8px', cursor: 'pointer' }}
                  >
                    <ShieldAlert size={11} />
                    {graphData.attack_paths.length} Attack Path{graphData.attack_paths.length !== 1 ? 's' : ''}
                    {showPaths ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
                  </button>
                </>
              )}
            </>
          )}

          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
            {/* Node type filter chips */}
            {allTypes.length > 0 && (
              <div style={{ display: 'flex', gap: 4 }}>
                {allTypes.map(t => {
                  const cfg    = NODE_CFG[t] ?? NODE_CFG.host
                  const hidden = hiddenTypes.has(t)
                  return (
                    <button key={t} onClick={() => toggleType(t)} title={`${hidden ? 'Show' : 'Hide'} ${t} nodes`}
                      style={{ fontSize: 9, fontWeight: 700, color: hidden ? '#3A4150' : cfg.color, background: hidden ? 'rgba(255,255,255,0.03)' : cfg.bg, border: `1px solid ${hidden ? 'rgba(255,255,255,0.06)' : cfg.color + '40'}`, borderRadius: 4, padding: '2px 6px', cursor: 'pointer', textTransform: 'uppercase', letterSpacing: '0.06em', textDecoration: hidden ? 'line-through' : 'none' }}
                    >
                      {t}
                    </button>
                  )
                })}
              </div>
            )}

            <button onClick={() => setShowControls(p => !p)}
              style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, color: showControls ? '#93C5FD' : '#8B95A7', background: showControls ? 'rgba(59,130,246,0.12)' : 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 5, padding: '3px 8px', cursor: 'pointer' }}
            >
              <SlidersHorizontal size={11} />
              Controls
            </button>

            {selectedId && (
              <button onClick={() => refetchGraph()}
                style={{ display: 'flex', alignItems: 'center', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 5, padding: '3px 7px', cursor: 'pointer', color: '#5C6373' }}
              >
                <RefreshCw size={11} className={graphLoading ? 'animate-spin' : ''} />
              </button>
            )}
          </div>
        </div>

        {/* Controls drawer */}
        {showControls && (
          <div style={{ padding: '10px 14px', background: '#0D0D0D', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', gap: 20, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 10, color: '#5C6373', minWidth: 60 }}>Depth: <strong style={{ color: '#93C5FD' }}>{depth}</strong></span>
              <input type="range" min={1} max={10} value={depth} onChange={e => setDepth(+e.target.value)} style={{ width: 100, accentColor: '#3B82F6' }} />
            </div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 10, color: '#8B95A7' }}>
              <input type="checkbox" checked={collapseIps} onChange={e => setCollapseIps(e.target.checked)} style={{ accentColor: '#3B82F6' }} />
              Collapse IPs to /24 subnets
            </label>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Layers size={11} color="#5C6373" />
              <span style={{ fontSize: 10, color: '#5C6373' }}>Dagre hierarchical layout · Left → Right</span>
            </div>
          </div>
        )}

        {/* Canvas area */}
        <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
          {!selectedId && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 12 }}>
              <div style={{ width: 52, height: 52, borderRadius: '50%', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Layers size={22} color="#3A4150" />
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 14, fontWeight: 600, color: '#5C6373' }}>Select an investigation</div>
                <div style={{ fontSize: 11, color: '#3A4150', marginTop: 4 }}>Choose from the list to view its attack graph</div>
              </div>
            </div>
          )}

          {selectedId && graphLoading && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 10 }}>
              <RefreshCw size={20} color="#3B82F6" className="animate-spin" />
              <span style={{ fontSize: 11, color: '#5C6373' }}>Building graph…</span>
            </div>
          )}

          {selectedId && !graphLoading && filteredData && filteredData.node_count === 0 && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 10 }}>
              <Layers size={28} color="#3A4150" />
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#5C6373' }}>No graph data yet</div>
                <div style={{ fontSize: 11, color: '#3A4150', marginTop: 4, maxWidth: 280, lineHeight: 1.5 }}>
                  The attack graph is generated as events are correlated by the analysis worker.
                </div>
              </div>
            </div>
          )}

          {layoutData && filteredData && filteredData.node_count > 0 && (
            <ReactFlowProvider key={selectedId}>
              <GraphCanvas nodes={layoutData.nodes} edges={layoutData.edges} onNodeSelect={handleNodeSelect} />
            </ReactFlowProvider>
          )}

          {showPaths && graphData && graphData.attack_paths.length > 0 && filteredData && (
            <AttackPathsPanel paths={graphData.attack_paths} nodes={filteredData.nodes} onClose={() => setShowPaths(false)} />
          )}
        </div>
      </div>

      {/* ── Right: Node detail ── */}
      {selectedNode && selectedId && (
        <NodeDetailPanel node={selectedNode} invId={selectedId} onClose={() => setSelectedNode(null)} />
      )}
    </div>
  )
}
