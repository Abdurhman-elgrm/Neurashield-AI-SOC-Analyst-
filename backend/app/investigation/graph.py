from __future__ import annotations

"""
In-memory attack graph.

Nodes are entities (users, hosts, IPs, processes, hashes, domains).
Edges are directional relationships derived from event entity context.

Supports:
  - multi-hop BFS traversal
  - shortest-path lookup
  - parent/child expansion (via SPAWNED / PARENT_OF edges)
  - neighbor discovery

No external graph DB. No recursion.
"""

from collections import deque
from typing import Any

from app.investigation.schemas import (
    AttackGraph,
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
)


# ─── Node-type inference ──────────────────────────────────────────────────────

def _infer_node_type(entity_key: str) -> GraphNodeType:
    if entity_key.startswith("user:"):
        return GraphNodeType.USER
    if entity_key.startswith("host:"):
        return GraphNodeType.HOST
    if entity_key.startswith("ip:"):
        return GraphNodeType.IP
    if entity_key.startswith("proc:"):
        return GraphNodeType.PROCESS
    if entity_key.startswith("hash:"):
        return GraphNodeType.HASH
    if entity_key.startswith("domain:"):
        return GraphNodeType.DOMAIN
    return GraphNodeType.HOST


def _node_label(entity_key: str) -> str:
    for prefix in ("user:", "host:", "ip:", "proc:", "hash:", "domain:"):
        if entity_key.startswith(prefix):
            return entity_key[len(prefix):]
    return entity_key


# ─── Graph builder ────────────────────────────────────────────────────────────

class AttackGraphBuilder:
    """
    Builds an in-memory attack graph from event snapshots.
    All methods are synchronous (no I/O).
    """

    def __init__(self, investigation_id: str) -> None:
        self._inv_id = investigation_id
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[tuple[str, str, GraphEdgeType], GraphEdge] = {}
        self._adj: dict[str, list[str]] = {}

    # ── Public build interface ────────────────────────────────────────────────

    def add_snapshot(self, snapshot: dict[str, Any]) -> None:
        """Ingest one event snapshot — idempotent."""
        ts = self._ts(snapshot)
        entity_keys: list[str] = snapshot.get("related_entity_keys") or []
        hostname = str(snapshot.get("hostname") or "")
        host_key = f"host:{hostname.lower()}" if hostname else None

        for ek in entity_keys:
            self._upsert_node(ek, ts)

        if host_key and host_key not in {ek for ek in entity_keys}:
            self._upsert_node(host_key, ts)

        # Derive edges from context
        self._add_entity_edges(snapshot, entity_keys, host_key, ts)

    def build(self) -> AttackGraph:
        nodes = list(self._nodes.values())
        edges = list(self._edges.values())
        max_depth = self._compute_max_depth()
        return AttackGraph(
            investigation_id=self._inv_id,
            nodes=nodes,
            edges=edges,
            node_count=len(nodes),
            edge_count=len(edges),
            max_depth=max_depth,
        )

    # ── Traversal helpers (operate on built graph) ────────────────────────────

    @staticmethod
    def bfs_neighbors(
        graph: AttackGraph,
        start: str,
        max_hops: int = 3,
    ) -> list[str]:
        """Return all node_ids reachable from start within max_hops."""
        adj: dict[str, list[str]] = {}
        for edge in graph.edges:
            adj.setdefault(edge.source, []).append(edge.target)
            adj.setdefault(edge.target, []).append(edge.source)

        visited: set[str] = {start}
        queue: deque[tuple[str, int]] = deque([(start, 0)])
        result: list[str] = []
        while queue:
            node, depth = queue.popleft()
            if depth >= max_hops:
                continue
            for neighbor in adj.get(node, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    result.append(neighbor)
                    queue.append((neighbor, depth + 1))
        return result

    @staticmethod
    def shortest_path(
        graph: AttackGraph,
        source: str,
        target: str,
        max_hops: int = 10,
    ) -> list[str]:
        """BFS shortest path from source → target. Returns [] if unreachable."""
        adj: dict[str, list[str]] = {}
        for edge in graph.edges:
            adj.setdefault(edge.source, []).append(edge.target)

        if source not in {n.node_id for n in graph.nodes}:
            return []

        visited: set[str] = {source}
        queue: deque[list[str]] = deque([[source]])
        while queue:
            path = queue.popleft()
            if len(path) > max_hops + 1:
                break
            node = path[-1]
            for neighbor in adj.get(node, []):
                if neighbor == target:
                    return path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(path + [neighbor])
        return []

    @staticmethod
    def get_children(graph: AttackGraph, node_id: str) -> list[str]:
        """Return direct children via SPAWNED or PARENT_OF edges."""
        child_types = {GraphEdgeType.SPAWNED, GraphEdgeType.PARENT_OF}
        return [
            e.target for e in graph.edges
            if e.source == node_id and e.edge_type in child_types
        ]

    @staticmethod
    def get_parents(graph: AttackGraph, node_id: str) -> list[str]:
        """Return direct parents via SPAWNED or PARENT_OF edges."""
        parent_types = {GraphEdgeType.SPAWNED, GraphEdgeType.PARENT_OF}
        return [
            e.source for e in graph.edges
            if e.target == node_id and e.edge_type in parent_types
        ]

    @staticmethod
    def get_neighbors(graph: AttackGraph, node_id: str) -> list[str]:
        """Return all adjacent nodes (undirected)."""
        result: set[str] = set()
        for e in graph.edges:
            if e.source == node_id:
                result.add(e.target)
            elif e.target == node_id:
                result.add(e.source)
        return list(result)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _upsert_node(self, node_id: str, ts: float) -> None:
        if node_id in self._nodes:
            n = self._nodes[node_id]
            self._nodes[node_id] = GraphNode(
                node_id=n.node_id,
                node_type=n.node_type,
                label=n.label,
                attributes=n.attributes,
                first_seen=min(n.first_seen, ts) if n.first_seen else ts,
                last_seen=max(n.last_seen, ts),
                event_count=n.event_count + 1,
            )
        else:
            self._nodes[node_id] = GraphNode(
                node_id=node_id,
                node_type=_infer_node_type(node_id),
                label=_node_label(node_id),
                first_seen=ts,
                last_seen=ts,
                event_count=1,
            )
        self._adj.setdefault(node_id, [])

    def _add_edge(
        self,
        source: str,
        target: str,
        edge_type: GraphEdgeType,
        ts: float,
    ) -> None:
        if source == target:
            return
        if source not in self._nodes or target not in self._nodes:
            return
        key = (source, target, edge_type)
        if key in self._edges:
            e = self._edges[key]
            self._edges[key] = GraphEdge(
                source=e.source,
                target=e.target,
                edge_type=e.edge_type,
                weight=e.weight + 1,
                first_seen=min(e.first_seen, ts),
                last_seen=max(e.last_seen, ts),
            )
        else:
            self._edges[key] = GraphEdge(
                source=source,
                target=target,
                edge_type=edge_type,
                weight=1,
                first_seen=ts,
                last_seen=ts,
            )
        if target not in self._adj.get(source, []):
            self._adj.setdefault(source, []).append(target)

    def _add_entity_edges(
        self,
        snap: dict[str, Any],
        entity_keys: list[str],
        host_key: str | None,
        ts: float,
    ) -> None:
        proc = snap.get("process") or {}
        net  = snap.get("network") or {}

        user_keys   = [k for k in entity_keys if k.startswith("user:")]
        proc_keys   = [k for k in entity_keys if k.startswith("proc:")]
        ip_keys     = [k for k in entity_keys if k.startswith("ip:")]
        hash_keys   = [k for k in entity_keys if k.startswith("hash:")]
        domain_keys = [k for k in entity_keys if k.startswith("domain:")]

        # Prefer explicit host entity keys; fall back to hostname-derived key
        ec_host_keys = [k for k in entity_keys if k.startswith("host:")]
        effective_host_keys = ec_host_keys if ec_host_keys else ([host_key] if host_key else [])

        # Processes execute on their host
        for pk in proc_keys:
            for hk in effective_host_keys:
                self._add_edge(pk, hk, GraphEdgeType.EXECUTED_ON, ts)

        # Users authenticate to hosts
        for uk in user_keys:
            for hk in effective_host_keys:
                self._add_edge(uk, hk, GraphEdgeType.AUTHENTICATED_TO, ts)

        # Processes connect to IPs
        for pk in proc_keys:
            for ik in ip_keys:
                self._add_edge(pk, ik, GraphEdgeType.CONNECTED_TO, ts)

        # Processes resolve domains
        for pk in proc_keys:
            for dk in domain_keys:
                self._add_edge(pk, dk, GraphEdgeType.RESOLVED, ts)

        # Processes have hashes (downloaded / associated)
        for pk in proc_keys:
            for hk in hash_keys:
                self._add_edge(pk, hk, GraphEdgeType.DOWNLOADED, ts)

        # Parent-child process relationship via process metadata
        if isinstance(proc, dict):
            parent_guid = proc.get("parent_guid") or proc.get("ppid")
            if parent_guid:
                parent_key = f"proc:guid:{parent_guid}"
                if parent_key in self._nodes:
                    for pk in proc_keys:
                        self._add_edge(parent_key, pk, GraphEdgeType.SPAWNED, ts)

        # Network: src IP → host, dst IP from process
        if isinstance(net, dict):
            src = net.get("source_ip")
            dst = net.get("destination_ip")
            if src and host_key:
                src_key = f"ip:{src}"
                if src_key in self._nodes:
                    self._add_edge(src_key, host_key, GraphEdgeType.CONNECTED_TO, ts)
            if dst:
                dst_key = f"ip:{dst}"
                if dst_key in self._nodes:
                    for pk in proc_keys:
                        self._add_edge(pk, dst_key, GraphEdgeType.CONNECTED_TO, ts)

    def _compute_max_depth(self) -> int:
        """BFS from every root node to find maximum depth."""
        if not self._nodes:
            return 0
        # Nodes with no incoming edges are roots
        has_incoming: set[str] = set()
        for src, targets in self._adj.items():
            has_incoming.update(targets)
        roots = [n for n in self._nodes if n not in has_incoming]
        if not roots:
            roots = list(self._nodes.keys())[:1]

        max_d = 0
        for root in roots[:5]:  # cap scan for performance
            depth = 0
            visited: set[str] = {root}
            queue: deque[tuple[str, int]] = deque([(root, 0)])
            while queue:
                _, d = queue.popleft()
                depth = max(depth, d)
                node = _
                for nb in self._adj.get(node, []):
                    if nb not in visited:
                        visited.add(nb)
                        queue.append((nb, d + 1))
            max_d = max(max_d, depth)
        return max_d

    @staticmethod
    def _ts(snapshot: dict[str, Any]) -> float:
        try:
            return float(snapshot.get("timestamp") or 0.0)
        except (TypeError, ValueError):
            return 0.0


def build_attack_graph(
    investigation_id: str,
    snapshots: list[dict[str, Any]],
) -> AttackGraph:
    builder = AttackGraphBuilder(investigation_id)
    for snap in snapshots:
        builder.add_snapshot(snap)
    return builder.build()
