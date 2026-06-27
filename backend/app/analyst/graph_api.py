from __future__ import annotations

"""
Graph API service — retrieve and filter the attack graph for an investigation.

Data source: `investigations.graph_json` (populated by the worker).

Filtering:
  - depth          — max hops from roots via BFS (1-10)
  - entity_filter  — whitelist of node_ids to include (and their neighbors)
  - collapse_ips   — merge IP nodes that share the same /24 prefix

Attack paths are computed using shortest-path BFS from user nodes to IP nodes.
"""

from collections import deque
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyst.schemas import GraphEdgeOut, GraphFilter, GraphNodeOut, GraphResponse
from app.core.exceptions import NotFoundError
from app.models.investigation import Investigation

logger = structlog.get_logger(__name__)


class GraphService:
    @staticmethod
    async def get_graph(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        filters: GraphFilter,
    ) -> GraphResponse:
        result = await db.execute(
            select(Investigation).where(
                Investigation.investigation_group_id == investigation_id,
                Investigation.tenant_id == tenant_id,
            )
        )
        inv = result.scalar_one_or_none()
        if inv is None:
            raise NotFoundError(f"Investigation {investigation_id} not found")

        raw: dict[str, Any] = inv.graph_json or {}
        raw_nodes: list[dict[str, Any]] = raw.get("nodes") or []
        raw_edges: list[dict[str, Any]] = raw.get("edges") or []

        nodes, edges = _apply_graph_filters(raw_nodes, raw_edges, filters)
        attack_paths = _find_attack_paths(nodes, edges, max_paths=10)

        return GraphResponse(
            investigation_id=investigation_id,
            nodes=[
                GraphNodeOut(
                    node_id=n["node_id"],
                    node_type=n.get("node_type", "host"),
                    label=n.get("label", n["node_id"]),
                    attributes=n.get("attributes") or {},
                    first_seen=float(n.get("first_seen", 0.0)),
                    last_seen=float(n.get("last_seen", 0.0)),
                    event_count=int(n.get("event_count", 0)),
                )
                for n in nodes
            ],
            edges=[
                GraphEdgeOut(
                    source=e["source"],
                    target=e["target"],
                    edge_type=e.get("edge_type", "connected_to"),
                    weight=int(e.get("weight", 1)),
                    first_seen=float(e.get("first_seen", 0.0)),
                    last_seen=float(e.get("last_seen", 0.0)),
                )
                for e in edges
            ],
            attack_paths=attack_paths,
            node_count=len(nodes),
            edge_count=len(edges),
            max_depth=_compute_max_depth(nodes, edges),
        )

    @staticmethod
    async def get_node_neighbors(
        db: AsyncSession,
        tenant_id: UUID,
        investigation_id: str,
        node_id: str,
        depth: int = 2,
    ) -> GraphResponse:
        """Return the sub-graph reachable from a given node within `depth` hops."""
        filters = GraphFilter(depth=depth, entity_filter=[node_id])
        return await GraphService.get_graph(db, tenant_id, investigation_id, filters)


# ─── Filter + transform helpers ───────────────────────────────────────────────


def _apply_graph_filters(
    raw_nodes: list[dict[str, Any]],
    raw_edges: list[dict[str, Any]],
    filters: GraphFilter,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    node_map = {n["node_id"]: n for n in raw_nodes}

    # Build adjacency (undirected) for BFS
    adj: dict[str, list[str]] = {}
    for e in raw_edges:
        adj.setdefault(e["source"], []).append(e["target"])
        adj.setdefault(e["target"], []).append(e["source"])

    if filters.entity_filter:
        # BFS from each requested entity node up to `depth` hops
        reachable: set[str] = set()
        for seed in filters.entity_filter:
            if seed not in node_map:
                continue
            queue: deque[tuple[str, int]] = deque([(seed, 0)])
            visited: set[str] = {seed}
            while queue:
                nid, d = queue.popleft()
                reachable.add(nid)
                if d < filters.depth:
                    for nb in adj.get(nid, []):
                        if nb not in visited:
                            visited.add(nb)
                            queue.append((nb, d + 1))
        filtered_nodes = [n for n in raw_nodes if n["node_id"] in reachable]
        filtered_edges = [
            e for e in raw_edges if e["source"] in reachable and e["target"] in reachable
        ]
    else:
        # BFS from roots up to `depth` hops
        has_incoming: set[str] = {e["target"] for e in raw_edges}
        roots = [n["node_id"] for n in raw_nodes if n["node_id"] not in has_incoming]
        if not roots and raw_nodes:
            roots = [raw_nodes[0]["node_id"]]

        reachable = set()
        for root in roots:
            queue = deque([(root, 0)])
            visited = {root}
            while queue:
                nid, d = queue.popleft()
                reachable.add(nid)
                if d < filters.depth:
                    for nb in adj.get(nid, []):
                        if nb not in visited:
                            visited.add(nb)
                            queue.append((nb, d + 1))

        filtered_nodes = [n for n in raw_nodes if n["node_id"] in reachable]
        filtered_edges = [
            e for e in raw_edges if e["source"] in reachable and e["target"] in reachable
        ]

    if filters.collapse_ips:
        filtered_nodes, filtered_edges = _collapse_ip_nodes(filtered_nodes, filtered_edges)

    return filtered_nodes, filtered_edges


def _collapse_ip_nodes(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Merge IP nodes that share the same /24 prefix into a subnet node."""
    subnet_map: dict[str, str] = {}  # node_id → representative node_id
    for n in nodes:
        nid = n["node_id"]
        if nid.startswith("ip:"):
            ip = nid[3:]
            parts = ip.split(".")
            if len(parts) == 4:
                subnet = ".".join(parts[:3]) + ".0/24"
                rep = f"ip:{subnet}"
                subnet_map[nid] = rep

    collapsed_nodes: list[dict[str, Any]] = []
    seen_subnets: set[str] = set()
    for n in nodes:
        rep = subnet_map.get(n["node_id"])
        if rep:
            if rep not in seen_subnets:
                seen_subnets.add(rep)
                collapsed_nodes.append(
                    {
                        "node_id": rep,
                        "node_type": "ip",
                        "label": rep[3:],
                        "attributes": {"collapsed": True},
                        "first_seen": n.get("first_seen", 0.0),
                        "last_seen": n.get("last_seen", 0.0),
                        "event_count": n.get("event_count", 0),
                    }
                )
        else:
            collapsed_nodes.append(n)

    collapsed_edges: list[dict[str, Any]] = []
    seen_edge_keys: set[tuple[str, str, str]] = set()
    for e in edges:
        src = subnet_map.get(e["source"], e["source"])
        tgt = subnet_map.get(e["target"], e["target"])
        if src == tgt:
            continue
        key = (src, tgt, e.get("edge_type", ""))
        if key not in seen_edge_keys:
            seen_edge_keys.add(key)
            collapsed_edges.append({**e, "source": src, "target": tgt})

    return collapsed_nodes, collapsed_edges


def _find_attack_paths(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    max_paths: int = 10,
) -> list[list[str]]:
    """BFS shortest paths from user nodes to IP nodes."""
    adj: dict[str, list[str]] = {}
    for e in edges:
        adj.setdefault(e["source"], []).append(e["target"])

    user_nodes = [n["node_id"] for n in nodes if n.get("node_type") == "user"]
    ip_nodes = {n["node_id"] for n in nodes if n.get("node_type") == "ip"}

    paths: list[list[str]] = []
    for start in user_nodes:
        if len(paths) >= max_paths:
            break
        visited: set[str] = {start}
        queue: deque[list[str]] = deque([[start]])
        while queue and len(paths) < max_paths:
            path = queue.popleft()
            if len(path) > 8:
                break
            node = path[-1]
            for nb in adj.get(node, []):
                if nb in ip_nodes:
                    paths.append(path + [nb])
                elif nb not in visited:
                    visited.add(nb)
                    queue.append(path + [nb])
    return paths


def _compute_max_depth(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> int:
    if not nodes:
        return 0
    adj: dict[str, list[str]] = {}
    for e in edges:
        adj.setdefault(e["source"], []).append(e["target"])
    has_incoming = {e["target"] for e in edges}
    roots = [n["node_id"] for n in nodes if n["node_id"] not in has_incoming]
    if not roots:
        return 0
    max_d = 0
    for root in roots[:5]:
        q: deque[tuple[str, int]] = deque([(root, 0)])
        vis: set[str] = {root}
        while q:
            nid, d = q.popleft()
            max_d = max(max_d, d)
            for nb in adj.get(nid, []):
                if nb not in vis:
                    vis.add(nb)
                    q.append((nb, d + 1))
    return max_d
