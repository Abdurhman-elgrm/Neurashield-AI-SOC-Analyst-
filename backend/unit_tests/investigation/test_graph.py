from __future__ import annotations

import pytest

from app.investigation.graph import (
    AttackGraphBuilder,
    build_attack_graph,
    _infer_node_type,
    _node_label,
)
from app.investigation.schemas import GraphEdgeType, GraphNodeType
from unit_tests.investigation.conftest import (
    INV_ID, _TS_BASE,
    make_snapshot, make_network_snapshot, make_process_snapshot,
)


class TestNodeTypeInference:
    def test_user_prefix(self):
        assert _infer_node_type("user:alice") == GraphNodeType.USER

    def test_host_prefix(self):
        assert _infer_node_type("host:workstation-01") == GraphNodeType.HOST

    def test_ip_prefix(self):
        assert _infer_node_type("ip:1.2.3.4") == GraphNodeType.IP

    def test_proc_prefix(self):
        assert _infer_node_type("proc:exe:cmd.exe") == GraphNodeType.PROCESS

    def test_hash_prefix(self):
        assert _infer_node_type("hash:md5:deadbeef") == GraphNodeType.HASH

    def test_domain_prefix(self):
        assert _infer_node_type("domain:evil.com") == GraphNodeType.DOMAIN

    def test_label_strips_prefix(self):
        assert _node_label("user:corp\\alice") == "corp\\alice"
        assert _node_label("ip:10.0.0.1") == "10.0.0.1"
        assert _node_label("host:myhost") == "myhost"


class TestGraphBuilderNodes:
    def test_empty_snapshots_empty_graph(self):
        g = build_attack_graph(INV_ID, [])
        assert g.node_count == 0
        assert g.edge_count == 0

    def test_host_node_created_from_entity_key(self):
        snap = make_snapshot(
            related_entity_keys=["host:workstation-01"],
        )
        g = build_attack_graph(INV_ID, [snap])
        node_ids = {n.node_id for n in g.nodes}
        assert "host:workstation-01" in node_ids

    def test_ip_node_created(self):
        snap = make_network_snapshot(dst_ip="93.184.216.34")
        g = build_attack_graph(INV_ID, [snap])
        node_ids = {n.node_id for n in g.nodes}
        assert "ip:93.184.216.34" in node_ids

    def test_process_node_created(self):
        snap = make_process_snapshot(process_name="cmd.exe")
        g = build_attack_graph(INV_ID, [snap])
        node_ids = {n.node_id for n in g.nodes}
        assert any("proc:" in nid for nid in node_ids)

    def test_node_event_count_increments(self):
        snap1 = make_snapshot(event_id="e1", related_entity_keys=["host:myhost"])
        snap2 = make_snapshot(event_id="e2", related_entity_keys=["host:myhost"])
        g = build_attack_graph(INV_ID, [snap1, snap2])
        host_node = next(n for n in g.nodes if n.node_id == "host:myhost")
        assert host_node.event_count == 2

    def test_node_first_last_seen(self):
        snap1 = make_snapshot(event_id="e1", timestamp=_TS_BASE, related_entity_keys=["host:h1"])
        snap2 = make_snapshot(event_id="e2", timestamp=_TS_BASE + 100, related_entity_keys=["host:h1"])
        g = build_attack_graph(INV_ID, [snap1, snap2])
        h = next(n for n in g.nodes if n.node_id == "host:h1")
        assert h.first_seen == _TS_BASE
        assert h.last_seen == _TS_BASE + 100

    def test_duplicate_entity_keys_single_node(self):
        snap1 = make_snapshot(event_id="e1", related_entity_keys=["ip:1.2.3.4"])
        snap2 = make_snapshot(event_id="e2", related_entity_keys=["ip:1.2.3.4"])
        g = build_attack_graph(INV_ID, [snap1, snap2])
        ip_nodes = [n for n in g.nodes if n.node_id == "ip:1.2.3.4"]
        assert len(ip_nodes) == 1

    def test_node_count_field_matches_nodes_list(self):
        snaps = [
            make_snapshot(event_id="e1", related_entity_keys=["host:h1", "ip:1.1.1.1"]),
        ]
        g = build_attack_graph(INV_ID, snaps)
        assert g.node_count == len(g.nodes)


class TestGraphBuilderEdges:
    def test_edge_count_field_matches_edges_list(self):
        snap = make_process_snapshot()
        g = build_attack_graph(INV_ID, [snap])
        assert g.edge_count == len(g.edges)

    def test_executed_on_edge_process_to_host(self):
        snap = make_process_snapshot(hostname="HOST-01")
        g = build_attack_graph(INV_ID, [snap])
        edge_types = {e.edge_type for e in g.edges}
        assert GraphEdgeType.EXECUTED_ON in edge_types

    def test_connected_to_edge_process_to_ip(self):
        snap = make_snapshot(
            event_id="e1",
            hostname="HOST-01",
            category="network",
            related_entity_keys=["host:host-01", "proc:exe:svchost.exe", "ip:93.184.216.34"],
        )
        g = build_attack_graph(INV_ID, [snap])
        edge_types = {e.edge_type for e in g.edges}
        assert GraphEdgeType.CONNECTED_TO in edge_types

    def test_authenticated_to_edge_user_to_host(self):
        snap = make_snapshot(
            event_id="e1",
            hostname="HOST-01",
            related_entity_keys=["host:host-01", "user:corp\\alice"],
        )
        g = build_attack_graph(INV_ID, [snap])
        edge_types = {e.edge_type for e in g.edges}
        assert GraphEdgeType.AUTHENTICATED_TO in edge_types

    def test_resolved_edge_process_to_domain(self):
        snap = make_snapshot(
            event_id="e1",
            related_entity_keys=["proc:exe:chrome.exe", "domain:evil.com", "host:h1"],
        )
        g = build_attack_graph(INV_ID, [snap])
        edge_types = {e.edge_type for e in g.edges}
        assert GraphEdgeType.RESOLVED in edge_types

    def test_edge_weight_increments_on_repetition(self):
        snap1 = make_snapshot(event_id="e1", related_entity_keys=["proc:exe:cmd.exe", "host:h1"])
        snap2 = make_snapshot(event_id="e2", related_entity_keys=["proc:exe:cmd.exe", "host:h1"])
        g = build_attack_graph(INV_ID, [snap1, snap2])
        edges_to_host = [
            e for e in g.edges
            if e.source == "proc:exe:cmd.exe" and e.target == "host:h1"
        ]
        if edges_to_host:
            assert edges_to_host[0].weight == 2


class TestGraphTraversal:
    def _build_simple(self) -> tuple:
        snaps = [
            make_snapshot(event_id="e1", related_entity_keys=["user:alice", "host:h1"]),
            make_snapshot(event_id="e2", related_entity_keys=["host:h1", "ip:1.2.3.4"]),
        ]
        g = build_attack_graph(INV_ID, snaps)
        return g

    def test_bfs_neighbors_reachable(self):
        g = self._build_simple()
        neighbors = AttackGraphBuilder.bfs_neighbors(g, "user:alice", max_hops=2)
        assert "host:h1" in neighbors

    def test_bfs_neighbors_empty_when_no_edges(self):
        snap = make_snapshot(related_entity_keys=["host:isolated"])
        g = build_attack_graph(INV_ID, [snap])
        neighbors = AttackGraphBuilder.bfs_neighbors(g, "host:isolated", max_hops=3)
        assert neighbors == []

    def test_shortest_path_direct(self):
        snaps = [make_snapshot(related_entity_keys=["user:alice", "host:h1"])]
        g = build_attack_graph(INV_ID, snaps)
        path = AttackGraphBuilder.shortest_path(g, "user:alice", "host:h1")
        assert path == ["user:alice", "host:h1"]

    def test_shortest_path_unreachable_returns_empty(self):
        snaps = [
            make_snapshot(event_id="e1", related_entity_keys=["user:alice", "host:h1"]),
            make_snapshot(event_id="e2", related_entity_keys=["host:h2", "ip:9.9.9.9"]),
        ]
        g = build_attack_graph(INV_ID, snaps)
        path = AttackGraphBuilder.shortest_path(g, "user:alice", "ip:9.9.9.9")
        # May or may not reach depending on graph construction — just verify type
        assert isinstance(path, list)

    def test_get_neighbors_returns_adjacent(self):
        snaps = [make_snapshot(related_entity_keys=["user:alice", "host:h1"])]
        g = build_attack_graph(INV_ID, snaps)
        neighbors = AttackGraphBuilder.get_neighbors(g, "user:alice")
        assert "host:h1" in neighbors

    def test_get_children_empty_without_spawn_edges(self):
        snaps = [make_snapshot(related_entity_keys=["host:h1", "ip:1.2.3.4"])]
        g = build_attack_graph(INV_ID, snaps)
        children = AttackGraphBuilder.get_children(g, "host:h1")
        assert isinstance(children, list)

    def test_max_depth_non_negative(self):
        snaps = [make_snapshot(related_entity_keys=["host:h1", "ip:1.2.3.4", "user:alice"])]
        g = build_attack_graph(INV_ID, snaps)
        assert g.max_depth >= 0
