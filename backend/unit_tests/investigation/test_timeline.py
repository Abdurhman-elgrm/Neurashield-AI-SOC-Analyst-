from __future__ import annotations

import pytest

from app.investigation.timeline import build_timeline
from unit_tests.investigation.conftest import (
    INV_ID, TENANT_ID, _TS_BASE,
    make_snapshot, make_network_snapshot, make_process_snapshot,
)


class TestTimelineBasic:
    def test_empty_snapshots_returns_empty_timeline(self):
        tl = build_timeline(INV_ID, TENANT_ID, [])
        assert tl.total_events == 0
        assert tl.entries == []
        assert tl.first_seen == 0.0
        assert tl.last_seen == 0.0

    def test_single_event(self):
        snap = make_snapshot(event_id="e1", timestamp=_TS_BASE)
        tl = build_timeline(INV_ID, TENANT_ID, [snap])
        assert tl.total_events == 1
        assert len(tl.entries) == 1
        assert tl.entries[0].event_id == "e1"

    def test_investigation_id_and_tenant_propagated(self):
        tl = build_timeline("custom-inv", "custom-tenant", [make_snapshot()])
        assert tl.investigation_id == "custom-inv"
        assert tl.tenant_id == "custom-tenant"

    def test_entries_sorted_by_timestamp(self):
        snaps = [
            make_snapshot(event_id="e3", timestamp=_TS_BASE + 20),
            make_snapshot(event_id="e1", timestamp=_TS_BASE),
            make_snapshot(event_id="e2", timestamp=_TS_BASE + 10),
        ]
        tl = build_timeline(INV_ID, TENANT_ID, snaps)
        timestamps = [e.timestamp for e in tl.entries]
        assert timestamps == sorted(timestamps)

    def test_first_seen_is_minimum_timestamp(self):
        snaps = [
            make_snapshot(event_id="e1", timestamp=_TS_BASE + 100),
            make_snapshot(event_id="e2", timestamp=_TS_BASE),
        ]
        tl = build_timeline(INV_ID, TENANT_ID, snaps)
        assert tl.first_seen == _TS_BASE

    def test_last_seen_is_maximum_timestamp(self):
        snaps = [
            make_snapshot(event_id="e1", timestamp=_TS_BASE),
            make_snapshot(event_id="e2", timestamp=_TS_BASE + 500),
        ]
        tl = build_timeline(INV_ID, TENANT_ID, snaps)
        assert tl.last_seen == _TS_BASE + 500

    def test_duration_correct(self):
        snaps = [
            make_snapshot(event_id="e1", timestamp=_TS_BASE),
            make_snapshot(event_id="e2", timestamp=_TS_BASE + 300),
        ]
        tl = build_timeline(INV_ID, TENANT_ID, snaps)
        assert tl.duration_seconds == 300.0

    def test_duration_zero_for_single_event(self):
        tl = build_timeline(INV_ID, TENANT_ID, [make_snapshot()])
        assert tl.duration_seconds == 0.0


class TestTimelineStatistics:
    def test_distinct_hosts_counted(self):
        snaps = [
            make_snapshot(event_id="e1", hostname="HOST-A"),
            make_snapshot(event_id="e2", hostname="HOST-B"),
            make_snapshot(event_id="e3", hostname="HOST-A"),
        ]
        tl = build_timeline(INV_ID, TENANT_ID, snaps)
        assert tl.distinct_hosts == 2

    def test_distinct_ips_counted(self):
        snaps = [
            make_network_snapshot(event_id="n1", dst_ip="1.2.3.4"),
            make_network_snapshot(event_id="n2", dst_ip="5.6.7.8"),
            make_network_snapshot(event_id="n3", dst_ip="1.2.3.4"),
        ]
        tl = build_timeline(INV_ID, TENANT_ID, snaps)
        assert tl.distinct_ips == 3  # src + 2 distinct dst

    def test_distinct_processes_counted(self):
        snaps = [
            make_process_snapshot(event_id="p1", process_name="cmd.exe"),
            make_process_snapshot(event_id="p2", process_name="powershell.exe"),
            make_process_snapshot(event_id="p3", process_name="cmd.exe"),
        ]
        tl = build_timeline(INV_ID, TENANT_ID, snaps)
        assert tl.distinct_processes == 2

    def test_total_events_matches_snapshot_count(self):
        snaps = [make_snapshot(event_id=f"e{i}") for i in range(10)]
        tl = build_timeline(INV_ID, TENANT_ID, snaps)
        assert tl.total_events == 10


class TestTimelineGroups:
    def test_session_groups_populated(self):
        snaps = [
            make_snapshot(event_id="e1", session_id="s1"),
            make_snapshot(event_id="e2", session_id="s1"),
            make_snapshot(event_id="e3", session_id="s2"),
        ]
        tl = build_timeline(INV_ID, TENANT_ID, snaps)
        assert "s1" in tl.session_groups
        assert len(tl.session_groups["s1"]) == 2
        assert "s2" in tl.session_groups

    def test_process_tree_groups_populated(self):
        snaps = [
            make_snapshot(event_id="e1", process_tree_id="pt1"),
            make_snapshot(event_id="e2", process_tree_id="pt1"),
        ]
        tl = build_timeline(INV_ID, TENANT_ID, snaps)
        assert "pt1" in tl.process_tree_groups
        assert len(tl.process_tree_groups["pt1"]) == 2

    def test_correlation_groups_populated(self):
        snaps = [
            make_snapshot(event_id="e1", correlation_id="cid-x"),
            make_snapshot(event_id="e2", correlation_id="cid-x"),
        ]
        tl = build_timeline(INV_ID, TENANT_ID, snaps)
        assert "cid-x" in tl.correlation_groups


class TestTimelineEntryFields:
    def test_entry_has_hostname(self):
        snap = make_snapshot(hostname="MYHOST")
        tl = build_timeline(INV_ID, TENANT_ID, [snap])
        assert tl.entries[0].hostname == "MYHOST"

    def test_entry_has_severity(self):
        snap = make_snapshot(severity=7)
        tl = build_timeline(INV_ID, TENANT_ID, [snap])
        assert tl.entries[0].severity == 7

    def test_entry_has_category(self):
        snap = make_snapshot(category="network")
        tl = build_timeline(INV_ID, TENANT_ID, [snap])
        assert tl.entries[0].category == "network"

    def test_entry_outcome_high_severity(self):
        snap = make_snapshot(severity=9)
        tl = build_timeline(INV_ID, TENANT_ID, [snap])
        assert tl.entries[0].outcome == "critical"

    def test_entry_outcome_low_severity(self):
        snap = make_snapshot(severity=1)
        tl = build_timeline(INV_ID, TENANT_ID, [snap])
        assert tl.entries[0].outcome == "low"

    def test_entry_process_name_extracted(self):
        snap = make_process_snapshot(process_name="mimikatz.exe")
        tl = build_timeline(INV_ID, TENANT_ID, [snap])
        assert tl.entries[0].process is not None
        assert "mimikatz" in tl.entries[0].process.lower()

    def test_entry_matched_rules_propagated(self):
        snap = make_snapshot(matched_rules=["same_host_burst", "same_process_tree"])
        tl = build_timeline(INV_ID, TENANT_ID, [snap])
        assert "same_host_burst" in tl.entries[0].rule_match
