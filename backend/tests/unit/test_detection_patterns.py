"""Unit tests for pattern-based detection rule evaluation."""

from __future__ import annotations

from datetime import UTC, datetime

from app.detection.patterns import evaluate_condition, evaluate_conditions
from app.normalization.models import NormalizedEvent, NormalizedProcess


def _make_event(**kwargs) -> NormalizedEvent:
    defaults = {
        "event_id": "test",
        "timestamp": datetime.now(tz=UTC),
        "category": "process",
        "severity": 1,
        "hostname": "WIN-TEST",
        "os_type": "windows",
        "agent_id": "agent1",
        "tenant_id": "tenant1",
    }
    defaults.update(kwargs)
    return NormalizedEvent(**defaults)


class TestFieldAccess:
    def test_top_level_field(self):
        event = _make_event(hostname="HOST1")
        from app.detection.patterns import _get_field

        assert _get_field(event, "hostname") == "HOST1"

    def test_sub_object_field(self):
        proc = NormalizedProcess(name="cmd.exe", pid=1234)
        event = _make_event(process=proc)
        from app.detection.patterns import _get_field

        assert _get_field(event, "process.name") == "cmd.exe"
        assert _get_field(event, "process.pid") == 1234

    def test_missing_sub_object_returns_none(self):
        event = _make_event(process=None)
        from app.detection.patterns import _get_field

        assert _get_field(event, "process.name") is None

    def test_missing_field_returns_none(self):
        event = _make_event()
        from app.detection.patterns import _get_field

        assert _get_field(event, "nonexistent") is None


class TestOperators:
    def test_eq_match(self):
        proc = NormalizedProcess(name="cmd.exe")
        event = _make_event(process=proc)
        assert evaluate_condition({"field": "process.name", "op": "eq", "value": "cmd.exe"}, event)

    def test_eq_case_insensitive(self):
        proc = NormalizedProcess(name="CMD.EXE")
        event = _make_event(process=proc)
        assert evaluate_condition({"field": "process.name", "op": "eq", "value": "cmd.exe"}, event)

    def test_ne_match(self):
        proc = NormalizedProcess(name="notepad.exe")
        event = _make_event(process=proc)
        assert evaluate_condition({"field": "process.name", "op": "ne", "value": "cmd.exe"}, event)

    def test_contains(self):
        proc = NormalizedProcess(command_line="powershell -EncodedCommand abc")
        event = _make_event(process=proc)
        assert evaluate_condition(
            {"field": "process.command_line", "op": "contains", "value": "EncodedCommand"}, event
        )

    def test_regex_match(self):
        proc = NormalizedProcess(name="svchost.exe")
        event = _make_event(process=proc)
        assert evaluate_condition(
            {"field": "process.name", "op": "regex", "value": r"svc.*\.exe"}, event
        )

    def test_in_operator(self):
        proc = NormalizedProcess(name="cmd.exe")
        event = _make_event(process=proc)
        assert evaluate_condition(
            {"field": "process.name", "op": "in", "value": ["cmd.exe", "powershell.exe"]}, event
        )

    def test_not_in_operator(self):
        proc = NormalizedProcess(name="notepad.exe")
        event = _make_event(process=proc)
        assert evaluate_condition(
            {"field": "process.name", "op": "not_in", "value": ["cmd.exe", "powershell.exe"]}, event
        )

    def test_exists_true(self):
        proc = NormalizedProcess(name="cmd.exe")
        event = _make_event(process=proc)
        assert evaluate_condition({"field": "process.name", "op": "exists"}, event)

    def test_exists_false_on_none(self):
        event = _make_event(process=None)
        assert not evaluate_condition({"field": "process.name", "op": "exists"}, event)

    def test_gt_operator(self):
        event = _make_event(severity=3)
        assert evaluate_condition({"field": "severity", "op": "gt", "value": 2}, event)

    def test_lte_operator(self):
        event = _make_event(severity=2)
        assert evaluate_condition({"field": "severity", "op": "lte", "value": 3}, event)

    def test_none_field_returns_false(self):
        event = _make_event(process=None)
        assert not evaluate_condition(
            {"field": "process.name", "op": "eq", "value": "cmd.exe"}, event
        )


class TestMultiCondition:
    def test_all_conditions_must_match(self):
        proc = NormalizedProcess(name="powershell.exe", command_line="-EncodedCommand abc")
        event = _make_event(process=proc)
        conditions = [
            {"field": "process.name", "op": "eq", "value": "powershell.exe"},
            {"field": "process.command_line", "op": "contains", "value": "EncodedCommand"},
        ]
        assert evaluate_conditions(conditions, event)

    def test_any_false_fails_all(self):
        proc = NormalizedProcess(name="powershell.exe", command_line="normal.ps1")
        event = _make_event(process=proc)
        conditions = [
            {"field": "process.name", "op": "eq", "value": "powershell.exe"},
            {"field": "process.command_line", "op": "contains", "value": "EncodedCommand"},
        ]
        assert not evaluate_conditions(conditions, event)

    def test_empty_conditions_matches_all(self):
        event = _make_event()
        assert evaluate_conditions([], event)
