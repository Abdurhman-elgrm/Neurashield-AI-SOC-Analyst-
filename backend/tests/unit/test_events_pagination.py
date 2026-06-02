"""Unit tests for cursor-based pagination utilities."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from app.events.pagination import (
    CursorError,
    decode_cursor,
    decode_simple_cursor,
    encode_cursor,
    encode_simple_cursor,
)


TS = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
EID = UUID("12345678-1234-1234-1234-123456789abc")


class TestEncodeDecode:
    def test_encode_decode_roundtrip(self):
        cursor = encode_cursor(TS, EID, "event_timestamp", "desc")
        ts, eid, sf, sd = decode_cursor(cursor)
        assert ts == TS
        assert eid == EID
        assert sf == "event_timestamp"
        assert sd == "desc"

    def test_different_sort_fields(self):
        for sf in ["event_timestamp", "ingested_at", "severity", "host_name"]:
            for sd in ["asc", "desc"]:
                cursor = encode_cursor(TS, EID, sf, sd)
                _, _, decoded_sf, decoded_sd = decode_cursor(cursor)
                assert decoded_sf == sf
                assert decoded_sd == sd

    def test_cursor_is_url_safe(self):
        cursor = encode_cursor(TS, EID, "event_timestamp", "desc")
        assert "+" not in cursor
        assert "/" not in cursor
        assert "=" not in cursor or cursor.replace("=", "") == cursor.rstrip("=")

    def test_cursor_is_opaque_string(self):
        cursor = encode_cursor(TS, EID, "event_timestamp", "desc")
        assert isinstance(cursor, str)
        assert len(cursor) > 20

    def test_bad_cursor_raises_cursor_error(self):
        with pytest.raises(CursorError):
            decode_cursor("not-a-valid-cursor")

    def test_partial_cursor_raises_cursor_error(self):
        with pytest.raises(CursorError):
            decode_cursor("dGltZXN0YW1w")  # valid b64 but wrong format

    def test_empty_cursor_raises_cursor_error(self):
        with pytest.raises(CursorError):
            decode_cursor("")


class TestSimpleCursor:
    def test_simple_encode_decode_roundtrip(self):
        cursor = encode_simple_cursor(TS, EID)
        ts, eid = decode_simple_cursor(cursor)
        assert ts == TS
        assert eid == EID

    def test_simple_cursor_with_microseconds(self):
        ts_with_us = datetime(2024, 6, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)
        cursor = encode_simple_cursor(ts_with_us, EID)
        ts, eid = decode_simple_cursor(cursor)
        assert ts == ts_with_us
        assert eid == EID

    def test_simple_cursor_uniqueness(self):
        eid2 = uuid4()
        c1 = encode_simple_cursor(TS, EID)
        c2 = encode_simple_cursor(TS, eid2)
        assert c1 != c2

    def test_simple_cursor_bad_input_raises(self):
        with pytest.raises(CursorError):
            decode_simple_cursor("garbage-cursor-value")


class TestCursorOrdering:
    def test_later_timestamp_produces_different_cursor(self):
        ts2 = datetime(2024, 6, 2, 12, 0, 0, tzinfo=timezone.utc)
        c1 = encode_cursor(TS, EID, "event_timestamp", "desc")
        c2 = encode_cursor(ts2, EID, "event_timestamp", "desc")
        assert c1 != c2

    def test_different_event_ids_produce_different_cursors(self):
        eid2 = uuid4()
        c1 = encode_cursor(TS, EID, "event_timestamp", "desc")
        c2 = encode_cursor(TS, eid2, "event_timestamp", "desc")
        assert c1 != c2
