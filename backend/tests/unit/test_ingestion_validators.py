"""Unit tests for ingestion batch validators."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.exceptions import ValidationError
from app.ingestion.schemas import RawEventPayload
from app.ingestion.validators import validate_batch


def _make_event(event_id: str = "evt-001") -> RawEventPayload:
    return RawEventPayload(
        event_id=event_id,
        timestamp=datetime.now(tz=UTC),
        category="process",
        hostname="HOST1",
        os_type="windows",
    )


class TestValidateBatch:
    def test_valid_batch_passes(self):
        events = [_make_event(f"evt-{i}") for i in range(5)]
        validate_batch(events)  # should not raise

    def test_empty_batch_raises(self):
        with pytest.raises(ValidationError):
            validate_batch([])

    def test_duplicate_event_ids_raise(self):
        events = [_make_event("evt-001"), _make_event("evt-001")]
        with pytest.raises(ValidationError, match="duplicate"):
            validate_batch(events)

    def test_batch_exceeding_max_size_raises(self):
        from app.ingestion.validators import MAX_EVENTS_PER_BATCH

        events = [_make_event(f"evt-{i}") for i in range(MAX_EVENTS_PER_BATCH + 1)]
        with pytest.raises(ValidationError):
            validate_batch(events)


class TestCategoryValidation:
    def test_valid_categories_accepted(self):
        for cat in ("process", "network", "file", "auth", "registry", "dns", "other"):
            ev = RawEventPayload(
                event_id="id1",
                timestamp=datetime.now(tz=UTC),
                category=cat,
                hostname="H",
                os_type="linux",
            )
            assert ev.category == cat

    def test_unknown_category_defaults_to_other(self):
        ev = RawEventPayload(
            event_id="id1",
            timestamp=datetime.now(tz=UTC),
            category="weird_cat",
            hostname="H",
            os_type="linux",
        )
        assert ev.category == "other"
