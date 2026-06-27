from __future__ import annotations

from app.core.exceptions import ValidationError
from app.ingestion.schemas import RawEventPayload

MAX_EVENTS_PER_BATCH = 500
MAX_FIELD_DEPTH = 5


def validate_batch(events: list[RawEventPayload]) -> None:
    """
    Cross-event batch-level validation.
    Individual field validation is handled by the Pydantic schema.
    """
    if not events:
        raise ValidationError("Batch must contain at least one event")
    if len(events) > MAX_EVENTS_PER_BATCH:
        raise ValidationError(
            f"Batch exceeds maximum size of {MAX_EVENTS_PER_BATCH} events",
            details={"max": MAX_EVENTS_PER_BATCH, "received": len(events)},
        )

    # Check for duplicate event_ids within the batch itself
    seen: set[str] = set()
    for event in events:
        if event.event_id in seen:
            raise ValidationError(
                "Batch contains duplicate event_id",
                details={"duplicate_id": event.event_id},
            )
        seen.add(event.event_id)


def _check_dict_depth(obj: object, current_depth: int = 0) -> None:
    if not isinstance(obj, dict):
        return
    if current_depth > MAX_FIELD_DEPTH:
        raise ValidationError(
            "Nested object depth exceeds maximum",
            details={"max_depth": MAX_FIELD_DEPTH},
        )
    for v in obj.values():
        _check_dict_depth(v, current_depth + 1)
