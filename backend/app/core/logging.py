from __future__ import annotations

import logging
import sys
from contextvars import ContextVar
from typing import Any

import structlog
from structlog.types import EventDict, Processor

# ─── Context variables propagated through async call chains ───────────────────
request_id_ctx: ContextVar[str] = ContextVar("request_id", default="")
tenant_id_ctx: ContextVar[str] = ContextVar("tenant_id", default="")
user_id_ctx: ContextVar[str] = ContextVar("user_id", default="")


def get_request_id() -> str:
    return request_id_ctx.get()


def get_tenant_id() -> str:
    return tenant_id_ctx.get()


def get_user_id() -> str:
    return user_id_ctx.get()


# ─── Custom processors ────────────────────────────────────────────────────────

def add_app_context(logger: Any, method: str, event_dict: EventDict) -> EventDict:
    """Inject request/tenant/user context from ContextVars into every log event."""
    if rid := request_id_ctx.get():
        event_dict["request_id"] = rid
    if tid := tenant_id_ctx.get():
        event_dict["tenant_id"] = tid
    if uid := user_id_ctx.get():
        event_dict["user_id"] = uid
    return event_dict


def drop_color_message_key(logger: Any, method: str, event_dict: EventDict) -> EventDict:
    """Remove the extra 'color_message' key that uvicorn injects."""
    event_dict.pop("color_message", None)
    return event_dict


# ─── Configuration ────────────────────────────────────────────────────────────

def configure_logging(log_level: str = "INFO", environment: str = "development") -> None:
    """
    Configure structlog for structured JSON output (production) or
    pretty console output (development). Called once at application startup.
    """
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        add_app_context,
        drop_color_message_key,
    ]

    if environment == "production":
        renderer: Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Quiet noisy libraries
    for noisy in ("asyncio", "uvicorn.access", "sqlalchemy.engine"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    # Uvicorn uses its own logging; wire it through structlog
    for uvicorn_logger in ("uvicorn", "uvicorn.error"):
        logging.getLogger(uvicorn_logger).handlers = [handler]
