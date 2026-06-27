"""
Shared async utilities — safe fire-and-forget task wrapper.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def create_task_safe(
    coro: Coroutine[Any, Any, Any],
    *,
    name: str | None = None,
) -> asyncio.Task:
    """
    Schedule `coro` as a background asyncio task with an automatic exception-
    logging callback.  Replaces bare `asyncio.create_task()` at fire-and-forget
    call sites so unhandled exceptions are surfaced in structured logs rather
    than silently dropped.

    Usage:
        create_task_safe(some_async_fn(arg), name="describe_the_work")
    """
    task = asyncio.create_task(coro, name=name)
    task.add_done_callback(_log_if_exception)
    return task


def _log_if_exception(task: asyncio.Task) -> None:
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error(
            "background_task_unhandled_exception",
            task_name=task.get_name(),
            exc_info=exc,
        )
