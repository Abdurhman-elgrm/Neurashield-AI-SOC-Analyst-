from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from typing import Generic, TypeVar

T = TypeVar("T")


class BatchAccumulator(Generic[T]):
    """
    Collects items until either `max_size` is reached or `flush_interval_secs`
    elapses, then yields the accumulated batch.

    Usage:
        acc = BatchAccumulator(max_size=100, flush_interval_secs=1.0)
        async for batch in acc.batches():
            await process(batch)
    """

    def __init__(self, max_size: int, flush_interval_secs: float = 1.0) -> None:
        self._max_size = max_size
        self._flush_interval = flush_interval_secs
        self._queue: asyncio.Queue[T | None] = asyncio.Queue()

    async def put(self, item: T) -> None:
        await self._queue.put(item)

    async def close(self) -> None:
        await self._queue.put(None)

    async def batches(self) -> AsyncGenerator[list[T], None]:
        batch: list[T] = []
        deadline = asyncio.get_event_loop().time() + self._flush_interval

        while True:
            now = asyncio.get_event_loop().time()
            remaining = max(0.0, deadline - now)

            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=remaining)
            except TimeoutError:
                if batch:
                    yield batch
                    batch = []
                deadline = asyncio.get_event_loop().time() + self._flush_interval
                continue

            if item is None:
                if batch:
                    yield batch
                return

            batch.append(item)
            if len(batch) >= self._max_size:
                yield batch
                batch = []
                deadline = asyncio.get_event_loop().time() + self._flush_interval
