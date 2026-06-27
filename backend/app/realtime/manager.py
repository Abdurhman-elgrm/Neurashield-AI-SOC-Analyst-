from __future__ import annotations

import asyncio
from collections import defaultdict

import structlog
from fastapi import WebSocket

logger = structlog.get_logger(__name__)


class ConnectionManager:
    """
    In-process WebSocket connection registry for one backend instance.
    Tenant-scoped: connections are grouped by tenant_id.

    For multi-instance fanout, use the Broadcaster which pub/subs via Redis.
    This manager handles the local delivery leg only.
    """

    def __init__(self) -> None:
        # tenant_id (str) → set of WebSocket connections
        self._connections: dict[str, set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, tenant_id: str) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections[tenant_id].add(websocket)
        logger.info(
            "ws_client_connected",
            tenant_id=tenant_id,
            active=len(self._connections[tenant_id]),
        )

    async def disconnect(self, websocket: WebSocket, tenant_id: str) -> None:
        async with self._lock:
            self._connections[tenant_id].discard(websocket)
            if not self._connections[tenant_id]:
                del self._connections[tenant_id]
        logger.info("ws_client_disconnected", tenant_id=tenant_id)

    async def broadcast_to_tenant(self, tenant_id: str, message: str) -> None:
        """Sends `message` to all local connections for `tenant_id`."""
        async with self._lock:
            sockets = set(self._connections.get(tenant_id, set()))

        if not sockets:
            return

        dead: list[WebSocket] = []
        for ws in sockets:
            try:
                await ws.send_text(message)
            except Exception as exc:
                logger.debug("ws_send_failed", tenant_id=tenant_id, error=str(exc))
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections[tenant_id].discard(ws)

    def connection_count(self, tenant_id: str) -> int:
        return len(self._connections.get(tenant_id, set()))

    def total_connections(self) -> int:
        return sum(len(v) for v in self._connections.values())


# ─── Singleton ────────────────────────────────────────────────────────────────
connection_manager = ConnectionManager()
