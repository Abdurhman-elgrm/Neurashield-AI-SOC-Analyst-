from __future__ import annotations

"""
WebSocket router — two endpoints:

  /ws            (Phase 2, legacy)  — kept for backward compatibility
  /ws/realtime   (Phase 3.5)        — full collaborative SOC workspace

/ws/realtime protocol
─────────────────────
Auth:  query params  ?token=<jwt>&tenant_id=<uuid>

Server → client messages  (RealtimeEvent JSON):
  { "v":2, "event_id":"...", "event_type":"...", "tenant_id":"...",
    "actor_id":"...", "channel":"...", "timestamp":"...", "payload":{...} }

Client → server messages  (ClientMessage JSON):
  { "type": "subscribe",         "channel": "alerts" }
  { "type": "unsubscribe",       "channel": "alerts" }
  { "type": "heartbeat" }
  { "type": "set_investigation", "investigation_id": "..." }
  { "type": "typing",            "investigation_id": "..." }
  { "type": "acquire_lock",      "investigation_id": "..." }
  { "type": "release_lock",      "investigation_id": "..." }
  { "type": "pong" }
"""


import asyncio
import json
from uuid import uuid4

import structlog
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.exceptions import ForbiddenError, UnauthorizedError
from app.core.redis import TenantRedisClient, redis_manager
from app.pipeline import stream_names
from app.realtime import channels as ch
from app.realtime.auth import authenticate_websocket
from app.realtime.broadcast import (
    RealtimeBroadcaster,
    deregister_connection_queue,
    get_connection_queue,
    register_connection_queue,
)
from app.realtime.events import error_msg, realtime_analyst_joined, realtime_analyst_left
from app.realtime.locks import InvestigationLockService
from app.realtime.manager import connection_manager
from app.realtime.presence import PresenceService
from app.realtime.schemas import (
    ClientMessage,
    RealtimeEvent,
    RealtimeEventType,
    WelcomePayload,
)
from app.realtime.subscriptions import subscription_manager
from app.realtime.sync import SyncEngine

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["websocket"])

_PING_INTERVAL_SECS  = 25   # server sends ping to client
_HEARTBEAT_TIMEOUT   = 60   # drop connection if no pong within this window
_REALTIME_SUBSYSTEM  = ch.REALTIME_SUBSYSTEM


# ─── Phase 2 legacy /ws endpoint ─────────────────────────────────────────────

@router.websocket("/ws")
async def websocket_legacy(
    websocket: WebSocket,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Legacy Phase 2 WebSocket — kept for backward compat."""
    token         = websocket.query_params.get("token")
    tenant_id_str = websocket.query_params.get("tenant_id")

    try:
        user, member = await authenticate_websocket(websocket, token, tenant_id_str, db)
    except UnauthorizedError as exc:
        await websocket.close(code=4001, reason=exc.message)
        return
    except ForbiddenError as exc:
        await websocket.close(code=4003, reason=exc.message)
        return
    except Exception:
        await websocket.close(code=4000, reason="Authentication failed")
        return

    tenant_id = str(member.tenant_id)
    await connection_manager.connect(websocket, tenant_id)
    logger.info("ws_legacy_connected", user_id=str(user.id), tenant_id=tenant_id)

    try:
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=_PING_INTERVAL_SECS)
            except asyncio.TimeoutError:
                await websocket.send_text(
                    '{"v":1,"type":"ping","tenant_id":"' + tenant_id + '","payload":{},"ts":""}'
                )
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("ws_legacy_unexpected_close", error=str(exc))
    finally:
        await connection_manager.disconnect(websocket, tenant_id)


# ─── Phase 3.5 /ws/realtime endpoint ─────────────────────────────────────────

@router.websocket("/ws/realtime")
async def websocket_realtime(
    websocket: WebSocket,
    db: AsyncSession = Depends(get_db),
) -> None:
    """
    Full collaborative SOC workspace WebSocket.
    Supports channel subscriptions, presence, typing indicators, and edit locks.
    """
    token         = websocket.query_params.get("token")
    tenant_id_str = websocket.query_params.get("tenant_id")

    try:
        user, member = await authenticate_websocket(websocket, token, tenant_id_str, db)
    except UnauthorizedError as exc:
        await websocket.close(code=4001, reason=exc.message)
        return
    except ForbiddenError as exc:
        await websocket.close(code=4003, reason=exc.message)
        return
    except Exception:
        await websocket.close(code=4000, reason="Authentication failed")
        return

    tenant_id  = str(member.tenant_id)
    analyst_id = str(user.id)
    ws_id      = str(uuid4())

    redis  = redis_manager.get_client()
    rt_client = TenantRedisClient(redis, tenant_id, _REALTIME_SUBSYSTEM)

    # ── Register connection ────────────────────────────────────────────────────
    await websocket.accept()
    send_queue = register_connection_queue(ws_id)
    await subscription_manager.subscribe(ws_id, tenant_id, ch.PRESENCE)

    state = await PresenceService.join(
        rt_client, analyst_id, tenant_id,
        display_name=getattr(user, "full_name", "") or getattr(user, "email", ""),
    )

    logger.info(
        "ws_realtime_connected",
        ws_id=ws_id,
        analyst_id=analyst_id,
        tenant_id=tenant_id,
    )

    # Send welcome message
    online_count = await PresenceService.count_online(rt_client)
    welcome = RealtimeEvent.create(
        event_type=RealtimeEventType.WELCOME,
        tenant_id=tenant_id,
        actor_id="system",
        channel=ch.PRESENCE,
        payload=WelcomePayload(
            analyst_id=analyst_id,
            tenant_id=tenant_id,
            available_channels=list(ch.ALL_CHANNELS),
            online_analysts=online_count,
        ).model_dump(),
    )
    await websocket.send_text(welcome.to_json())

    # Broadcast presence join to peers
    try:
        await SyncEngine.on_analyst_joined(
            rt_client, tenant_id, analyst_id,
            display_name=state.display_name,
            workspace=state.workspace,
        )
    except Exception:
        pass  # presence broadcast is best-effort

    # ── Task: drain send_queue → websocket ─────────────────────────────────────
    async def _sender() -> None:
        while True:
            try:
                msg = await asyncio.wait_for(send_queue.get(), timeout=_PING_INTERVAL_SECS)
                await websocket.send_text(msg)
                send_queue.task_done()
            except asyncio.TimeoutError:
                # Send a ping keepalive
                ping = RealtimeEvent.create(
                    event_type=RealtimeEventType.PING,
                    tenant_id=tenant_id,
                    actor_id="system",
                    channel=ch.PRESENCE,
                    payload={},
                )
                await websocket.send_text(ping.to_json())
            except (WebSocketDisconnect, asyncio.CancelledError):
                break
            except Exception as exc:
                logger.debug("ws_sender_error", ws_id=ws_id, error=str(exc))
                break

    sender_task = asyncio.create_task(_sender())

    # ── Main receive loop ──────────────────────────────────────────────────────
    try:
        while True:
            raw = await websocket.receive_text()
            await _handle_client_message(
                raw, ws_id, tenant_id, analyst_id, rt_client, websocket
            )
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("ws_realtime_unexpected_close", ws_id=ws_id, error=str(exc))
    finally:
        sender_task.cancel()
        await _cleanup_connection(ws_id, tenant_id, analyst_id, rt_client)


async def _handle_client_message(
    raw: str,
    ws_id: str,
    tenant_id: str,
    analyst_id: str,
    rt_client: TenantRedisClient,
    websocket: WebSocket,
) -> None:
    try:
        data = json.loads(raw)
        msg  = ClientMessage(**data)
    except Exception:
        return  # ignore malformed messages

    mtype = msg.type

    if mtype == "subscribe" and msg.channel:
        added = await subscription_manager.subscribe(ws_id, tenant_id, msg.channel)
        if added:
            ack = RealtimeEvent.create(
                event_type=RealtimeEventType.SUBSCRIBED,
                tenant_id=tenant_id,
                actor_id="system",
                channel=msg.channel,
                payload={"channel": msg.channel},
            )
            await websocket.send_text(ack.to_json())

    elif mtype == "unsubscribe" and msg.channel:
        await subscription_manager.unsubscribe(ws_id, msg.channel)
        ack = RealtimeEvent.create(
            event_type=RealtimeEventType.UNSUBSCRIBED,
            tenant_id=tenant_id,
            actor_id="system",
            channel=msg.channel,
            payload={"channel": msg.channel},
        )
        await websocket.send_text(ack.to_json())

    elif mtype == "heartbeat":
        await PresenceService.heartbeat(
            rt_client, analyst_id,
            workspace=msg.workspace,
            investigation_id=msg.investigation_id,
        )

    elif mtype == "set_investigation" and msg.investigation_id:
        await PresenceService.set_active_investigation(
            rt_client, analyst_id, msg.investigation_id
        )

    elif mtype == "typing" and msg.investigation_id:
        try:
            await SyncEngine.on_analyst_typing(
                rt_client, tenant_id, analyst_id, msg.investigation_id
            )
        except Exception:
            pass

    elif mtype == "acquire_lock" and msg.investigation_id:
        lock = await InvestigationLockService.acquire(
            rt_client, msg.investigation_id, tenant_id, analyst_id
        )
        payload = lock.model_dump() if lock else {"error": "lock_held"}
        resp = RealtimeEvent.create(
            event_type="lock.acquired" if lock else "lock.denied",
            tenant_id=tenant_id,
            actor_id=analyst_id,
            channel=ch.INVESTIGATIONS,
            payload=payload,
        )
        await websocket.send_text(resp.to_json())

    elif mtype == "release_lock" and msg.investigation_id:
        released = await InvestigationLockService.release(
            rt_client, msg.investigation_id, analyst_id
        )
        resp = RealtimeEvent.create(
            event_type="lock.released" if released else "lock.not_owned",
            tenant_id=tenant_id,
            actor_id=analyst_id,
            channel=ch.INVESTIGATIONS,
            payload={"investigation_id": msg.investigation_id, "released": released},
        )
        await websocket.send_text(resp.to_json())

    elif mtype == "pong":
        pass  # client keepalive response


async def _cleanup_connection(
    ws_id: str,
    tenant_id: str,
    analyst_id: str,
    rt_client: TenantRedisClient,
) -> None:
    """Clean up all state associated with a disconnected WebSocket."""
    deregister_connection_queue(ws_id)
    await subscription_manager.cleanup(ws_id)
    await PresenceService.leave(rt_client, analyst_id)

    try:
        await SyncEngine.on_analyst_left(rt_client, tenant_id, analyst_id)
    except Exception:
        pass

    logger.info("ws_realtime_disconnected", ws_id=ws_id, analyst_id=analyst_id)
