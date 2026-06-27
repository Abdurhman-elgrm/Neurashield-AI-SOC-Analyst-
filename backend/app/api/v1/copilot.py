from __future__ import annotations

from typing import Annotated
from uuid import UUID

import structlog
from fastapi import APIRouter
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select

from app.core.dependencies import DBSession, require_permission
from app.rbac.permissions import Permission
from app.schemas.common import APIResponse

router = APIRouter(prefix="/copilot", tags=["copilot"])
log = structlog.get_logger(__name__)

_CONTEXT_WINDOW = 10


# ─── Request / Response schemas ──────────────────────────────────────────────


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    mode: str = Field(default="deep_dive")
    investigation_id: str | None = None


class ChatResponse(BaseModel):
    response: str
    mode: str
    context_summary: dict


class ChatMessageResponse(BaseModel):
    id: str
    role: str
    content: str
    created_at: str
    investigation_id: str | None


# ─── POST /copilot/chat ───────────────────────────────────────────────────────


@router.post("/chat", response_model=APIResponse[ChatResponse])
async def chat(
    payload: ChatRequest,
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: DBSession,
) -> APIResponse[ChatResponse]:
    from app.ai.chat import CHAT_MODES, build_soc_context, build_system_prompt
    from app.ai.llm_manager import get_llm_manager
    from app.models.chat import ChatMessage
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    # Normalise mode
    mode = payload.mode if payload.mode in CHAT_MODES else "deep_dive"

    # Parse investigation_id and verify it belongs to the calling tenant.
    inv_uuid: UUID | None = None
    if payload.investigation_id:
        try:
            parsed = UUID(payload.investigation_id)
            # Verify ownership before passing to build_soc_context.
            from app.models.investigation import Investigation

            owned = await db.scalar(
                select(Investigation.id).where(
                    Investigation.id == parsed,
                    Investigation.tenant_id == m.tenant_id,
                    Investigation.deleted_at.is_(None),
                )
            )
            if owned is not None:
                inv_uuid = parsed
            else:
                log.warning(
                    "copilot_investigation_id_tenant_mismatch",
                    investigation_id=str(parsed),
                    tenant_id=str(m.tenant_id),
                )
        except ValueError:
            inv_uuid = None

    # Build SOC context
    soc_context = await build_soc_context(db, m.tenant_id, inv_uuid)

    # Fetch last N messages for conversation continuity
    history_result = await db.execute(
        select(ChatMessage)
        .where(
            ChatMessage.tenant_id == m.tenant_id,
            ChatMessage.user_id == m.user_id,
        )
        .order_by(ChatMessage.created_at.desc())
        .limit(_CONTEXT_WINDOW)
    )
    history = list(reversed(history_result.scalars().all()))

    history_text = ""
    if history:
        lines = []
        for msg in history:
            label = "Analyst" if msg.role == "user" else "NEURASHIELD"
            lines.append(f"{label}: {msg.content[:300]}")
        history_text = "\n".join(lines)

    system_prompt = build_system_prompt(mode, soc_context, history_text)

    # Sanitize user message before sending to LLM
    from app.ai.prompt_guard import sanitize_user_message

    safe_message = sanitize_user_message(payload.message)

    # Call LLM
    try:
        manager = get_llm_manager()
        response_text = await manager.generate(
            prompt=safe_message,
            system_prompt=system_prompt,
            max_tokens=2048,
        )
    except Exception as exc:
        log.warning("copilot_llm_failed", error=str(exc))
        response_text = (
            "I'm unable to process your request right now — the AI service is temporarily unavailable. "
            "Please check your GROQ_API_KEY / GEMINI_API_KEY configuration and try again."
        )

    # Persist both messages (store sanitized version)
    user_msg = ChatMessage(
        tenant_id=m.tenant_id,
        user_id=m.user_id,
        investigation_id=inv_uuid,
        role="user",
        content=safe_message,
    )
    asst_msg = ChatMessage(
        tenant_id=m.tenant_id,
        user_id=m.user_id,
        investigation_id=inv_uuid,
        role="assistant",
        content=response_text,
    )
    db.add(user_msg)
    db.add(asst_msg)
    await db.commit()

    log.info(
        "copilot_chat",
        mode=mode,
        tenant_id=str(m.tenant_id),
        inv_id=str(inv_uuid) if inv_uuid else None,
    )

    context_summary = {
        "alert_count": len(soc_context.get("alerts", [])),
        "investigation_count": len(soc_context.get("investigations", [])),
        "has_current_investigation": "current_investigation" in soc_context,
    }
    return APIResponse.ok(
        ChatResponse(response=response_text, mode=mode, context_summary=context_summary)
    )


# ─── GET /copilot/history ─────────────────────────────────────────────────────


@router.get("/history", response_model=APIResponse[list[ChatMessageResponse]])
async def get_history(
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: DBSession,
) -> APIResponse[list[ChatMessageResponse]]:
    from app.models.chat import ChatMessage
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    result = await db.execute(
        select(ChatMessage)
        .where(
            ChatMessage.tenant_id == m.tenant_id,
            ChatMessage.user_id == m.user_id,
        )
        .order_by(ChatMessage.created_at.asc())
        .limit(50)
    )
    messages = result.scalars().all()

    return APIResponse.ok(
        [
            ChatMessageResponse(
                id=str(msg.id),
                role=msg.role,
                content=msg.content,
                created_at=msg.created_at.isoformat(),
                investigation_id=str(msg.investigation_id) if msg.investigation_id else None,
            )
            for msg in messages
        ]
    )


# ─── DELETE /copilot/history ──────────────────────────────────────────────────


@router.delete("/history", response_model=APIResponse[dict])
async def clear_history(
    member: Annotated[object, require_permission(Permission.INVESTIGATIONS_READ)],
    db: DBSession,
) -> APIResponse[dict]:
    from app.models.chat import ChatMessage
    from app.models.tenant_member import TenantMember

    m: TenantMember = member  # type: ignore[assignment]

    count_result = await db.execute(
        select(func.count())
        .select_from(ChatMessage)
        .where(
            ChatMessage.tenant_id == m.tenant_id,
            ChatMessage.user_id == m.user_id,
        )
    )
    count = count_result.scalar() or 0

    await db.execute(
        delete(ChatMessage).where(
            ChatMessage.tenant_id == m.tenant_id,
            ChatMessage.user_id == m.user_id,
        )
    )
    await db.commit()

    return APIResponse.ok({"deleted": count})
