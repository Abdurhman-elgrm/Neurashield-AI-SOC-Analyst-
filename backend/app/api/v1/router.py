from fastapi import APIRouter

from app.api.v1 import auth, health, members, tenants, users
from app.api.v1 import agents, alerts, events, rules, installer
from app.api.v1 import investigations, entities
from app.api.v1 import api_keys
from app.ingestion.router import router as ingestion_router
from app.realtime.router import router as ws_router

api_router = APIRouter()

# ─── Health (no auth) ─────────────────────────────────────────────────────────
api_router.include_router(health.router)

# ─── Authentication (no auth required) ───────────────────────────────────────
api_router.include_router(auth.router)

# ─── Authenticated resources ──────────────────────────────────────────────────
api_router.include_router(users.router)
api_router.include_router(tenants.router)
api_router.include_router(members.router)

# ─── Phase 2: Ingestion (agent self-auth) ─────────────────────────────────────
api_router.include_router(ingestion_router)

# ─── Phase 2: Agent management (tenant member auth) ───────────────────────────
api_router.include_router(agents.router)

# ─── Phase 2: Events, Alerts, Detection Rules ────────────────────────────────
api_router.include_router(events.router)
api_router.include_router(alerts.router)
api_router.include_router(rules.router)

# ─── Installer token hub ─────────────────────────────────────────────────────
api_router.include_router(installer.router)

# ─── Phase 3: Analyst workspace ──────────────────────────────────────────────
api_router.include_router(investigations.router)

# ─── Phase 3.6: Events Explorer ──────────────────────────────────────────────
api_router.include_router(entities.router)

# ─── Settings: API Keys ───────────────────────────────────────────────────────
api_router.include_router(api_keys.router)

# ─── Phase 2: WebSocket (registered at root level, no prefix) ────────────────
api_router.include_router(ws_router)
