from fastapi import APIRouter

from app.api.v1 import auth, health, members, tenants, users
from app.api.v1 import agents, alerts, events, rules, installer
from app.api.v1 import investigations, entities
from app.api.v1 import api_keys, reports, dashboard
from app.api.v1 import notification_channels, suppressions
from app.api.v1 import playbooks
from app.api.v1 import sigma
from app.api.v1 import imports
from app.api.v1 import fleet, ueba, iocs
from app.api.v1 import integrations
from app.api.v1 import metrics
from app.api.v1.copilot import router as copilot_router
from app.api.v1.invitations import router as invitations_router
from app.api.v1.mssp_api import router as mssp_router
from app.api.v1.threat_intel_api import router as threat_intel_router
from app.ingestion.router import router as ingestion_router
from app.connectors.router import router as connectors_router
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

# ─── Phase 3: External Connectors (API-key auth) ──────────────────────────────
api_router.include_router(connectors_router)

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

# ─── Compliance Reports ───────────────────────────────────────────────────────
api_router.include_router(reports.router)

# ─── Dashboard (KPI + time-series + MITRE heatmap) ───────────────────────────
api_router.include_router(dashboard.router)

# ─── AI Copilot ───────────────────────────────────────────────────────────────
api_router.include_router(copilot_router)

# ─── Invitations (public accept + authenticated management) ───────────────────
api_router.include_router(invitations_router)

# ─── Notification preferences ─────────────────────────────────────────────────
from app.api.v1.notifications import router as notifications_router
api_router.include_router(notifications_router)

# ─── Outbound notification channels (Slack/Teams/webhook/PagerDuty/email) ────
api_router.include_router(notification_channels.router)

# ─── Alert suppression rules ─────────────────────────────────────────────────
api_router.include_router(suppressions.router)

# ─── SOAR: Playbook Generator ─────────────────────────────────────────────────
api_router.include_router(playbooks.router)

# ─── Sigma Rule Engine ────────────────────────────────────────────────────────
api_router.include_router(sigma.router)

# ─── Log Import ───────────────────────────────────────────────────────────────
api_router.include_router(imports.router)

# ─── Fleet, UEBA, MSSP, Threat Intel, IOC Enrichment ─────────────────────────
api_router.include_router(fleet.router)
api_router.include_router(ueba.router)
api_router.include_router(mssp_router)
api_router.include_router(threat_intel_router)
api_router.include_router(iocs.router)
api_router.include_router(integrations.router)
api_router.include_router(metrics.router)

# ─── Phase 2: WebSocket (registered at root level, no prefix) ────────────────
api_router.include_router(ws_router)
