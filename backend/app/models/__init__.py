# Import all models here so Alembic autogenerate can discover them
# and SQLAlchemy can build the complete relationship graph.

from app.models.base import Base
from app.models.user import User
from app.models.tenant import Tenant
from app.models.tenant_member import TenantMember
from app.models.invitation import Invitation
from app.models.refresh_token import RefreshToken
from app.models.audit_log import AuditLog
from app.models.agent import Agent
from app.models.heartbeat import Heartbeat
from app.models.detection_rule import DetectionRule
from app.models.event import Event
from app.models.alert import Alert
from app.models.installer_token import InstallerToken
from app.models.investigation import Investigation
from app.models.api_key import ApiKey
from app.models.analyst import (
    InvestigationNote,
    InvestigationAssignment,
    InvestigationActivity,
    InvestigationEvidence,
    InvestigationVerdict,
    SavedHunt,
)
from app.models.chat import ChatMessage
from app.models.rag_chunk import RAGChunk
from app.models.notification_channel import NotificationChannel
from app.models.suppression_rule import SuppressionRule
from app.models.playbook import (
    PlaybookTemplate,
    PlaybookTemplateStep,
    Playbook,
    PlaybookStep,
    PlaybookRun,
)
from app.models.response_action import ResponseAction
from app.models.playbook import PlaybookAutoConfig
from app.models.generated_report import GeneratedReport

__all__ = [
    "Base",
    "User",
    "Tenant",
    "TenantMember",
    "Invitation",
    "RefreshToken",
    "AuditLog",
    "Agent",
    "Heartbeat",
    "DetectionRule",
    "Event",
    "Alert",
    "InstallerToken",
    "Investigation",
    "ApiKey",
    "InvestigationNote",
    "InvestigationAssignment",
    "InvestigationActivity",
    "InvestigationEvidence",
    "InvestigationVerdict",
    "SavedHunt",
    "ChatMessage",
    "RAGChunk",
    "NotificationChannel",
    "SuppressionRule",
    "PlaybookTemplate",
    "PlaybookTemplateStep",
    "Playbook",
    "PlaybookStep",
    "PlaybookRun",
    "ResponseAction",
    "PlaybookAutoConfig",
    "GeneratedReport",
]
