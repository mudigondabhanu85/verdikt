"""Import every model so app.db.base.Base.metadata is fully populated —
required for create_all() in tests and for Alembic autogenerate.
"""

from app.models.ai_provider_config import AIProviderConfig
from app.models.api_key import ApiKey
from app.models.attack_chain import AttackChain, AttackChainEvidence
from app.models.audit import AuditLogEntry
from app.models.autonomous_pentest import PentestCommand
from app.models.business_rule import BusinessRule
from app.models.chatbot_agency_probe import ChatbotAgencyProbe
from app.models.chatbot_target import ChatbotTarget
from app.models.cmdb_config import CMDBConfig
from app.models.credential import CredentialSet
from app.models.finding import Evidence, Finding
from app.models.finding_ticket import FindingTicket
from app.models.login_macro import LoginMacro
from app.models.notification_config import NotificationConfig
from app.models.oidc_provider_config import OidcProviderConfig
from app.models.organization import Organization, User
from app.models.project import Project, ScopeEntry, Version
from app.models.project_membership import ProjectMembership
from app.models.rbac import RolePermission
from app.models.retest_job import RetestJob
from app.models.review_candidate import ReviewCandidate
from app.models.scan import AgentJob, ScanRun
from app.models.target import Target
from app.models.ticketing_config import TicketingConfig
from app.models.traffic import TrafficInteraction
from app.models.vgs_config import VGSConfig
from app.models.vgs_vulnerability import (
    VgsEvidenceStep,
    VgsReportDraft,
    VgsReportVulnerability,
    VgsVulnerabilityLibraryEntry,
)

__all__ = [
    "AIProviderConfig",
    "ApiKey",
    "AttackChain",
    "AttackChainEvidence",
    "AuditLogEntry",
    "PentestCommand",
    "BusinessRule",
    "ChatbotAgencyProbe",
    "ChatbotTarget",
    "CMDBConfig",
    "CredentialSet",
    "Evidence",
    "Finding",
    "FindingTicket",
    "LoginMacro",
    "NotificationConfig",
    "OidcProviderConfig",
    "Organization",
    "User",
    "Project",
    "ScopeEntry",
    "Version",
    "ProjectMembership",
    "RolePermission",
    "RetestJob",
    "ReviewCandidate",
    "AgentJob",
    "ScanRun",
    "Target",
    "TicketingConfig",
    "TrafficInteraction",
    "VGSConfig",
    "VgsEvidenceStep",
    "VgsReportDraft",
    "VgsReportVulnerability",
    "VgsVulnerabilityLibraryEntry",
]
