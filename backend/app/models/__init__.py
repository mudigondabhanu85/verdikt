"""Import every model so app.db.base.Base.metadata is fully populated —
required for create_all() in tests and for Alembic autogenerate.
"""

from app.models.ai_provider_config import AIProviderConfig
from app.models.audit import AuditLogEntry
from app.models.business_rule import BusinessRule
from app.models.credential import CredentialSet
from app.models.finding import Evidence, Finding
from app.models.login_macro import LoginMacro
from app.models.organization import Organization, User
from app.models.project import AuthorizationRecord, Project, ScopeEntry, Version
from app.models.rbac import RolePermission
from app.models.review_candidate import ReviewCandidate
from app.models.scan import AgentJob, ScanRun
from app.models.target import Target
from app.models.traffic import TrafficInteraction

__all__ = [
    "AIProviderConfig",
    "AuditLogEntry",
    "BusinessRule",
    "CredentialSet",
    "Evidence",
    "Finding",
    "LoginMacro",
    "Organization",
    "User",
    "AuthorizationRecord",
    "Project",
    "ScopeEntry",
    "Version",
    "RolePermission",
    "ReviewCandidate",
    "AgentJob",
    "ScanRun",
    "Target",
    "TrafficInteraction",
]
