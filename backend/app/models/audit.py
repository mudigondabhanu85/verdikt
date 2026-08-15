import uuid

from sqlalchemy import JSON, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditLogEntry(Base):
    """Immutable audit trail (§1.3). Phase 0 covers the CRUD-level slice:
    credential create/update, scope/authorization changes, traffic import.
    Per-HTTP-request and per-LLM-call audit logging is added alongside the
    agents that make those calls (Phase 2+).
    """

    __tablename__ = "audit_log_entries"

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(100))
    resource_type: Mapped[str] = mapped_column(String(64))
    resource_id: Mapped[str] = mapped_column(String(64))
    entry_metadata: Mapped[dict | None] = mapped_column(JSON)
