import uuid

from sqlalchemy import ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# Jira Cloud's REST API v3 is the only provider wired up for this first
# pass — provider-tagged like AIProviderConfig/NotificationConfig so a
# second ticketing system is a client + a string, not a new table.
TICKETING_PROVIDER_TYPES = ("jira",)


class TicketingConfig(Base):
    """A named, org-scoped ticketing system connection (§8 reporting/ops
    gap) — lets an analyst create a real ticket from a Finding instead
    of manually copy-pasting it into Jira. api_token is envelope-
    encrypted, same discipline as every other stored secret in this
    codebase (never persisted or returned as plaintext).
    """

    __tablename__ = "ticketing_configs"

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    label: Mapped[str] = mapped_column(String(100))
    provider: Mapped[str] = mapped_column(String(20))
    base_url: Mapped[str] = mapped_column(String(500))
    email: Mapped[str] = mapped_column(String(255))
    encrypted_api_token: Mapped[bytes] = mapped_column(LargeBinary)
    masked_reference: Mapped[str] = mapped_column(String(255))
    project_key: Mapped[str] = mapped_column(String(50))
    issue_type: Mapped[str] = mapped_column(String(50), default="Task")
