import uuid

from sqlalchemy import Boolean, ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# Slack's incoming-webhook API is the only provider wired up for this
# first pass — the schema stays provider-tagged (like AIProviderConfig)
# so a second provider (e.g. Microsoft Teams' near-identical webhook
# shape) is a client + a string, not a new table.
NOTIFICATION_PROVIDER_TYPES = ("slack",)


class NotificationConfig(Base):
    """A named, org-scoped notification target (§8 reporting/ops gap).
    The webhook URL is envelope-encrypted the same way CredentialSet's
    secret and AIProviderConfig's api_key are — a Slack incoming-webhook
    URL is itself a bearer secret (anyone with it can post as your bot),
    not a public identifier.
    """

    __tablename__ = "notification_configs"

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    label: Mapped[str] = mapped_column(String(100))
    provider: Mapped[str] = mapped_column(String(20))
    encrypted_webhook_url: Mapped[bytes] = mapped_column(LargeBinary)
    masked_reference: Mapped[str] = mapped_column(String(255))
    notify_on_scan_completed: Mapped[bool] = mapped_column(Boolean, default=True)
