import uuid

from sqlalchemy import Boolean, ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# Slack and Teams both use a simple incoming-webhook POST — webhook_url
# alone is sufficient for those two. Outlook (SMTP) needs a handful of
# extra fields (host/port/username/password/from/to) that don't fit the
# single-webhook-URL shape, so those live in encrypted_config_json below
# instead of proliferating nullable columns per provider.
NOTIFICATION_PROVIDER_TYPES = ("slack", "teams", "outlook")


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
    # Slack/Teams: the webhook URL itself. Outlook: unused (empty-masked);
    # its connection details live in encrypted_config_json instead.
    encrypted_webhook_url: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    masked_reference: Mapped[str] = mapped_column(String(255))
    # Outlook only — a Fernet-encrypted JSON blob of
    # {smtp_host, smtp_port, smtp_username, smtp_password, from_address,
    # to_address}. Nullable/unused for Slack and Teams.
    encrypted_config_json: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    notify_on_scan_completed: Mapped[bool] = mapped_column(Boolean, default=True)
