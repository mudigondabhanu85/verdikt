import uuid

from sqlalchemy import Boolean, ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class VGSConfig(Base):
    """A named, org-scoped VGS webhook target (§11 — the decoupled
    integration path). The webhook URL is envelope-encrypted the same way
    NotificationConfig's Slack webhook is — it may itself embed a bearer
    secret, not just a public identifier.
    """

    __tablename__ = "vgs_configs"

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    label: Mapped[str] = mapped_column(String(100))
    encrypted_webhook_url: Mapped[bytes] = mapped_column(LargeBinary)
    masked_reference: Mapped[str] = mapped_column(String(255))
    push_on_scan_completed: Mapped[bool] = mapped_column(Boolean, default=True)
