import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# Prefixed so a leaked key is instantly identifiable as a Verdikt
# credential (grep-able in logs/scanners), matching common practice
# (Stripe's sk_live_, GitHub's ghp_, etc.).
API_KEY_PREFIX = "vdk_"


class ApiKey(Base):
    """A long-lived credential for programmatic access (§9 enterprise
    hardening — CI/CD pipelines and automation calling the API directly,
    as an alternative to a short-lived JWT from an interactive login).
    Authenticates AS an existing User (same org/role/permissions that
    user already has — an API key is not a separate principal type), so
    every RBAC check and audit-log entry downstream works unchanged.

    Only hashed_key (SHA-256 — the key itself is already
    high-entropy/random, unlike a user-chosen password, so a slow KDF
    like argon2 isn't needed; SHA-256 also allows an indexed equality
    lookup instead of iterating every key to try a salted verify) is
    ever persisted. The raw key is shown to the caller exactly once, at
    creation time, and never again.
    """

    __tablename__ = "api_keys"

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    label: Mapped[str] = mapped_column(String(100))
    # First ~12 chars of the real key, safe to display for identification
    # ("which key is this") without reconstructing the secret.
    key_prefix: Mapped[str] = mapped_column(String(20))
    hashed_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
