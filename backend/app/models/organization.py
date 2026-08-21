import uuid

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

# Baseline RBAC roles (§9). Adding a role is a data change (a new set of
# role_permissions rows), not a code change — see app/models/rbac.py.
BASELINE_ROLES = ("org_admin", "project_lead", "analyst", "viewer")


class Organization(Base):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), unique=True)

    users: Mapped[list["User"]] = relationship(back_populates="organization")


class User(Base):
    __tablename__ = "users"

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    # Nullable — an SSO-only user (§9, app.auth.oidc) never sets a
    # password. app.auth.security.verify_password is only ever reached
    # after confirming this is non-null, so login-by-password can't
    # succeed against a None hash.
    hashed_password: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32))
    is_active: Mapped[bool] = mapped_column(default=True)
    # The OIDC ID token's "sub" claim, once this user has logged in via
    # SSO at least once — scoped by org (a lookup always happens within
    # one specific org's configured OIDC provider), not globally unique.
    oidc_subject: Mapped[str | None] = mapped_column(String(255), index=True)

    organization: Mapped[Organization] = relationship(back_populates="users")
