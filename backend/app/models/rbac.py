from sqlalchemy import Boolean, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RolePermission(Base):
    """The RBAC permission matrix as data (§9): (role, resource, action) ->
    allowed. Granting a role a new permission, or adding a new role, is a
    row insert — never a code change in app/auth/rbac.py.
    """

    __tablename__ = "role_permissions"
    __table_args__ = (UniqueConstraint("role", "resource", "action", name="uq_role_permission"),)

    role: Mapped[str] = mapped_column(String(32), index=True)
    resource: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(32))
    allowed: Mapped[bool] = mapped_column(Boolean, default=True)
