import uuid

from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ProjectMembership(Base):
    """Restricts a non-org_admin user's project-scoped access (every
    Project/Version/ScanRun/Finding/ReviewCandidate route — see
    app.api.deps's own project-access check) to an explicit set of
    Projects, layered on top of the existing org-wide role. org_admin
    always bypasses this (see app.api.deps._check_project_access) — the
    role's whole point is unrestricted administrative access, matching
    how every other resource's RBAC grant already treats it.

    No row for a (user, project) pair means no access, not "access
    pending" — an org_admin inviting a project_lead/analyst/viewer must
    explicitly assign at least one Project before that user can see
    anything, mirroring the "no ScopeEntry means nothing is in scope"
    fail-closed convention used throughout the scanning engine itself.
    """

    __tablename__ = "project_memberships"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))

    __table_args__ = (UniqueConstraint("user_id", "project_id", name="uq_project_membership_user_project"),)
