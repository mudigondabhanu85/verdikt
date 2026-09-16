import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Project(Base):
    __tablename__ = "projects"

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(255))
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    # Soft delete (§6): set on archive, cleared on unarchive. Archived
    # projects are hidden from the default list view but never lose data.
    # Hard delete (admin-only, typed confirmation) removes the row outright
    # instead of setting this.
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    versions: Mapped[list["Version"]] = relationship(back_populates="project")


class Version(Base):
    """An engagement within a project."""

    __tablename__ = "versions"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    name: Mapped[str] = mapped_column(String(255))
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))

    project: Mapped[Project] = relationship(back_populates="versions")
    scope_entries: Mapped[list["ScopeEntry"]] = relationship(back_populates="version")


class ScopeEntry(Base):
    """A single allow/deny entry in a Version's technical scope. Later-phase
    agents read the in_scope=True rows as their hard host/port allow-list
    (§1) — this is not just a UI reminder.
    """

    __tablename__ = "scope_entries"

    version_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("versions.id"))
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int | None] = mapped_column(Integer)
    path_pattern: Mapped[str | None] = mapped_column(String(500))
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)
    # "target" (the default — a real, analyst-authorized scan target) or
    # "login_only" (auto-added purely so a login POST can reach a
    # third-party IdP host — see
    # app.api.routes.credentials._ensure_login_endpoint_in_scope). Still
    # in_scope=True either way (login must still be able to reach it) —
    # this only feeds app.agents.scope's fuzzing filter, so an IdP host
    # added this way never becomes a target for injection/XSS/SSTI
    # payloads just because the crawl happened to discover something on
    # it during the login flow.
    purpose: Mapped[str] = mapped_column(String(20), default="target")

    version: Mapped[Version] = relationship(back_populates="scope_entries")
