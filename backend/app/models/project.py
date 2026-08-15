import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Project(Base):
    __tablename__ = "projects"

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(255))
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))

    versions: Mapped[list["Version"]] = relationship(back_populates="project")


class Version(Base):
    """An engagement within a project. Carries the §1 authorization-gate
    state directly: no active-testing agent may run against a target until
    this Version has scope entries and at least one authorization record.
    """

    __tablename__ = "versions"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    name: Mapped[str] = mapped_column(String(255))
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))

    project: Mapped[Project] = relationship(back_populates="versions")
    scope_entries: Mapped[list["ScopeEntry"]] = relationship(back_populates="version")
    authorization_records: Mapped[list["AuthorizationRecord"]] = relationship(
        back_populates="version"
    )

    @property
    def is_authorized(self) -> bool:
        return len(self.authorization_records) > 0


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

    version: Mapped[Version] = relationship(back_populates="scope_entries")


class AuthorizationRecord(Base):
    """A recorded authorization for a Version — an uploaded pentest
    authorization letter reference and/or a checkbox attestation with a
    named approver (§1). A Version is only "authorized" once it has at
    least one of these.
    """

    __tablename__ = "authorization_records"

    version_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("versions.id"))
    approver_name: Mapped[str] = mapped_column(String(255))
    attestation_text: Mapped[str | None] = mapped_column(Text)
    letter_object_key: Mapped[str | None] = mapped_column(String(500))
    attested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    attested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    version: Mapped[Version] = relationship(back_populates="authorization_records")
