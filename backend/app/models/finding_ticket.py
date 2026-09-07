import uuid

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class FindingTicket(Base):
    """Links a Finding to a ticket actually created in an external
    system (e.g. a real Jira issue key) — a Finding can accumulate
    several of these over time (re-created after being closed, or filed
    in more than one tracker), so this is its own table rather than a
    single nullable column on Finding.
    """

    __tablename__ = "finding_tickets"

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    ticketing_config_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ticketing_configs.id"))
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    external_key: Mapped[str] = mapped_column(String(50))
    external_url: Mapped[str] = mapped_column(String(500))
