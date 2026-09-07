import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

TRAFFIC_SOURCES = (
    "manual",
    "burp_live",
    "har",
    "burp_file",
    "zst_traffic",
    "agent",
    "webinspect_macro",
)


class TrafficInteraction(Base):
    """Persisted form of the canonical HttpInteraction schema (§4). Every
    ingestion path (manual entry, Burp, file import, macro recorder)
    normalizes into this same shape so downstream agents are source-agnostic.
    """

    __tablename__ = "traffic_interactions"

    version_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("versions.id"))
    # ON DELETE SET NULL, not CASCADE: recorded traffic history should
    # survive the credential that produced it being deleted later — same
    # "don't take history down with the source" contract as
    # VgsReportVulnerability.source_finding_id.
    credential_set_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("credential_sets.id", ondelete="SET NULL")
    )
    source: Mapped[str] = mapped_column(String(32))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    request_method: Mapped[str] = mapped_column(String(16))
    request_url: Mapped[str] = mapped_column(Text)
    request_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    request_query_params: Mapped[dict] = mapped_column(JSON, default=dict)
    request_body: Mapped[str | None] = mapped_column(Text)

    response_status: Mapped[int | None] = mapped_column(Integer)
    response_headers: Mapped[dict | None] = mapped_column(JSON)
    response_body: Mapped[str | None] = mapped_column(Text)
    timing_ms: Mapped[float | None] = mapped_column(Float)

    version = relationship("Version")
