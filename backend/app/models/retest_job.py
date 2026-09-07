import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# §8 per-finding retest — a single, cheap re-verification of ONE
# Finding's specific check (not a full rescan). "not_supported" is a
# real, honest outcome, not an error: app.agents.retest_registry only
# covers check types whose original detection is a single deterministic
# HTTP/browser probe against a stable URL — checks that need a fresh
# authenticated session (CSRF, JWT, access-control, business-logic) or
# AI-assisted adversarial payload validation (the injection family)
# aren't retestable standalone from a Finding alone yet; a full rescan
# remains the way to re-verify those.
RETEST_JOB_STATUSES = ("pending", "running", "completed", "failed")
RETEST_RESULTS = ("still_vulnerable", "fixed", "not_supported", "error")


class RetestJob(Base):
    __tablename__ = "retest_jobs"

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    result: Mapped[str | None] = mapped_column(String(30), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    request_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
