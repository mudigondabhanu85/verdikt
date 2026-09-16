import uuid

from sqlalchemy import JSON, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

# Only these two exist as real Finding rows (§8): a candidate that never
# reproduces on re-fetch is discarded, not persisted as "needs_review" —
# see app/agents/header_config.py for the confirmation step.
CONFIRMATION_STATUSES = ("ai_confirmed", "analyst_confirmed")
RETEST_STATUSES = ("open", "fixed", "risk_accepted", "false_positive_after_review")


class Finding(Base):
    __tablename__ = "findings"

    scan_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"))
    agent_job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agent_jobs.id", ondelete="CASCADE"))
    check_id: Mapped[str] = mapped_column(String(100))

    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16))
    owasp_2025_category: Mapped[str] = mapped_column(String(100))
    cwe_id: Mapped[str] = mapped_column(String(20))
    portswigger_reference_url: Mapped[str | None] = mapped_column(String(500))
    cvss_vector: Mapped[str] = mapped_column(String(100))
    cvss_score: Mapped[float] = mapped_column(Float)
    affected_endpoints: Mapped[list] = mapped_column(JSON, default=list)

    plain_language_summary: Mapped[str] = mapped_column(Text)
    technical_description: Mapped[str] = mapped_column(Text)
    steps_to_reproduce: Mapped[list] = mapped_column(JSON, default=list)
    remediation: Mapped[str] = mapped_column(Text)
    references: Mapped[list] = mapped_column(JSON, default=list)

    confirmation_status: Mapped[str] = mapped_column(String(20), default="ai_confirmed")
    retest_status: Mapped[str] = mapped_column(String(30), default="open")

    evidence: Mapped["Evidence | None"] = relationship(uselist=False, viewonly=True)


class Evidence(Base):
    __tablename__ = "evidence"

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    request_raw: Mapped[str] = mapped_column(Text)
    response_raw: Mapped[str] = mapped_column(Text)
    # Populated by Phase 5's Playwright evidence-capture subsystem; always
    # empty in Phase 1 (no client-side/browser-observable check types yet).
    screenshot_refs: Mapped[list] = mapped_column(JSON, default=list)
    additional_notes: Mapped[str | None] = mapped_column(Text)
    # The exact substring that proves this finding — a forged Origin
    # value, an executed XSS marker, an unescaped "={marker}" string,
    # the weak password itself, etc. — not just the full raw request/
    # response text it appears somewhere inside. Every report surface
    # (HTML/PDF/DOCX) highlights this specific substring wherever
    # request_raw/response_raw is shown, since a wall of raw HTTP text
    # with nothing visually pointing at the one line that matters isn't
    # persuasive to a non-technical reader. Nullable — not every check
    # was retrofitted with this in the same pass that added the column,
    # and a missing payload degrades gracefully to unhighlighted raw
    # text rather than an error.
    payload: Mapped[str | None] = mapped_column(Text)
