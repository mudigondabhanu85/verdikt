import uuid

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# §2 step 5: candidates that pass deterministic + LLM triage but still
# need something Phase 2 can't provide yet (browser proof for XSS) land
# here instead of becoming a Finding. Never exported in client-facing
# reports; an analyst promotes or dismisses them explicitly.
REVIEW_CANDIDATE_STATUSES = ("pending", "promoted", "dismissed")


class ReviewCandidate(Base):
    __tablename__ = "review_candidates"

    scan_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_runs.id"))
    agent_job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agent_jobs.id"))
    check_type: Mapped[str] = mapped_column(String(100))
    title: Mapped[str] = mapped_column(String(255))
    severity_guess: Mapped[str] = mapped_column(String(16))
    affected_endpoint: Mapped[str] = mapped_column(Text)
    request_raw: Mapped[str] = mapped_column(Text)
    response_raw: Mapped[str] = mapped_column(Text)
    llm_reasoning: Mapped[str] = mapped_column(Text)
    llm_confidence: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(20), default="pending")
