import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import JSON, DateTime, ForeignKey, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

SCAN_RUN_STATUSES = ("pending", "running", "completed", "failed")
# "skipped" (§10.5): the §2 budget guardrail stopped this agent before it
# ran, not a failure — see app/ai/budget.py.
AGENT_JOB_STATUSES = ("pending", "running", "completed", "failed", "skipped")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    version_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("versions.id"))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    # Running total of estimated LLM spend for this run (§10.5 budget guardrail).
    llm_cost_usd: Mapped[Decimal] = mapped_column(Numeric(10, 4), default=Decimal(0))
    # Generated lazily on first report request and cached here (§8) so
    # repeated report.json/html/pdf/docx requests don't re-spend LLM
    # budget regenerating the same text — see app.reporting.executive_summary.
    executive_summary: Mapped[str | None] = mapped_column(Text)


class AgentJob(Base):
    __tablename__ = "agent_jobs"

    scan_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_runs.id"))
    agent_type: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    stats: Mapped[dict | None] = mapped_column(JSON)
