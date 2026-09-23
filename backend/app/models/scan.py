import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import JSON, BigInteger, DateTime, ForeignKey, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

SCAN_RUN_STATUSES = ("pending", "running", "completed", "failed", "cancelled")
# "skipped" (§10.5): the §2 budget guardrail stopped this agent before it
# ran, not a failure — see app/ai/budget.py.
AGENT_JOB_STATUSES = ("pending", "running", "completed", "failed", "skipped")
# "deterministic" (default): the existing 57-agent LangGraph pipeline
# (app.agents.graph/runner.execute_scan_run). "autonomous_ai": a
# hand-written multi-turn tool-use loop against a real, network-isolated
# sandbox container (app.agents.autonomous_pentest.runner) — deliberately
# NOT run through build_graph()/LangGraph at all, since its open-ended,
# variable-length turn count doesn't fit a StateGraph's join semantics
# any better than runner.py's own _run_chain_analysis does (see that
# function's docstring for the identical reasoning, applied here to a
# much larger step instead of one small one).
SCAN_RUN_MODES = ("deterministic", "autonomous_ai")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    version_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("versions.id"))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    mode: Mapped[str] = mapped_column(String(20), default="deterministic")
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    # Set when the run reached status="completed" having crawled
    # effectively nothing (recon + authenticated_recon both discovered 0
    # endpoints) — a Target/Scope-host mismatch, or an auth failure the
    # crawler can't distinguish from "nothing to find". Distinct from
    # `error`: this scan didn't fail, it's just very likely misconfigured.
    warning: Mapped[str | None] = mapped_column(Text)
    # Running total of estimated LLM spend for this run (§10.5 budget guardrail).
    llm_cost_usd: Mapped[Decimal] = mapped_column(Numeric(10, 4), default=Decimal(0))
    # Running totals of actual token usage across every LLM call this run
    # made (accumulated in the same place as llm_cost_usd — see
    # app.ai.budget.BudgetGuard.guarded_complete, the single choke point
    # every agent's LLM call goes through). BigInteger: a long scan across
    # 20+ LLM-calling agent nodes can plausibly add up past Integer's
    # ~2.1B ceiling given enough retries/re-runs over the run's lifetime.
    llm_input_tokens: Mapped[int] = mapped_column(BigInteger, default=0)
    llm_output_tokens: Mapped[int] = mapped_column(BigInteger, default=0)
    # Generated lazily on first report request and cached here (§8) so
    # repeated report.json/html/pdf/docx requests don't re-spend LLM
    # budget regenerating the same text — see app.reporting.executive_summary.
    executive_summary: Mapped[str | None] = mapped_column(Text)
    # Which LLM provider+model this run's agents used (multi-agent §0/§10).
    # NULL means "fall back to the deployment's global ai_provider setting"
    # (app.config.Settings.ai_provider) — see app.ai.provider.resolve_provider.
    ai_provider_config_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("ai_provider_configs.id")
    )
    # Deterministic tech-stack fingerprint captured during recon (§10 smart
    # scan) — see app.agents.fingerprint. JSON dict, empty until recon runs.
    tech_stack_fingerprint: Mapped[dict | None] = mapped_column(JSON)


class AgentJob(Base):
    __tablename__ = "agent_jobs"

    scan_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"))
    agent_type: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    stats: Mapped[dict | None] = mapped_column(JSON)
