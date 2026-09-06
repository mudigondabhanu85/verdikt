import uuid

from sqlalchemy import JSON, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class AttackChain(Base):
    """A cross-referenced compound exploit spanning multiple independently
    Confirmed findings (§2's Chain Analysis Agent) — its own artifact, not
    a merged Finding, since its severity/narrative/repro steps are about
    the combination, not any single link. Only ever created after every
    finding_id it references has already passed the Confirmed-Only
    Findings Policy on its own; the chain as a whole then goes through the
    same adversarial-validation discipline before being persisted here.
    """

    __tablename__ = "attack_chains"

    scan_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_runs.id"))
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16))
    # Ordered list of Finding UUIDs (as strings) this chain links, in the
    # order they're used in the narrative — step 1 uses finding_ids[0],
    # etc.
    finding_ids: Mapped[list] = mapped_column(JSON, default=list)

    plain_language_summary: Mapped[str] = mapped_column(Text)
    narrative: Mapped[str] = mapped_column(Text)
    steps_to_reproduce: Mapped[list] = mapped_column(JSON, default=list)
    references: Mapped[list] = mapped_column(JSON, default=list)

    confirmation_status: Mapped[str] = mapped_column(String(20), default="ai_confirmed")

    evidence: Mapped["AttackChainEvidence | None"] = relationship(uselist=False, viewonly=True)


class AttackChainEvidence(Base):
    """Combined evidence bundle for an AttackChain — same shape as
    Evidence (§8), kept as a separate table (not reusing Evidence
    directly) since it isn't tied to a single agent_job_id/finding_id the
    way per-Finding evidence is."""

    __tablename__ = "attack_chain_evidence"

    attack_chain_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("attack_chains.id"))
    request_raw: Mapped[str] = mapped_column(Text)
    response_raw: Mapped[str] = mapped_column(Text)
    screenshot_refs: Mapped[list] = mapped_column(JSON, default=list)
    additional_notes: Mapped[str | None] = mapped_column(Text)
