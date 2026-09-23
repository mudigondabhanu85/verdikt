import uuid
from decimal import Decimal
from datetime import datetime

from pydantic import BaseModel

from app.schemas.finding import FindingOut


class ScanRunCreate(BaseModel):
    """Optional body for POST /versions/{id}/scan-runs. ai_provider_config_id,
    when given, must reference an AIProviderConfig owned by the caller's
    org (multi-agent §0/§10 — pick a provider per scan run); omitted or
    null falls back to the deployment's global ai_provider setting.
    """

    ai_provider_config_id: uuid.UUID | None = None


class ScanRunOut(BaseModel):
    id: uuid.UUID
    version_id: uuid.UUID
    status: str
    # "deterministic" (the existing 57-agent graph) | "autonomous_ai" —
    # see app.models.scan.SCAN_RUN_MODES. The frontend uses this to show
    # the Pentest Transcript tab only where it applies.
    mode: str = "deterministic"
    started_at: datetime | None
    completed_at: datetime | None
    error: str | None
    warning: str | None = None
    ai_provider_config_id: uuid.UUID | None = None
    # LLM spend/usage for this run (§10.5 budget guardrail — see
    # app.ai.budget.BudgetGuard). 0 for scans that never called an LLM
    # (e.g. ai_provider="fake"/Null adapter, or budget exhausted before
    # any call).
    llm_cost_usd: Decimal = Decimal(0)
    llm_input_tokens: int = 0
    llm_output_tokens: int = 0
    # Same shape as ScanRunDetail's own field below — populated here too
    # so the scan-runs LIST (what the Scan Runs tab actually renders)
    # can show a vulnerability count per run without a click-through,
    # instead of only being visible on each run's own detail page.
    finding_counts_by_severity: dict[str, int] = {}

    model_config = {"from_attributes": True}


class AgentJobOut(BaseModel):
    id: uuid.UUID
    agent_type: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    error: str | None
    stats: dict | None

    model_config = {"from_attributes": True}


class ScanRunDetail(ScanRunOut):
    agent_jobs: list[AgentJobOut]
    finding_counts_by_severity: dict[str, int]
    tech_stack_fingerprint: dict | None = None


class ScanRunDiffOut(BaseModel):
    """§8 diff report — new/fixed/still_open findings between an earlier
    scan run and a later one, matched the same way app.agents.retest's
    scan-level diff already matches findings across runs
    (check_id + affected_endpoints). "fixed" findings are returned as
    they appeared in the earlier run (that's the only place they still
    exist); "still_open" findings are returned as they appear in the
    later run (its evidence is the more current one).
    """

    earlier_scan_run_id: uuid.UUID
    later_scan_run_id: uuid.UUID
    new_findings: list[FindingOut]
    fixed_findings: list[FindingOut]
    still_open_findings: list[FindingOut]
