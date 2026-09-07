import uuid
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
    started_at: datetime | None
    completed_at: datetime | None
    error: str | None
    warning: str | None = None
    ai_provider_config_id: uuid.UUID | None = None

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
