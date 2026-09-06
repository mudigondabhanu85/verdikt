import uuid
from datetime import datetime

from pydantic import BaseModel


class AttackChainEvidenceOut(BaseModel):
    request_raw: str
    response_raw: str
    screenshot_refs: list[str]
    additional_notes: str | None

    model_config = {"from_attributes": True}


class AttackChainOut(BaseModel):
    id: uuid.UUID
    scan_run_id: uuid.UUID
    title: str
    severity: str
    finding_ids: list[str]
    plain_language_summary: str
    narrative: str
    steps_to_reproduce: list[str]
    references: list[str]
    confirmation_status: str
    created_at: datetime
    evidence: AttackChainEvidenceOut | None

    model_config = {"from_attributes": True}
