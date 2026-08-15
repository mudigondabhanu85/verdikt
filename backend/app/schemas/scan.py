import uuid
from datetime import datetime

from pydantic import BaseModel


class ScanRunOut(BaseModel):
    id: uuid.UUID
    version_id: uuid.UUID
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    error: str | None

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
