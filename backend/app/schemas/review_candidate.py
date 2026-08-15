import uuid

from pydantic import BaseModel


class ReviewCandidateOut(BaseModel):
    id: uuid.UUID
    scan_run_id: uuid.UUID
    agent_job_id: uuid.UUID
    check_type: str
    title: str
    severity_guess: str
    affected_endpoint: str
    request_raw: str
    response_raw: str
    llm_reasoning: str
    llm_confidence: str
    status: str

    model_config = {"from_attributes": True}
