import uuid
from typing import Literal

from pydantic import BaseModel


class EvidenceOut(BaseModel):
    request_raw: str
    response_raw: str
    screenshot_refs: list[str]
    additional_notes: str | None

    model_config = {"from_attributes": True}


class FindingOut(BaseModel):
    id: uuid.UUID
    check_id: str
    title: str
    severity: str
    owasp_2025_category: str
    cwe_id: str
    portswigger_reference_url: str | None
    cvss_vector: str
    cvss_score: float
    affected_endpoints: list[str]
    plain_language_summary: str
    technical_description: str
    steps_to_reproduce: list[str]
    remediation: str
    references: list[str]
    confirmation_status: str
    retest_status: str
    evidence: EvidenceOut | None = None

    model_config = {"from_attributes": True}


class FindingStatusUpdate(BaseModel):
    """PATCH .../findings/{id} body — an analyst's own disposition after
    reviewing a Finding: mark it a false positive, accept the risk, or
    reopen it. See app.models.finding.RETEST_STATUSES.
    """

    retest_status: Literal["open", "fixed", "risk_accepted", "false_positive_after_review"]
