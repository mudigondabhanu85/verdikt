import uuid
from datetime import datetime

from pydantic import BaseModel


class DashboardScanRunSummary(BaseModel):
    id: uuid.UUID
    version_id: uuid.UUID
    project_name: str
    version_name: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    finding_counts_by_severity: dict[str, int]


class DashboardOut(BaseModel):
    total_projects: int
    total_versions: int
    total_scan_runs: int
    # "Open" here means retest_status != "fixed" — includes "open",
    # "risk_accepted", and "false_positive_after_review" together
    # (deliberately not split out further for this first pass; an
    # analyst reviewing the number would still open the underlying
    # scan run to see the breakdown).
    open_findings_by_severity: dict[str, int]
    recent_scan_runs: list[DashboardScanRunSummary]
