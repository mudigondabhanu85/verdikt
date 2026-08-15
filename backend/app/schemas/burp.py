import uuid

from pydantic import BaseModel


class BurpScanCreate(BaseModel):
    burp_base_url: str
    burp_api_key: str | None = None
    urls: list[str]
    scan_configurations: list[str] | None = None


class BurpScanCreated(BaseModel):
    scan_run_id: uuid.UUID
    agent_job_id: uuid.UUID
    task_id: str


class BurpScanImport(BaseModel):
    burp_base_url: str
    burp_api_key: str | None = None
    scan_run_id: uuid.UUID
    poll_interval: float = 5.0
    timeout: float = 3600.0


class BurpImportResult(BaseModel):
    scan_status: str
    imported_count: int
    finding_ids: list[uuid.UUID]
