import uuid
from typing import Literal

from pydantic import BaseModel


class VGSConfigCreate(BaseModel):
    label: str
    webhook_url: str
    push_on_scan_completed: bool = True
    # The real, connected VGS instance has no auth of its own (§11 —
    # confirmed against its actual source). These stay optional for any
    # other findings-ingestion webhook an org points this at instead.
    # auth_value is the raw secret: an API key, a bearer token, or
    # "username:password" for basic — never echoed back once stored.
    auth_type: Literal["api_key", "bearer_token", "basic"] | None = None
    auth_value: str | None = None


class VGSConfigOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    label: str
    masked_reference: str
    push_on_scan_completed: bool
    auth_type: str | None
    masked_auth_reference: str | None

    model_config = {"from_attributes": True}
