import uuid

from pydantic import BaseModel


class VGSConfigCreate(BaseModel):
    label: str
    webhook_url: str
    push_on_scan_completed: bool = True


class VGSConfigOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    label: str
    masked_reference: str
    push_on_scan_completed: bool

    model_config = {"from_attributes": True}
