import uuid

from pydantic import BaseModel, model_validator

from app.models.ticketing_config import TICKETING_PROVIDER_TYPES


class TicketingConfigCreate(BaseModel):
    label: str
    provider: str
    base_url: str
    email: str
    api_token: str
    project_key: str
    issue_type: str = "Task"

    @model_validator(mode="after")
    def _validate_provider(self) -> "TicketingConfigCreate":
        if self.provider not in TICKETING_PROVIDER_TYPES:
            raise ValueError(f"provider must be one of {TICKETING_PROVIDER_TYPES}, got {self.provider!r}")
        return self


class TicketingConfigOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    label: str
    provider: str
    base_url: str
    email: str
    masked_reference: str
    project_key: str
    issue_type: str

    model_config = {"from_attributes": True}
