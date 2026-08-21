import uuid

from pydantic import BaseModel, model_validator

from app.models.notification_config import NOTIFICATION_PROVIDER_TYPES


class NotificationConfigCreate(BaseModel):
    label: str
    provider: str
    webhook_url: str
    notify_on_scan_completed: bool = True

    @model_validator(mode="after")
    def _validate_provider(self) -> "NotificationConfigCreate":
        if self.provider not in NOTIFICATION_PROVIDER_TYPES:
            raise ValueError(f"provider must be one of {NOTIFICATION_PROVIDER_TYPES}, got {self.provider!r}")
        return self


class NotificationConfigOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    label: str
    provider: str
    masked_reference: str
    notify_on_scan_completed: bool

    model_config = {"from_attributes": True}
