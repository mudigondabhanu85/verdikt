import uuid

from pydantic import BaseModel, model_validator

from app.models.notification_config import NOTIFICATION_PROVIDER_TYPES


class NotificationConfigCreate(BaseModel):
    label: str
    provider: str
    # Required for "slack"/"teams" — the incoming-webhook URL.
    webhook_url: str | None = None
    # Required together for "outlook" — plain SMTP connection details (the
    # build spec's own documented fallback to the Graph API, which needs
    # an Azure app registration this integration doesn't assume exists).
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_username: str | None = None
    smtp_password: str | None = None
    from_address: str | None = None
    to_address: str | None = None
    notify_on_scan_completed: bool = True

    @model_validator(mode="after")
    def _validate_provider(self) -> "NotificationConfigCreate":
        if self.provider not in NOTIFICATION_PROVIDER_TYPES:
            raise ValueError(f"provider must be one of {NOTIFICATION_PROVIDER_TYPES}, got {self.provider!r}")
        if self.provider in ("slack", "teams") and not self.webhook_url:
            raise ValueError(f'webhook_url is required when provider={self.provider!r}')
        if self.provider == "outlook":
            required = (
                self.smtp_host,
                self.smtp_port,
                self.smtp_username,
                self.smtp_password,
                self.from_address,
                self.to_address,
            )
            if any(v is None for v in required):
                raise ValueError(
                    "smtp_host, smtp_port, smtp_username, smtp_password, from_address, "
                    'and to_address are all required when provider="outlook"'
                )
        return self


class NotificationConfigOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    label: str
    provider: str
    masked_reference: str
    notify_on_scan_completed: bool

    model_config = {"from_attributes": True}
