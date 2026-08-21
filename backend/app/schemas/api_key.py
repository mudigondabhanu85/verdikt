import uuid
from datetime import datetime

from pydantic import BaseModel


class ApiKeyCreate(BaseModel):
    label: str


class ApiKeyCreated(BaseModel):
    """Returned exactly once, at creation time — this is the only
    response that will ever contain the raw key."""

    id: uuid.UUID
    label: str
    api_key: str
    key_prefix: str


class ApiKeyOut(BaseModel):
    id: uuid.UUID
    label: str
    key_prefix: str
    last_used_at: datetime | None
    revoked_at: datetime | None

    model_config = {"from_attributes": True}
