import uuid

from pydantic import BaseModel


class TargetCreate(BaseModel):
    host: str
    port: int | None = None
    base_url: str | None = None


class TargetOut(BaseModel):
    id: uuid.UUID
    version_id: uuid.UUID
    host: str
    port: int | None
    base_url: str | None

    model_config = {"from_attributes": True}
