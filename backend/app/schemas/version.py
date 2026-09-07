import uuid
from datetime import datetime

from pydantic import BaseModel


class VersionCreate(BaseModel):
    name: str


class VersionOut(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    name: str
    created_at: datetime
    is_authorized: bool

    model_config = {"from_attributes": True}


class ScopeEntryCreate(BaseModel):
    host: str
    port: int | None = None
    path_pattern: str | None = None
    in_scope: bool = True


class ScopeEntryUpdate(BaseModel):
    host: str | None = None
    port: int | None = None
    path_pattern: str | None = None
    in_scope: bool | None = None


class ScopeEntryOut(BaseModel):
    id: uuid.UUID
    version_id: uuid.UUID
    host: str
    port: int | None
    path_pattern: str | None
    in_scope: bool

    model_config = {"from_attributes": True}


class AuthorizationRecordOut(BaseModel):
    id: uuid.UUID
    version_id: uuid.UUID
    approver_name: str
    attestation_text: str | None
    letter_object_key: str | None
    attested_by: uuid.UUID
    attested_at: datetime

    model_config = {"from_attributes": True}
