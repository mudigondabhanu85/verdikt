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
    # "target" (a real, analyst-authorized scan target) or "login_only"
    # (auto-added purely so a login POST could reach a third-party IdP —
    # see app.api.routes.credentials._ensure_login_endpoint_in_scope).
    # Surfaced so the Scope tab can show an analyst *why* a host they
    # didn't type themselves is in scope, not just that it is.
    purpose: str

    model_config = {"from_attributes": True}
