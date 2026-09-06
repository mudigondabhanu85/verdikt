import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr


class UserInviteCreate(BaseModel):
    email: EmailStr
    role: str


class UserInviteOut(BaseModel):
    """Returned once, from the invite-creation response only — the
    invite_token is a secret-equivalent (whoever holds it can set the
    account's password), never re-displayed or returned from GET /users,
    same discipline as an API key's raw value (app.models.api_key)."""

    id: uuid.UUID
    email: EmailStr
    role: str
    invite_token: str
    invited_at: datetime

    model_config = {"from_attributes": True}


class UserOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    email: EmailStr
    role: str
    is_active: bool
    invited_at: datetime | None
    invite_accepted_at: datetime | None

    model_config = {"from_attributes": True}


class AcceptInviteRequest(BaseModel):
    invite_token: str
    password: str
