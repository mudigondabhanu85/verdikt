import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class UserInviteCreate(BaseModel):
    email: EmailStr
    role: str
    # Optional — when set, the account is created active with this
    # password immediately (no invite link to hand off); when omitted,
    # behavior is unchanged from before this field existed: an
    # invite_token is generated and the invitee sets their own password
    # via accept-invite. Either way the org_admin doing the inviting
    # never has to know or transmit the invitee's real, final password.
    password: str | None = Field(default=None, min_length=8)


class UserInviteOut(BaseModel):
    """Returned once, from the invite-creation response only — the
    invite_token is a secret-equivalent (whoever holds it can set the
    account's password), never re-displayed or returned from GET /users,
    same discipline as an API key's raw value (app.models.api_key).
    invite_token is None when the inviter set a password directly —
    there is no link to hand off in that case, the account is already
    usable."""

    id: uuid.UUID
    email: EmailStr
    role: str
    invite_token: str | None
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
    project_ids: list[uuid.UUID] = []

    model_config = {"from_attributes": True}


class AcceptInviteRequest(BaseModel):
    invite_token: str
    password: str


class UserRoleUpdate(BaseModel):
    role: str


class UserProjectMembershipsUpdate(BaseModel):
    """Replaces the user's full set of assigned Projects — a PUT, not a
    PATCH, to match the UI's own multi-select (the whole checked/selected
    set is submitted at once, not one add/remove at a time). Meaningless
    for an org_admin (ProjectMembership is never consulted for that
    role — see app.api.deps._check_project_access), but still accepted
    rather than rejected: an org that later demotes an org_admin to
    project_lead shouldn't find a stale, un-settable membership list
    waiting for them."""

    project_ids: list[uuid.UUID]
