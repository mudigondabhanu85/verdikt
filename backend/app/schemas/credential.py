import uuid

from pydantic import BaseModel


class CredentialSetCreate(BaseModel):
    label: str
    credential_type: str = "username_password"
    username: str
    secret: str  # password / token / etc. — encrypted before storage, never echoed back

    # Optional explicit login config (§4/§5's Phase 2 precursor to the
    # Phase 4 macro recorder) — needed for JSON/REST logins that
    # auto-discovery from a server-rendered <form> can't find. Leave all
    # unset to fall back to <form> auto-discovery.
    login_endpoint: str | None = None
    login_method: str | None = None
    login_body_template: str | None = None
    login_content_type: str | None = None
    token_response_path: str | None = None

    # Static cookies sent on every authenticated request, merged in
    # alongside whatever the login response itself sets — see
    # app.models.credential.CredentialSet.extra_cookies.
    extra_cookies: dict[str, str] | None = None


class CredentialSetOut(BaseModel):
    id: uuid.UUID
    version_id: uuid.UUID
    label: str
    credential_type: str
    masked_reference: str
    login_endpoint: str | None
    login_method: str | None
    token_response_path: str | None
    extra_cookies: dict[str, str] | None

    model_config = {"from_attributes": True}
