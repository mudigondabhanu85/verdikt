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

    # Optional — see app.models.credential.CredentialSet.privilege_rank.
    privilege_rank: int | None = None


class CredentialSetUpdate(BaseModel):
    """All fields optional — a PATCH only touches what's present (§5/§6:
    an analyst rotating a password after a client rotation, or fixing a
    login endpoint, without deleting and recreating the credential set).
    username/secret can each be supplied independently — the route
    decrypts the existing envelope first and only overrides the field(s)
    actually present here before re-encrypting (the envelope itself
    always stores both jointly, see app.vault.credential_vault).
    """

    label: str | None = None
    credential_type: str | None = None
    username: str | None = None
    secret: str | None = None
    login_endpoint: str | None = None
    login_method: str | None = None
    login_body_template: str | None = None
    login_content_type: str | None = None
    token_response_path: str | None = None
    extra_cookies: dict[str, str] | None = None
    privilege_rank: int | None = None


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
    privilege_rank: int | None

    model_config = {"from_attributes": True}


class TestLoginResult(BaseModel):
    """Response for POST .../test-login — a quick "does this actually
    work" check, distinct from a full scan: attempts SessionManager.login
    (skipping <form> auto-discovery, which needs a real crawl this
    doesn't do — see the message returned when that's the gap) and, if a
    session comes back, fires one authenticated GET at the version's
    first Target to report a real HTTP status code.
    """

    session_established: bool
    test_request_url: str | None
    test_request_status: int | None
    ok: bool  # session_established AND test_request_status in 200..299
    message: str
