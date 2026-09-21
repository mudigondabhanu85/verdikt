import uuid
from datetime import datetime

from pydantic import BaseModel


class RecordMacroRequest(BaseModel):
    start_url: str


class RecordingStartedOut(BaseModel):
    recording_id: uuid.UUID


class LoginMacroOut(BaseModel):
    id: uuid.UUID
    version_id: uuid.UUID
    credential_set_id: uuid.UUID
    step_count: int
    created_at: datetime

    model_config = {"from_attributes": True}


class MacroReplayTestResult(BaseModel):
    """Response for POST .../macros/{macro_id}/replay — the macro-specific
    counterpart to TestLoginResult (app.schemas.credential): replays this
    exact recorded macro headlessly (not necessarily the credential's
    latest one — a credential can have several saved macros, see
    MacroSection's per-macro list) and reports a real pass/fail verdict,
    not just "a session was created" (see MacroReplayResult's docstring
    in app.agents.macro for why that alone isn't trustworthy).
    """

    ok: bool
    session_established: bool
    cookie_count: int
    final_url: str
    final_status: int | None
    still_shows_password_field: bool
    message: str
