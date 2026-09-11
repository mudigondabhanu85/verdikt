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
