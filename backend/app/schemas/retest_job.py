import uuid
from datetime import datetime

from pydantic import BaseModel


class RetestJobOut(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    status: str
    result: str | None
    created_at: datetime
    completed_at: datetime | None
    request_raw: str | None
    response_raw: str | None
    error: str | None

    model_config = {"from_attributes": True}
