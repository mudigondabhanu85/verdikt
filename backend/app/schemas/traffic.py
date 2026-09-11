import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel

TrafficSource = Literal[
    "manual",
    "burp_live",
    "har",
    "burp_file",
    "zst_traffic",
    "webinspect_macro",
    "agent",
    "openapi_import",
    "postman_import",
]


class HttpRequest(BaseModel):
    method: str
    url: str
    headers: dict[str, str] = {}
    query_params: dict[str, str] = {}
    body: str | None = None


class HttpResponse(BaseModel):
    status: int | None = None
    headers: dict[str, str] | None = None
    body: str | None = None
    timing_ms: float | None = None


class HttpInteraction(BaseModel):
    """Canonical schema every traffic ingestion path (manual, Burp, file
    import, macro recorder) normalizes into (§4). Downstream agents consume
    only this shape, never a source-specific format.
    """

    request: HttpRequest
    response: HttpResponse
    source: TrafficSource
    credential_set_id: uuid.UUID | None = None
    timestamp: datetime


class TrafficInteractionOut(BaseModel):
    id: uuid.UUID
    version_id: uuid.UUID
    source: TrafficSource
    timestamp: datetime
    request: HttpRequest
    response: HttpResponse
    credential_set_id: uuid.UUID | None = None

    model_config = {"from_attributes": True}


class TrafficImportResult(BaseModel):
    imported_count: int
    interaction_ids: list[uuid.UUID]


class ManualTrafficCreate(BaseModel):
    """Body for POST /versions/{id}/traffic/manual — a single HTTP
    exchange submitted directly (e.g. by the Montoya Burp extension's
    "Send to Verdikt" context-menu action, §4), rather than a whole file.
    source is always forced to "manual" server-side, not caller-supplied.
    """

    request: HttpRequest
    response: HttpResponse
    credential_set_id: uuid.UUID | None = None
    timestamp: datetime | None = None
