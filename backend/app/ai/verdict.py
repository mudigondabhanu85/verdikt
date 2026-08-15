import json
from typing import Literal

from pydantic import BaseModel, ValidationError


class Verdict(BaseModel):
    vulnerable: bool
    confidence: Literal["high", "medium", "low"]
    reasoning: str


def parse_verdict(raw_content: str) -> Verdict | None:
    """Every triage/validation prompt asks for a strict JSON verdict. If
    the model doesn't return parseable JSON matching the schema, treat it
    as "couldn't confirm" (None) — fail safe, never guess a Finding into
    existence from unparseable model output.
    """
    try:
        data = json.loads(raw_content)
    except json.JSONDecodeError:
        return None
    try:
        return Verdict(**data)
    except ValidationError:
        return None
