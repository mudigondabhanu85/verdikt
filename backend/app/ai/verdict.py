import json
import re
from typing import Literal

from pydantic import BaseModel, ValidationError

# Real model output routinely wraps JSON in a markdown code fence (```json
# ... ``` or plain ``` ... ```) even when the prompt asks for raw JSON —
# every real (non-scripted-fake) Claude response observed against DVWA did
# this. Strip one if present before parsing.
_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*\n?(.*?)\n?```$", re.DOTALL)


def _strip_code_fence(raw_content: str) -> str:
    match = _CODE_FENCE_RE.match(raw_content.strip())
    return match.group(1).strip() if match else raw_content.strip()


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
        data = json.loads(_strip_code_fence(raw_content))
    except json.JSONDecodeError:
        return None
    try:
        return Verdict(**data)
    except ValidationError:
        return None
