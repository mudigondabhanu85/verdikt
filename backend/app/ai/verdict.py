import json
import re
from typing import Literal

from pydantic import BaseModel, ValidationError

# Real model output routinely wraps JSON in a markdown code fence (```json
# ... ``` or plain ``` ... ```) even when the prompt asks for raw JSON —
# every real (non-scripted-fake) Claude response observed against DVWA did
# this. A real response was also observed containing TWO fenced JSON
# blocks: the model visibly second-guessed itself mid-response ("Wait,
# let me reconsider...") before settling on a final answer in a second
# block — findall (not a single anchored match) plus iterating candidates
# in reverse means the model's last, settled answer wins over an earlier
# one it explicitly walked back from.
_CODE_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)\n?```", re.DOTALL)


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
    candidates = _CODE_FENCE_RE.findall(raw_content) or [raw_content]
    for candidate in reversed(candidates):
        try:
            data = json.loads(candidate.strip())
        except json.JSONDecodeError:
            continue
        try:
            return Verdict(**data)
        except ValidationError:
            continue
    return None
