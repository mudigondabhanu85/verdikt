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


class FindingProposal(BaseModel):
    """What app.ai.prompts.autonomous_pentest.yaml's system prompt asks
    the model to emit once it has confirmed a real vulnerability with
    actual tool-collected evidence — see
    app.agents.autonomous_pentest.runner, the only caller. Deliberately
    a *proposal*: the runner still requires this to parse successfully
    against this schema before it becomes an ordinary Finding row (same
    "never guess a Finding into existence from unparseable output" rule
    parse_verdict already applies below), and unlike every deterministic
    check's Finding, there's no YAML catalog entry behind it — the
    model's own free-text title/description/evidence become the
    Finding's content directly, the same way app.agents.business_logic
    already builds a Finding from an LLM verdict's free-text reasoning
    rather than a fixed catalog lookup.
    """

    title: str
    severity: Literal["Critical", "High", "Medium", "Low"]
    cwe_id: str
    owasp_2025_category: str
    affected_endpoint: str
    plain_language_summary: str
    technical_description: str
    remediation: str
    evidence: str


def extract_json_objects(raw_content: str) -> list[dict]:
    """Strips markdown code fences (see _CODE_FENCE_RE's rationale above)
    and returns every fenced/bare block that parses as a JSON object,
    most-recent-first — reused by parse_verdict below and by
    app.agents.business_logic_planner's hypothesis parsing, since real
    model output has the same "wrapped in ```json ... ```, sometimes
    twice" quirks regardless of which prompt produced it.
    """
    candidates = _CODE_FENCE_RE.findall(raw_content) or [raw_content]
    parsed: list[dict] = []
    for candidate in reversed(candidates):
        try:
            data = json.loads(candidate.strip())
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            parsed.append(data)
    return parsed


def parse_verdict(raw_content: str) -> Verdict | None:
    """Every triage/validation prompt asks for a strict JSON verdict. If
    the model doesn't return parseable JSON matching the schema, treat it
    as "couldn't confirm" (None) — fail safe, never guess a Finding into
    existence from unparseable model output.
    """
    for data in extract_json_objects(raw_content):
        try:
            return Verdict(**data)
        except ValidationError:
            continue
    return None


def parse_finding_proposal(raw_content: str) -> FindingProposal | None:
    """Same fence-tolerant, fail-safe parsing as parse_verdict, for the
    autonomous pentest loop's Finding-proposal responses instead of a
    triage verdict. A response with no valid proposal (plain
    investigative narration, a mid-loop status update, a final "nothing
    found" summary) correctly returns None rather than raising — the
    caller only persists a Finding when this actually parses.
    """
    for data in extract_json_objects(raw_content):
        try:
            return FindingProposal(**data)
        except ValidationError:
            continue
    return None
