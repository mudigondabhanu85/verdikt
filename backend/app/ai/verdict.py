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
    # request_raw/response_raw: the exact command/request and the exact
    # raw output/response that prove this finding — required (not
    # optional) for the same reason app.models.finding.Evidence's own
    # columns are NOT NULL: a Finding with no re-checkable raw evidence
    # attached isn't meaningfully different from an unverified claim,
    # and this project's whole "never guess a Finding into existence"
    # discipline exists to keep that from ever reaching a report. A
    # proposal missing either of these simply fails to parse — the same
    # fail-safe behavior as a missing title/severity — rather than
    # producing a Finding with an empty Evidence row.
    request_raw: str
    response_raw: str
    # The literal substring that proves it (an injected payload, a
    # forged header value, the exact marker that came back unescaped) —
    # optional, since not every finding class has one crisp substring to
    # point at. Mirrors Evidence.payload exactly: every report surface
    # (HTML/PDF/DOCX) and the Findings tab already highlight this
    # specific substring wherever request_raw/response_raw is shown, so
    # populating it here is what makes AI-pentest findings get the same
    # highlighting deterministic findings already have — no new
    # highlighting code needed anywhere.
    payload: str | None = None
    # Only meaningful for a reflected/DOM XSS reachable via a plain GET
    # request: poc_url is the page's URL WITHOUT any payload in it
    # (e.g. "http://target/search.jsp"), poc_param is the name of the
    # query parameter that's unescaped/injectable (e.g. "query"). When
    # both are present, app.agents.autonomous_pentest.runner builds a
    # ProbeTarget from them and reuses app.agents.xss_browser_proof's
    # existing, already-proven mechanism — the exact same one the
    # deterministic XSS agent uses — to load it in a real headless
    # browser with a controlled proof payload and capture a real
    # screenshot. Deliberately NOT a pre-built URL with the model's own
    # payload already embedded: the browser-proof mechanism supplies its
    # own known-reliable execution payloads and only needs to know WHERE
    # to inject them, matching why it can auto-confirm findings the
    # model's own curl-based reflection check alone couldn't prove a
    # real browser would execute.
    poc_url: str | None = None
    poc_param: str | None = None


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
