"""Insecure deserialization (§3) — PASSIVE detection only. Does any
observed cookie or hidden form field carry a recognizable
serialized-object signature (Java, PHP, or .NET ViewState)?

This deliberately never attempts active exploitation — crafting a
working deserialization gadget chain is target/library-specific and can
crash or otherwise damage the target, exactly what §1.2's safe-by-default
guardrail exists to prevent. A signature match is also not independently
provable the way a SQLi/XSS payload's effect is, so per §2's
Confirmed-Only Findings Policy this can never become a Finding on its
own — it's queued as a ReviewCandidate for an analyst to manually assess,
the same treatment XSS gets before browser-proof.
"""

import re
import uuid
from dataclasses import dataclass

import httpx

from app.agents.http_client import ScopedHttpClient
from app.agents.recon import FormInfo
from app.models.review_candidate import ReviewCandidate

_JAVA_B64_PREFIX = "rO0AB"
_PHP_SERIALIZED_RE = re.compile(r'^[aOs]:\d+:')
_TRUNCATE = 200


@dataclass
class SerializationSignal:
    kind: str  # "Java", "PHP", or ".NET ViewState"
    source: str  # e.g. "cookie: JSESSIONID" or "hidden field: __VIEWSTATE"
    endpoint: str
    sample: str


def _classify(value: str) -> str | None:
    stripped = value.strip()
    if stripped.startswith(_JAVA_B64_PREFIX):
        return "Java"
    if _PHP_SERIALIZED_RE.match(stripped):
        return "PHP"
    return None


def detect_from_cookies(responses: dict[str, httpx.Response]) -> list[SerializationSignal]:
    signals: list[SerializationSignal] = []
    seen: set[str] = set()
    for url, response in responses.items():
        for raw in response.headers.get_list("set-cookie"):
            name, _, rest = raw.partition("=")
            name = name.strip()
            value = rest.split(";", 1)[0].strip()
            if name in seen:
                continue
            kind = _classify(value)
            if kind is not None:
                seen.add(name)
                signals.append(
                    SerializationSignal(
                        kind=kind, source=f"cookie: {name}", endpoint=url, sample=value[:_TRUNCATE]
                    )
                )
    return signals


def detect_from_forms(forms: list[FormInfo]) -> list[SerializationSignal]:
    signals: list[SerializationSignal] = []
    seen: set[str] = set()
    for form in forms:
        for field in form.fields:
            if field.name == "__VIEWSTATE" and field.name not in seen:
                seen.add(field.name)
                signals.append(
                    SerializationSignal(
                        kind=".NET ViewState",
                        source=f"hidden field: {field.name}",
                        endpoint=form.action_url,
                        sample="(__VIEWSTATE field present)",
                    )
                )
    return signals


class DeserializationAgent:
    """No LLM triage — a passive pattern match is queued straight to
    ReviewCandidate (never a Finding, see module docstring)."""

    def __init__(
        self,
        client: ScopedHttpClient,
        *,
        scan_run_id: uuid.UUID,
        agent_job_id: uuid.UUID,
        db_session,
    ):
        self._client = client
        self._scan_run_id = scan_run_id
        self._agent_job_id = agent_job_id
        self._session = db_session

    async def run(
        self, discovered_responses: dict[str, httpx.Response], forms: list[FormInfo]
    ) -> list[ReviewCandidate]:
        signals = detect_from_cookies(discovered_responses) + detect_from_forms(forms)
        candidates: list[ReviewCandidate] = []
        for signal in signals:
            candidates.append(await self._persist(signal))
        return candidates

    async def _persist(self, signal: SerializationSignal) -> ReviewCandidate:
        candidate = ReviewCandidate(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_type="potential-insecure-deserialization",
            title=f"Potential {signal.kind} Serialized Object Observed ({signal.source})",
            severity_guess="Low",
            affected_endpoint=signal.endpoint,
            request_raw=f"(passive observation — not an active probe) {signal.source} at {signal.endpoint}",
            response_raw=f"sample value: {signal.sample}",
            llm_reasoning=(
                f"Deterministic pattern match against a known {signal.kind} serialization "
                "signature — not independently confirmed. Active deserialization exploitation "
                "isn't automated (§1.2 safe-by-default: a gadget chain is target-specific and "
                "can be destructive), so this needs manual review to assess exploitability."
            ),
            llm_confidence="medium",
            status="pending",
        )
        async with self._client.session_lock:
            self._session.add(candidate)
            await self._session.commit()
        return candidate
