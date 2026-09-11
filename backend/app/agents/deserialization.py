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

An LLM triage pass (added 2026-09, matching injection.py's triage
pattern) still runs on every signal — not to promote it to a Finding
(the active-exploitation ban above makes that structurally impossible;
there's no safe re-execution step the way injection.py has), but to
replace the previously-static, templated `llm_reasoning` text with a
real per-signal assessment (plausibility, likely false-positive
patterns e.g. framework session tokens that happen to match the byte
signature) — genuine AI participation in triage, same as every other
check, without weakening the safety guarantee that this can never
self-confirm into a Finding.
"""

import re
import uuid
from dataclasses import dataclass

import httpx

from app.agents.http_client import ScopedHttpClient
from app.agents.recon import FormInfo
from app.ai.budget import BudgetExceededError, BudgetGuard, ProviderUnavailableError
from app.ai.prompts.loader import render_prompt
from app.ai.verdict import parse_verdict
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
    """LLM triage refines llm_reasoning/llm_confidence on every signal
    (see module docstring) — but can never turn one into a Finding; that
    would require active exploitation, which is deliberately never
    attempted here."""

    def __init__(
        self,
        client: ScopedHttpClient,
        *,
        scan_run_id: uuid.UUID,
        agent_job_id: uuid.UUID,
        db_session,
        budget_guard: BudgetGuard,
        ai_model: str,
    ):
        self._client = client
        self._scan_run_id = scan_run_id
        self._agent_job_id = agent_job_id
        self._session = db_session
        self._budget_guard = budget_guard
        self._ai_model = ai_model
        self.budget_exceeded = False
        self.budget_stop_reason: str | None = None

    async def run(
        self, discovered_responses: dict[str, httpx.Response], forms: list[FormInfo]
    ) -> list[ReviewCandidate]:
        signals = detect_from_cookies(discovered_responses) + detect_from_forms(forms)
        candidates: list[ReviewCandidate] = []
        for signal in signals:
            candidates.append(await self._persist(signal))
        return candidates

    async def _triage(self, signal: SerializationSignal) -> tuple[str, str]:
        """Returns (llm_reasoning, llm_confidence) — falls back to the
        old static template text if the budget's exhausted or the model
        response doesn't parse, same fail-safe discipline as every other
        triage call (app.ai.verdict.parse_verdict never guesses)."""
        fallback_reasoning = (
            f"Deterministic pattern match against a known {signal.kind} serialization "
            "signature — not independently confirmed. Active deserialization exploitation "
            "isn't automated (§1.2 safe-by-default: a gadget chain is target-specific and "
            "can be destructive), so this needs manual review to assess exploitability."
        )
        if self.budget_exceeded:
            return fallback_reasoning, "medium"
        messages = render_prompt(
            "deterministic_signal_triage",
            check_type=f"insecure deserialization ({signal.kind})",
            url=signal.endpoint,
            deterministic_signal=(
                f"A {signal.source} value matches the known {signal.kind} serialized-object "
                f"byte signature: {signal.sample!r}"
            ),
            evidence_before="(passive observation — no probe was sent, this is naturally-occurring traffic)",
            evidence_after=f"sample value: {signal.sample}",
        )
        try:
            response = await self._budget_guard.guarded_complete(messages, model=self._ai_model)
        except (BudgetExceededError, ProviderUnavailableError) as exc:
            self.budget_exceeded = True
            self.budget_stop_reason = (
                "provider_unavailable" if isinstance(exc, ProviderUnavailableError) else "budget_exceeded"
            )
            return fallback_reasoning, "medium"
        verdict = parse_verdict(response.content)
        if verdict is None:
            return fallback_reasoning, "medium"
        return verdict.reasoning, verdict.confidence

    async def _persist(self, signal: SerializationSignal) -> ReviewCandidate:
        llm_reasoning, llm_confidence = await self._triage(signal)
        candidate = ReviewCandidate(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_type="potential-insecure-deserialization",
            title=f"Potential {signal.kind} Serialized Object Observed ({signal.source})",
            severity_guess="Low",
            affected_endpoint=signal.endpoint,
            request_raw=f"(passive observation — not an active probe) {signal.source} at {signal.endpoint}",
            response_raw=f"sample value: {signal.sample}",
            llm_reasoning=llm_reasoning,
            llm_confidence=llm_confidence,
            status="pending",
        )
        async with self._client.session_lock:
            self._session.add(candidate)
            await self._session.commit()
        return candidate
