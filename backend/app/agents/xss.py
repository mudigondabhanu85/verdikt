import uuid
from dataclasses import dataclass

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.agents.probing import ProbeTarget, fetch_with_value, form_probe_targets, query_probe_targets
from app.agents.recon import DiscoveredParameter, FormInfo
from app.ai.budget import BudgetExceededError, BudgetGuard
from app.ai.prompts.loader import render_prompt
from app.ai.verdict import parse_verdict
from app.models.review_candidate import ReviewCandidate

_CONTEXT_RADIUS = 80


@dataclass
class XssCandidate:
    target: ProbeTarget
    payload: str
    reflection_context: str
    probe_response: httpx.Response


def _marker_for() -> str:
    return f"vxss{uuid.uuid4().hex[:8]}"


def _reflection_context(text: str, marker: str) -> str | None:
    index = text.find(marker)
    if index == -1:
        return None
    start = max(0, index - _CONTEXT_RADIUS)
    end = min(len(text), index + len(marker) + _CONTEXT_RADIUS)
    return text[start:end]


async def _probe_reflected_xss(client: ScopedHttpClient, target: ProbeTarget) -> XssCandidate | None:
    marker = _marker_for()
    payload = f"<{marker}>alert(1)</{marker}>"
    probe = await fetch_with_value(client, target, payload)
    context = _reflection_context(probe.text, f"<{marker}>")
    if context is None:
        return None
    return XssCandidate(target=target, payload=payload, reflection_context=context, probe_response=probe)


class XSSAgent:
    """Reflected-XSS detection. Unlike Injection/Access-Control, a
    confirmed candidate here becomes a ReviewCandidate, not a Finding —
    §2 step 2 requires actual Playwright browser reproduction for
    client-side issues, which is Phase 5 scope. This agent still does
    deterministic re-execution (§2 step 1: re-probe, confirm the
    reflection reproduces) before queuing a candidate, but stops short of
    the full Finding-confirmation pipeline.
    """

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

    async def run(
        self, parameters: list[DiscoveredParameter], forms: list[FormInfo]
    ) -> list[ReviewCandidate]:
        targets = query_probe_targets(parameters) + form_probe_targets(forms)
        candidates: list[ReviewCandidate] = []

        for target in targets:
            if self.budget_exceeded:
                break
            try:
                candidate = await _probe_reflected_xss(self._client, target)
            except (ScopeViolationError, httpx.HTTPError):
                continue
            if candidate is None:
                continue
            try:
                review_candidate = await self._triage_and_queue(candidate)
            except BudgetExceededError:
                self.budget_exceeded = True
                break
            if review_candidate is not None:
                candidates.append(review_candidate)

        return candidates

    async def _triage_and_queue(self, candidate: XssCandidate) -> ReviewCandidate | None:
        messages = render_prompt(
            "xss_triage",
            url=candidate.target.url,
            parameter=candidate.target.param_name,
            payload=candidate.payload,
            reflection_context=candidate.reflection_context,
        )
        response = await self._budget_guard.guarded_complete(messages, model=self._ai_model)
        verdict = parse_verdict(response.content)
        if verdict is None or not verdict.vulnerable:
            return None

        # §2 step 1: deterministic re-execution before queuing.
        reproduced = await _probe_reflected_xss(self._client, candidate.target)
        if reproduced is None:
            return None

        review_candidate = ReviewCandidate(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_type="xss-reflected",
            title="Possible Reflected Cross-Site Scripting (XSS)",
            severity_guess="High",
            affected_endpoint=reproduced.target.url,
            request_raw=format_request_raw(reproduced.probe_response),
            response_raw=format_response_raw(reproduced.probe_response),
            llm_reasoning=verdict.reasoning,
            llm_confidence=verdict.confidence,
            status="pending",
        )
        async with self._client.session_lock:
            self._session.add(review_candidate)
            await self._session.commit()
        return review_candidate
