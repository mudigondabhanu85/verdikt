import uuid
from dataclasses import dataclass

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient, ScopeViolationError
from app.agents.probing import ProbeTarget, fetch_with_value, form_probe_targets, query_probe_targets
from app.agents.recon import DiscoveredParameter, FormInfo
from app.agents.xss_browser_proof import attempt_browser_proof
from app.ai.budget import BudgetExceededError, BudgetGuard
from app.ai.prompts.loader import render_prompt
from app.ai.verdict import parse_verdict
from app.models.finding import Evidence, Finding
from app.models.review_candidate import ReviewCandidate
from app.storage.local_disk import get_object_storage

_CONTEXT_RADIUS = 80

# Shared with app.api.routes.review_candidates' manual-promotion path —
# a browser-confirmed reflected XSS and an analyst-promoted one describe
# the same vulnerability class, so they share one taxonomy entry.
XSS_FINDING_METADATA = {
    "owasp_2025_category": "A05 Injection",
    "cwe_id": "CWE-79",
    "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "cvss_score": 6.1,
    "portswigger_reference_url": "https://portswigger.net/web-security/cross-site-scripting",
    "remediation": (
        "Encode all user-controllable output for the context it's rendered in "
        "(HTML entity encoding for HTML body content, JS string escaping inside "
        "script contexts, etc.), and add a Content-Security-Policy as "
        "defense in depth."
    ),
}


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


async def _probe_reflected_xss(
    client: ScopedHttpClient, target: ProbeTarget, session: AuthenticatedSession | None = None
) -> XssCandidate | None:
    marker = _marker_for()
    payload = f"<{marker}>alert(1)</{marker}>"
    probe = await fetch_with_value(client, target, payload, session)
    context = _reflection_context(probe.text, f"<{marker}>")
    if context is None:
        return None
    return XssCandidate(target=target, payload=payload, reflection_context=context, probe_response=probe)


class XSSAgent:
    """Reflected-XSS detection. A GET-based candidate that survives
    deterministic re-execution and LLM triage gets one more step — a real
    headless-browser load to check whether the injected script actually
    executes (§2 step 2, app.agents.xss_browser_proof) — and is persisted
    straight as a confirmed Finding (with a screenshot as evidence) when
    it does. A POST-based candidate, or a GET one where the browser
    didn't execute the payload (e.g. blocked by CSP), still becomes a
    ReviewCandidate for manual analyst review, same as before.
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
        self.findings: list[Finding] = []
        self._auth_session: AuthenticatedSession | None = None

    async def run(
        self,
        parameters: list[DiscoveredParameter],
        forms: list[FormInfo],
        sessions: dict[uuid.UUID, AuthenticatedSession] | None = None,
    ) -> list[ReviewCandidate]:
        # See app.agents.injection.InjectionAgent.run's identical fix —
        # a real, significant bug found live against DVWA: these probes
        # never carried any session at all before this, silently running
        # fully unauthenticated regardless of how vulnerable a
        # login-gated page actually was.
        self._auth_session = next(iter((sessions or {}).values()), None)
        targets = query_probe_targets(parameters) + form_probe_targets(forms)
        candidates: list[ReviewCandidate] = []

        for target in targets:
            if self.budget_exceeded:
                break
            try:
                candidate = await _probe_reflected_xss(self._client, target, self._auth_session)
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
        reproduced = await _probe_reflected_xss(self._client, candidate.target, self._auth_session)
        if reproduced is None:
            return None

        if reproduced.target.method == "GET":
            proof = await attempt_browser_proof(reproduced.target)
            if proof.executed:
                finding = await self._persist_confirmed_finding(reproduced, verdict, proof)
                self.findings.append(finding)
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

    async def _persist_confirmed_finding(self, reproduced: XssCandidate, verdict, proof) -> Finding:
        screenshot_refs: list[str] = []
        if proof.screenshot_png is not None:
            storage = get_object_storage()
            key = f"xss-browser-proof/{self._scan_run_id}/{uuid.uuid4().hex}.png"
            await storage.put(key, proof.screenshot_png, content_type="image/png")
            # Store the raw key, not url_for(key) — screenshot_refs must
            # stay something ObjectStorageAdapter.get() can read back
            # directly (see app.reporting.screenshots), and url_for()'s
            # return value is a display/locator string that isn't
            # guaranteed to double as a valid get() key for every adapter.
            screenshot_refs = [key]

        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="xss-reflected",
            title="Reflected Cross-Site Scripting (XSS)",
            severity="High",
            owasp_2025_category=XSS_FINDING_METADATA["owasp_2025_category"],
            cwe_id=XSS_FINDING_METADATA["cwe_id"],
            portswigger_reference_url=XSS_FINDING_METADATA["portswigger_reference_url"],
            cvss_vector=XSS_FINDING_METADATA["cvss_vector"],
            cvss_score=XSS_FINDING_METADATA["cvss_score"],
            affected_endpoints=[reproduced.target.url],
            plain_language_summary=(
                "This page reflects part of the web address back into the page without "
                "removing dangerous characters. A malicious link built with a script "
                "payload was automatically loaded in a real browser and the script "
                "actually ran, confirming an attacker-controlled link can execute "
                "arbitrary JavaScript in a victim's browser session."
            ),
            technical_description=(
                f"The parameter {reproduced.target.param_name!r} on "
                f"{reproduced.target.url} is reflected unescaped into the HTML "
                f"response. A headless browser loaded a request containing an "
                f"injected <script> payload and the payload executed, which is "
                f"direct proof of exploitability rather than just string reflection. "
                f"LLM triage reasoning: {verdict.reasoning}"
            ),
            steps_to_reproduce=[
                f"1. Send an HTTP GET request to {reproduced.target.url} with "
                f"{reproduced.target.param_name}=<script>alert(1)</script> "
                "(or open it directly in a browser).",
                "2. The injected script executes on page load — verified here by an "
                "automated headless-browser check, with a screenshot captured as "
                "evidence.",
            ],
            remediation=XSS_FINDING_METADATA["remediation"],
            references=[XSS_FINDING_METADATA["portswigger_reference_url"]],
            confirmation_status="ai_confirmed",
        )
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()
            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=format_request_raw(reproduced.probe_response),
                    response_raw=format_response_raw(reproduced.probe_response),
                    screenshot_refs=screenshot_refs,
                )
            )
            await self._session.commit()
        return finding
