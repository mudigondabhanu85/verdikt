import asyncio
import uuid
from dataclasses import dataclass
from typing import Awaitable, Callable

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.evidence_screenshot import capture_and_store_evidence_screenshot
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient, ScopeViolationError
from app.agents.idor import (
    find_numeric_id_segment,
    find_query_identifier,
    nearby_ids,
    sibling_values,
    substitute_path_segment,
    substitute_query_param,
)
from app.agents.matrix import Identity, build_identities
from app.ai.budget import BudgetExceededError, BudgetGuard, ProviderUnavailableError
from app.ai.prompts.loader import render_prompt
from app.ai.verdict import parse_verdict
from app.models.business_rule import BusinessRule
from app.models.finding import Evidence, Finding

_TRUNCATE = 2000
_DEFAULT_TAMPER_VALUES = ("-1", "0", "0.01", "999999999")

_BUSINESS_LOGIC_METADATA = {
    "resource_isolation": {
        "title": "Broken Access Control (Business-Rule IDOR)",
        "owasp_2025_category": "A06 Insecure Design",
        "cwe_id": "CWE-639",
        "severity": "High",
        "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "cvss_score": 8.1,
        "portswigger_reference_url": "https://portswigger.net/web-security/access-control/idor",
        "plain_language_summary": (
            "A logged-in user appears able to access another user's data just by "
            "changing an ID, violating a business rule the analyst explicitly flagged "
            "as something that should never be possible."
        ),
        "remediation": (
            "Verify server-side that the authenticated identity actually owns or is "
            "entitled to the specific resource ID being requested, on every request."
        ),
    },
    "workflow_order": {
        "title": "Workflow Step Bypass",
        "owasp_2025_category": "A06 Insecure Design",
        "cwe_id": "CWE-841",
        "severity": "High",
        "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "cvss_score": 8.2,
        "portswigger_reference_url": None,
        "plain_language_summary": (
            "A multi-step process can be completed out of order — a later step "
            "succeeded without its required earlier step being completed first."
        ),
        "remediation": (
            "Track workflow state server-side and reject any request for a step "
            "whose prerequisites have not actually been completed for this session/"
            "resource — never rely on the client to call steps in the right order."
        ),
    },
    "price_or_quantity_tampering": {
        "title": "Client-Controlled Price or Quantity",
        "owasp_2025_category": "A06 Insecure Design",
        "cwe_id": "CWE-840",
        "severity": "High",
        "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "cvss_score": 8.2,
        "portswigger_reference_url": None,
        "plain_language_summary": (
            "This endpoint appears to accept an out-of-range value (e.g. negative or "
            "zero price/quantity) from the client instead of validating or "
            "recalculating it server-side."
        ),
        "remediation": (
            "Never trust price, quantity, or total values submitted by the client — "
            "recompute and validate them server-side from trusted data on every request."
        ),
    },
    "race_condition_limited_use": {
        "title": "Race Condition on Limited-Use Resource",
        "owasp_2025_category": "A06 Insecure Design",
        "cwe_id": "CWE-362",
        "severity": "Medium",
        "cvss_vector": "AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "cvss_score": 6.5,
        "portswigger_reference_url": "https://portswigger.net/web-security/race-conditions",
        "plain_language_summary": (
            "Firing several identical requests to this endpoint at the same time let "
            "more of a limited-use action succeed than should have been possible — a "
            "classic time-of-check/time-of-use race condition."
        ),
        "remediation": (
            "Use a database-level lock, unique constraint, or atomic "
            "check-and-decrement operation to make the limited-use action safe under "
            "concurrent requests."
        ),
    },
}


@dataclass
class BusinessLogicCandidate:
    rule: BusinessRule
    identities: list[Identity]
    deterministic_signal: str
    evidence_response: httpx.Response
    endpoint: str
    # Only set for rule types with a genuine substituted-value payload
    # (resource_isolation's swapped ID, price_or_quantity_tampering's
    # tampered value) — workflow_order and race_condition_limited_use
    # findings differ by *sequence* or *concurrency*, not by any
    # substring in the request itself, so there's nothing honest to set
    # here for those.
    payload: str | None = None


DetectFn = Callable[
    [ScopedHttpClient, BusinessRule, list[Identity]], Awaitable[BusinessLogicCandidate | None]
]


def _resolve_identity(rule: BusinessRule, identities: list[Identity]) -> Identity:
    credential_set_id = rule.config.get("credential_set_id")
    if credential_set_id:
        for identity in identities:
            if identity.credential_set_id and str(identity.credential_set_id) == str(credential_set_id):
                return identity
    return next(i for i in identities if i.session is None)


async def _detect_resource_isolation(
    client: ScopedHttpClient, rule: BusinessRule, identities: list[Identity]
) -> BusinessLogicCandidate | None:
    url = rule.config["url"]
    id_info = find_numeric_id_segment(url)
    if id_info is not None:
        index, value = id_info
        authed = [i for i in identities if i.session is not None]

        for identity in authed:
            try:
                original_resp = await client.get(url, session=identity.session)
            except (ScopeViolationError, httpx.HTTPError):
                continue
            if original_resp.status_code >= 300:
                continue
            for candidate_id in nearby_ids(value):
                alt_url = substitute_path_segment(url, index, candidate_id)
                try:
                    alt_resp = await client.get(alt_url, session=identity.session)
                except (ScopeViolationError, httpx.HTTPError):
                    continue
                if alt_resp.status_code < 300 and len(alt_resp.text) > 20:
                    return BusinessLogicCandidate(
                        rule=rule,
                        identities=identities,
                        deterministic_signal=(
                            f"{identity.label} was able to fetch {alt_url} — an adjacent "
                            f"resource ID to {url} — and received a successful, substantive "
                            f"response ({len(alt_resp.text)} bytes, status {alt_resp.status_code})."
                        ),
                        evidence_response=alt_resp,
                        endpoint=alt_url,
                        payload=alt_url,
                    )
        return None

    # No numeric path segment — real gap found live: a lookup endpoint
    # keyed by a query-string identifier (e.g. "?email=") rather than a
    # REST-style numeric path segment fell straight through the check
    # above with nothing ever tested. Tried across EVERY identity,
    # including the unauthenticated baseline (identities[0], session=
    # None — filtered OUT of `authed` above): a query-parameter-keyed
    # endpoint that returns substantive per-identifier data to a fully
    # anonymous caller is the more severe, at-least-as-common real-world
    # shape (found live: a "/loyalty/points?email=" endpoint returning
    # any customer's balance with zero authentication) that the
    # authenticated-only, path-segment-only check above structurally
    # cannot reach.
    query_id = find_query_identifier(url)
    if query_id is None:
        return None
    name, value = query_id
    for identity in identities:
        try:
            original_resp = await client.get(url, session=identity.session)
        except (ScopeViolationError, httpx.HTTPError):
            continue
        if original_resp.status_code >= 300:
            continue
        for candidate_value in sibling_values(value):
            alt_url = substitute_query_param(url, name, candidate_value)
            try:
                alt_resp = await client.get(alt_url, session=identity.session)
            except (ScopeViolationError, httpx.HTTPError):
                continue
            if alt_resp.status_code < 300 and len(alt_resp.text) > 20:
                who = "An unauthenticated request" if identity.session is None else identity.label
                return BusinessLogicCandidate(
                    rule=rule,
                    identities=identities,
                    deterministic_signal=(
                        f'{who} was able to fetch {alt_url} — the same lookup endpoint as '
                        f'{url}, with only its "{name}" query parameter changed to a value '
                        f"never associated with this request — and received a successful, "
                        f"substantive response ({len(alt_resp.text)} bytes, status "
                        f"{alt_resp.status_code})."
                    ),
                    evidence_response=alt_resp,
                    endpoint=alt_url,
                    payload=alt_url,
                )
    return None


async def _detect_workflow_order(
    client: ScopedHttpClient, rule: BusinessRule, identities: list[Identity]
) -> BusinessLogicCandidate | None:
    identity = _resolve_identity(rule, identities)
    action = rule.config["guarded_action"]
    method = action.get("method", "GET").upper()
    url = action["url"]
    body = action.get("body")
    content_type = action.get("content_type", "application/json") if body else None

    try:
        response = await client.request(
            method, url, body=body, content_type=content_type, session=identity.session
        )
    except (ScopeViolationError, httpx.HTTPError):
        return None

    if response.status_code < 300:
        return BusinessLogicCandidate(
            rule=rule,
            identities=identities,
            deterministic_signal=(
                f"{identity.label} was able to call {method} {url} (the guarded action) "
                f"without first completing its precondition, and received a successful "
                f"response (status {response.status_code})."
            ),
            evidence_response=response,
            endpoint=url,
        )
    return None


async def _detect_price_tampering(
    client: ScopedHttpClient, rule: BusinessRule, identities: list[Identity]
) -> BusinessLogicCandidate | None:
    identity = _resolve_identity(rule, identities)
    method = rule.config.get("method", "POST").upper()
    url = rule.config["url"]
    body_template = rule.config["body_template"]
    content_type = rule.config.get("content_type", "application/json")
    baseline_value = str(rule.config.get("baseline_value", "1"))
    tamper_values = rule.config.get("tamper_values") or _DEFAULT_TAMPER_VALUES

    async def submit(value: str) -> httpx.Response:
        body = body_template.replace("{value}", value)
        return await client.request(method, url, body=body, content_type=content_type, session=identity.session)

    try:
        baseline_resp = await submit(baseline_value)
    except (ScopeViolationError, httpx.HTTPError):
        return None
    if baseline_resp.status_code >= 300:
        return None  # can't even establish a working baseline — skip this rule

    for tamper_value in tamper_values:
        try:
            tampered_resp = await submit(tamper_value)
        except (ScopeViolationError, httpx.HTTPError):
            continue
        if tampered_resp.status_code < 300:
            return BusinessLogicCandidate(
                rule=rule,
                identities=identities,
                deterministic_signal=(
                    f"Submitting {method} {url} with the tampered value '{tamper_value}' "
                    f"(baseline was '{baseline_value}') was accepted (status "
                    f"{tampered_resp.status_code}) instead of being rejected or "
                    f"recalculated server-side."
                ),
                evidence_response=tampered_resp,
                endpoint=url,
                payload=tamper_value,
            )
    return None


async def _detect_race_condition(
    client: ScopedHttpClient, rule: BusinessRule, identities: list[Identity]
) -> BusinessLogicCandidate | None:
    identity = _resolve_identity(rule, identities)
    method = rule.config.get("method", "POST").upper()
    url = rule.config["url"]
    body = rule.config.get("body")
    content_type = rule.config.get("content_type", "application/json") if body else None
    concurrency = int(rule.config.get("concurrency", 10))
    max_allowed = int(rule.config.get("max_allowed_successes", 1))

    async def fire() -> httpx.Response | None:
        try:
            return await client.request(
                method, url, body=body, content_type=content_type, session=identity.session
            )
        except (ScopeViolationError, httpx.HTTPError):
            return None

    responses = await asyncio.gather(*(fire() for _ in range(concurrency)))
    successes = [r for r in responses if r is not None and r.status_code < 300]
    if len(successes) > max_allowed:
        return BusinessLogicCandidate(
            rule=rule,
            identities=identities,
            deterministic_signal=(
                f"Fired {concurrency} concurrent {method} requests to {url} as "
                f"{identity.label}; {len(successes)} succeeded (status < 300), "
                f"exceeding the allowed maximum of {max_allowed}."
            ),
            evidence_response=successes[0],
            endpoint=url,
        )
    return None


_DETECT_FNS: dict[str, DetectFn] = {
    "resource_isolation": _detect_resource_isolation,
    "workflow_order": _detect_workflow_order,
    "price_or_quantity_tampering": _detect_price_tampering,
    "race_condition_limited_use": _detect_race_condition,
}


class BusinessLogicAgent:
    """§3's business-rules questionnaire made executable: each BusinessRule
    an analyst defines maps to one deterministic detector above. Server-
    side and re-fetchable like Injection/Access-Control, so confirmed
    candidates go through the full pipeline — deterministic re-execution
    (§2 step 1) -> LLM triage -> adversarial LLM validation (§2 step 3) ->
    real ai_confirmed Finding.
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
        sessions: dict[uuid.UUID, AuthenticatedSession],
        credential_labels: dict[uuid.UUID, str],
    ):
        self._client = client
        self._scan_run_id = scan_run_id
        self._agent_job_id = agent_job_id
        self._session = db_session
        self._budget_guard = budget_guard
        self._ai_model = ai_model
        self._identities = build_identities(sessions, credential_labels)
        self.budget_exceeded = False
        self.budget_stop_reason: str | None = None

    async def run(self, rules: list[BusinessRule]) -> list[Finding]:
        findings: list[Finding] = []

        for rule in rules:
            if self.budget_exceeded:
                break
            detect_fn = _DETECT_FNS.get(rule.rule_type)
            if detect_fn is None:
                continue
            try:
                candidate = await detect_fn(self._client, rule, self._identities)
            except (ScopeViolationError, httpx.HTTPError, KeyError, ValueError):
                continue
            if candidate is None:
                continue
            try:
                finding = await self._triage_and_confirm(candidate, detect_fn)
            except (BudgetExceededError, ProviderUnavailableError) as exc:
                self.budget_exceeded = True
                self.budget_stop_reason = (
                    "provider_unavailable" if isinstance(exc, ProviderUnavailableError) else "budget_exceeded"
                )
                break
            if finding is not None:
                findings.append(finding)

        return findings

    async def _triage_and_confirm(
        self, candidate: BusinessLogicCandidate, detect_fn: DetectFn
    ) -> Finding | None:
        messages = render_prompt(
            "business_logic_triage",
            rule_type=candidate.rule.rule_type,
            rule_title=candidate.rule.title,
            deterministic_signal=candidate.deterministic_signal,
            evidence=format_response_raw(candidate.evidence_response)[:_TRUNCATE],
        )
        response = await self._budget_guard.guarded_complete(messages, model=self._ai_model)
        verdict = parse_verdict(response.content)
        if verdict is None or not verdict.vulnerable:
            return None

        # §2 step 1: deterministic re-execution — re-run the exact same
        # rule's detector fresh; if it doesn't reproduce, discard silently.
        try:
            reproduced = await detect_fn(self._client, candidate.rule, candidate.identities)
        except (ScopeViolationError, httpx.HTTPError, KeyError, ValueError):
            return None
        if reproduced is None:
            return None

        validation_messages = render_prompt(
            "business_logic_validation",
            rule_type=reproduced.rule.rule_type,
            rule_title=reproduced.rule.title,
            prior_reasoning=verdict.reasoning,
            evidence=format_response_raw(reproduced.evidence_response)[:_TRUNCATE],
        )
        validation_response = await self._budget_guard.guarded_complete(
            validation_messages, model=self._ai_model
        )
        validation_verdict = parse_verdict(validation_response.content)
        if validation_verdict is None or not validation_verdict.vulnerable:
            return None

        return await self._persist(reproduced, validation_verdict)

    async def _persist(self, candidate: BusinessLogicCandidate, validation_verdict) -> Finding:
        meta = _BUSINESS_LOGIC_METADATA[candidate.rule.rule_type]
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id=f"business-logic-{candidate.rule.rule_type}",
            title=f"{meta['title']}: {candidate.rule.title}",
            severity=meta["severity"],
            owasp_2025_category=meta["owasp_2025_category"],
            cwe_id=meta["cwe_id"],
            portswigger_reference_url=meta["portswigger_reference_url"],
            cvss_vector=meta["cvss_vector"],
            cvss_score=meta["cvss_score"],
            affected_endpoints=[candidate.endpoint],
            plain_language_summary=(
                f"{meta['plain_language_summary']} Specifically, this violates the "
                f"business rule: \"{candidate.rule.title}\"."
            ),
            technical_description=(
                f"{candidate.deterministic_signal} An independent adversarial review "
                f"attempted to disprove this and could not: {validation_verdict.reasoning}"
            ),
            steps_to_reproduce=[
                f"1. This finding tests the business rule: \"{candidate.rule.title}\".",
                f"2. {candidate.deterministic_signal}",
            ],
            remediation=meta["remediation"],
            references=[meta["portswigger_reference_url"]] if meta["portswigger_reference_url"] else [],
            confirmation_status="ai_confirmed",
        )
        request_raw = format_request_raw(candidate.evidence_response)
        response_raw = format_response_raw(candidate.evidence_response)
        screenshot_refs = await capture_and_store_evidence_screenshot(
            scan_run_id=self._scan_run_id,
            check_id=finding.check_id,
            title=finding.title,
            request_raw=request_raw,
            response_raw=response_raw,
        )
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()

            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=request_raw,
                    response_raw=response_raw,
                    payload=candidate.payload,
                    screenshot_refs=screenshot_refs,
                )
            )
            await self._session.commit()
        return finding
