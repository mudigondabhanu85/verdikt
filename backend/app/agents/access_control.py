import re
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.agents.matrix import Identity, build_identities
from app.ai.budget import BudgetExceededError, BudgetGuard
from app.ai.prompts.loader import render_prompt
from app.ai.verdict import parse_verdict
from app.models.finding import Evidence, Finding

_TRUNCATE = 2000
_NUMERIC_ID_RE = re.compile(r"^\d+$")

_ACCESS_CONTROL_METADATA = {
    "vertical": {
        "title": "Broken Access Control (Vertical Privilege Escalation)",
        "owasp_2025_category": "A01 Broken Access Control",
        "cwe_id": "CWE-284",
        "severity": "Critical",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cvss_score": 9.1,
        "portswigger_reference_url": "https://portswigger.net/web-security/access-control",
        "plain_language_summary": (
            "An unauthenticated visitor appears to be able to access something that "
            "should require being logged in, getting essentially the same response a "
            "logged-in user would."
        ),
        "remediation": (
            "Enforce authentication and authorization checks server-side on every "
            "request to this endpoint — never rely on the client (e.g. hiding a UI "
            "element) to restrict access."
        ),
    },
    "horizontal": {
        "title": "Insecure Direct Object Reference (IDOR)",
        "owasp_2025_category": "A01 Broken Access Control",
        "cwe_id": "CWE-639",
        "severity": "High",
        "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "cvss_score": 8.1,
        "portswigger_reference_url": "https://portswigger.net/web-security/access-control/idor",
        "plain_language_summary": (
            "A logged-in user appears able to access another user's data just by "
            "changing an ID in the URL, without any ownership check on the server."
        ),
        "remediation": (
            "Verify server-side that the authenticated identity actually owns or is "
            "entitled to the specific resource ID being requested, on every request "
            "— not just that they are logged in."
        ),
    },
}


@dataclass
class AccessControlCandidate:
    comparison_type: str  # "vertical" or "horizontal"
    endpoint: str
    original_endpoint: str
    identity_a: Identity
    identity_b: Identity
    response_a: httpx.Response
    response_b: httpx.Response
    deterministic_signal: str


def _find_numeric_id_segment(url: str) -> tuple[int, str] | None:
    segments = urlsplit(url).path.split("/")
    for index in range(len(segments) - 1, -1, -1):
        if _NUMERIC_ID_RE.match(segments[index]):
            return index, segments[index]
    return None


def _substitute_path_segment(url: str, index: int, new_value: str) -> str:
    parsed = urlsplit(url)
    segments = parsed.path.split("/")
    segments[index] = new_value
    return urlunsplit((parsed.scheme, parsed.netloc, "/".join(segments), parsed.query, ""))


def _nearby_ids(value: str) -> list[str]:
    n = int(value)
    return [str(candidate) for candidate in (n - 1, n + 1) if candidate >= 0 and str(candidate) != value]


def _similar_length(a: int, b: int, *, tolerance: float = 0.1, floor: int = 20) -> bool:
    return abs(a - b) <= max(floor, tolerance * max(a, b, 1))


async def _detect_vertical(
    client: ScopedHttpClient, endpoint: str, identities: list[Identity]
) -> AccessControlCandidate | None:
    unauth = next((i for i in identities if i.session is None), None)
    authed = [i for i in identities if i.session is not None]
    if unauth is None or not authed:
        return None
    try:
        unauth_resp = await client.get(endpoint, session=None)
    except (ScopeViolationError, httpx.HTTPError):
        return None
    if unauth_resp.status_code >= 400:
        return None

    for identity in authed:
        try:
            auth_resp = await client.get(endpoint, session=identity.session)
        except (ScopeViolationError, httpx.HTTPError):
            continue
        if auth_resp.status_code >= 400:
            continue
        if _similar_length(len(unauth_resp.text), len(auth_resp.text)):
            return AccessControlCandidate(
                comparison_type="vertical",
                endpoint=endpoint,
                original_endpoint=endpoint,
                identity_a=unauth,
                identity_b=identity,
                response_a=unauth_resp,
                response_b=auth_resp,
                deterministic_signal=(
                    f"Unauthenticated response ({len(unauth_resp.text)} bytes, status "
                    f"{unauth_resp.status_code}) is nearly identical in size to the "
                    f"{identity.label} response ({len(auth_resp.text)} bytes, status "
                    f"{auth_resp.status_code}) to the same endpoint."
                ),
            )
    return None


async def _detect_horizontal(
    client: ScopedHttpClient, endpoint: str, identities: list[Identity]
) -> AccessControlCandidate | None:
    id_info = _find_numeric_id_segment(endpoint)
    if id_info is None:
        return None
    index, value = id_info
    authed = [i for i in identities if i.session is not None]

    for identity in authed:
        try:
            original_resp = await client.get(endpoint, session=identity.session)
        except (ScopeViolationError, httpx.HTTPError):
            continue
        if original_resp.status_code >= 300:
            continue
        for candidate_id in _nearby_ids(value):
            alt_url = _substitute_path_segment(endpoint, index, candidate_id)
            try:
                alt_resp = await client.get(alt_url, session=identity.session)
            except (ScopeViolationError, httpx.HTTPError):
                continue
            if alt_resp.status_code < 300 and len(alt_resp.text) > 20:
                return AccessControlCandidate(
                    comparison_type="horizontal",
                    endpoint=alt_url,
                    original_endpoint=endpoint,
                    identity_a=identity,
                    identity_b=identity,
                    response_a=original_resp,
                    response_b=alt_resp,
                    deterministic_signal=(
                        f"{identity.label} was able to fetch {alt_url} — an adjacent "
                        f"resource ID to {endpoint}, which the same identity legitimately "
                        f"owns — and received a successful, substantive response "
                        f"({len(alt_resp.text)} bytes, status {alt_resp.status_code})."
                    ),
                )
    return None


async def _reexecute(
    client: ScopedHttpClient, candidate: AccessControlCandidate
) -> AccessControlCandidate | None:
    try:
        if candidate.comparison_type == "vertical":
            response_a = await client.get(candidate.endpoint, session=None)
            response_b = await client.get(candidate.endpoint, session=candidate.identity_b.session)
            if response_a.status_code >= 400 or response_b.status_code >= 400:
                return None
            if not _similar_length(len(response_a.text), len(response_b.text)):
                return None
        else:
            response_a = await client.get(candidate.original_endpoint, session=candidate.identity_a.session)
            response_b = await client.get(candidate.endpoint, session=candidate.identity_b.session)
            if response_a.status_code >= 300 or response_b.status_code >= 300 or len(response_b.text) <= 20:
                return None
    except (ScopeViolationError, httpx.HTTPError):
        return None

    return AccessControlCandidate(
        comparison_type=candidate.comparison_type,
        endpoint=candidate.endpoint,
        original_endpoint=candidate.original_endpoint,
        identity_a=candidate.identity_a,
        identity_b=candidate.identity_b,
        response_a=response_a,
        response_b=response_b,
        deterministic_signal=candidate.deterministic_signal,
    )


class AccessControlAgent:
    """Matrix-driven (§5): fetches each discovered endpoint as every
    identity, deterministically flags divergences, then routes every
    candidate through the same triage -> re-execution (§2 step 1) ->
    adversarial-validation (§2 step 3) pipeline as Injection — server-side
    and re-fetchable, so these can be real ai_confirmed Findings.
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
        self,
        endpoints: list[str],
        sessions,
        credential_labels: dict[uuid.UUID, str],
    ) -> list[Finding]:
        identities = build_identities(sessions, credential_labels)
        findings: list[Finding] = []

        for endpoint in endpoints:
            if self.budget_exceeded:
                break
            for detect in (_detect_vertical, _detect_horizontal):
                candidate = await detect(self._client, endpoint, identities)
                if candidate is None:
                    continue
                try:
                    finding = await self._triage_and_confirm(candidate)
                except BudgetExceededError:
                    self.budget_exceeded = True
                    break
                if finding is not None:
                    findings.append(finding)

        return findings

    async def _triage_and_confirm(self, candidate: AccessControlCandidate) -> Finding | None:
        messages = render_prompt(
            "access_control_triage",
            url=candidate.endpoint,
            comparison_type=candidate.comparison_type,
            identity_a_label=candidate.identity_a.label,
            identity_b_label=candidate.identity_b.label,
            response_a=format_response_raw(candidate.response_a)[:_TRUNCATE],
            response_b=format_response_raw(candidate.response_b)[:_TRUNCATE],
            deterministic_signal=candidate.deterministic_signal,
        )
        response = await self._budget_guard.guarded_complete(messages, model=self._ai_model)
        verdict = parse_verdict(response.content)
        if verdict is None or not verdict.vulnerable:
            return None

        reproduced = await _reexecute(self._client, candidate)
        if reproduced is None:
            return None

        validation_messages = render_prompt(
            "access_control_validation",
            url=reproduced.endpoint,
            comparison_type=reproduced.comparison_type,
            identity_a_label=reproduced.identity_a.label,
            identity_b_label=reproduced.identity_b.label,
            prior_reasoning=verdict.reasoning,
            response_a=format_response_raw(reproduced.response_a)[:_TRUNCATE],
            response_b=format_response_raw(reproduced.response_b)[:_TRUNCATE],
        )
        validation_response = await self._budget_guard.guarded_complete(
            validation_messages, model=self._ai_model
        )
        validation_verdict = parse_verdict(validation_response.content)
        if validation_verdict is None or not validation_verdict.vulnerable:
            return None

        return await self._persist(reproduced, validation_verdict)

    async def _persist(self, candidate: AccessControlCandidate, validation_verdict) -> Finding:
        meta = _ACCESS_CONTROL_METADATA[candidate.comparison_type]
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id=f"access-control-{candidate.comparison_type}",
            title=meta["title"],
            severity=meta["severity"],
            owasp_2025_category=meta["owasp_2025_category"],
            cwe_id=meta["cwe_id"],
            portswigger_reference_url=meta["portswigger_reference_url"],
            cvss_vector=meta["cvss_vector"],
            cvss_score=meta["cvss_score"],
            affected_endpoints=[candidate.endpoint],
            plain_language_summary=meta["plain_language_summary"],
            technical_description=(
                f"{candidate.deterministic_signal} An independent adversarial review "
                f"attempted to disprove this and could not: {validation_verdict.reasoning}"
            ),
            steps_to_reproduce=[
                f"1. Authenticate as {candidate.identity_a.label}.",
                f"2. Send a GET request to {candidate.endpoint}.",
                f"3. Observe: {candidate.deterministic_signal}",
            ],
            remediation=meta["remediation"],
            references=[meta["portswigger_reference_url"]],
            confirmation_status="ai_confirmed",
        )
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()

            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=format_request_raw(candidate.response_b),
                    response_raw=format_response_raw(candidate.response_b),
                )
            )
            await self._session.commit()
        return finding
