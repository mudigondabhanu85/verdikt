"""CORS misconfiguration (§3) — deterministic checks: does the
application reflect an arbitrary Origin back into
Access-Control-Allow-Origin (worst case, combined with
Access-Control-Allow-Credentials: true — lets any website make
authenticated cross-origin requests and read the response), or serve a
blanket wildcard ACAO that's worth flagging for review?
"""

import uuid

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.finding import Evidence, Finding

_CATALOG_FILE = "cors_catalog.yaml"
_FORGED_ORIGIN = "https://verdikt-cors-test.invalid"


def _classify(response: httpx.Response) -> str | None:
    acao = response.headers.get("access-control-allow-origin")
    if acao is None:
        return None
    if acao == _FORGED_ORIGIN:
        acac = response.headers.get("access-control-allow-credentials", "").lower()
        if acac == "true":
            return "cors-reflected-origin-with-credentials"
        return None  # reflects an arbitrary origin but without credentials — not exploitable the same way
    if acao == "*":
        return "cors-wildcard-origin"
    return None


class CorsAgent:
    """No LLM needed — both checks are binary response-header
    inspections (§1.2 safe-by-default: one extra GET per host,
    read-only)."""

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

    async def run(self, endpoints: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        seen_hosts: set[str] = set()
        for url in endpoints:
            host = httpx.URL(url).host
            if host in seen_hosts:
                continue
            seen_hosts.add(host)
            finding = await self._check_endpoint(url)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _check_endpoint(self, url: str) -> Finding | None:
        try:
            probe = await self._client.get(url, extra_headers={"Origin": _FORGED_ORIGIN})
        except (ScopeViolationError, httpx.HTTPError):
            return None
        check_id = _classify(probe)
        if check_id is None:
            return None

        # §2 step 1: deterministic re-execution before confirming.
        try:
            probe_again = await self._client.get(url, extra_headers={"Origin": _FORGED_ORIGIN})
        except (ScopeViolationError, httpx.HTTPError):
            return None
        if _classify(probe_again) != check_id:
            return None

        check_def = get_check(check_id, filename=_CATALOG_FILE)
        extra = {"forged_origin": _FORGED_ORIGIN}
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id=check_id,
            title=check_def.title,
            severity=check_def.severity,
            owasp_2025_category=check_def.owasp_2025_category,
            cwe_id=check_def.cwe_id,
            portswigger_reference_url=check_def.portswigger_reference_url,
            cvss_vector=check_def.cvss_vector,
            cvss_score=check_def.cvss_score,
            affected_endpoints=[url],
            plain_language_summary=check_def.plain_language_summary,
            technical_description=render_check_template(check_def.technical_description, url, extra),
            steps_to_reproduce=[
                f'1. Send a GET request to {url} with the header "Origin: {_FORGED_ORIGIN}".',
                "2. Inspect the Access-Control-Allow-Origin (and "
                "Access-Control-Allow-Credentials) response headers and observe the "
                "misconfiguration described above.",
            ],
            remediation=check_def.remediation,
            references=[*check_def.references, check_def.portswigger_reference_url],
            confirmation_status="ai_confirmed",
        )
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()
            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=format_request_raw(probe_again),
                    response_raw=format_response_raw(probe_again),
                )
            )
            await self._session.commit()
        return finding
