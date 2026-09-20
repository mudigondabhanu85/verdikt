"""Host header injection (§3) — deterministic check: does the
application trust the client-supplied Host header when building
absolute URLs in its response (password-reset links, canonical URLs,
redirect Location headers) instead of a fixed server-side hostname? If
so, an attacker can poison those URLs to point at an attacker-controlled
domain — e.g. in a password-reset email a victim receives.
"""

import uuid

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.evidence_screenshot import capture_and_store_evidence_screenshot
from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.finding import Evidence, Finding

_CATALOG_FILE = "host_header_catalog.yaml"
_FORGED_HOST = "verdikt-host-header-test.invalid"


def _forged_host_reflected(response: httpx.Response) -> bool:
    if _FORGED_HOST in (response.text or ""):
        return True
    return _FORGED_HOST in response.headers.get("location", "")


class HostHeaderAgent:
    """No LLM needed — a single binary, deterministic check (§1.2
    safe-by-default: one extra GET per endpoint, read-only, no
    state-changing payloads)."""

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
                # One confirmed/rejected result per distinct host is
                # enough signal — this is a hostname-generation behavior,
                # not a per-endpoint one, so testing every single
                # discovered path on the same host adds requests without
                # adding information.
                continue
            seen_hosts.add(host)
            finding = await self._check_endpoint(url)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _check_endpoint(self, url: str) -> Finding | None:
        try:
            probe = await self._client.get(url, extra_headers={"Host": _FORGED_HOST})
        except (ScopeViolationError, httpx.HTTPError):
            return None
        if not _forged_host_reflected(probe):
            return None

        # §2 step 1: deterministic re-execution before confirming.
        try:
            probe_again = await self._client.get(url, extra_headers={"Host": _FORGED_HOST})
        except (ScopeViolationError, httpx.HTTPError):
            return None
        if not _forged_host_reflected(probe_again):
            return None

        check_def = get_check("host-header-injection", filename=_CATALOG_FILE)
        extra = {"forged_host": _FORGED_HOST}
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="host-header-injection",
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
                f"1. Send a GET request to {url} with the Host header set to an "
                f'attacker-controlled value (e.g. "{_FORGED_HOST}").',
                "2. Observe that value reflected back in the response body or a "
                "redirect Location header, instead of the request being rejected "
                "or a fixed hostname being used.",
            ],
            remediation=check_def.remediation,
            references=[*check_def.references, check_def.portswigger_reference_url],
            confirmation_status="ai_confirmed",
        )
        request_raw = format_request_raw(probe_again)
        response_raw = format_response_raw(probe_again)
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
                    payload=_FORGED_HOST,
                    screenshot_refs=screenshot_refs,
                )
            )
            await self._session.commit()
        return finding
