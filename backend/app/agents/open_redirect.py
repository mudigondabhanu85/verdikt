"""Open HTTP Redirect detection (§3, item 1) — for each discovered
parameter that looks redirect-shaped by name, substitutes a URL pointing
at an external, non-existent domain and confirms the finding only if the
target's own response actually redirects there (a real Location header
we can point at, not a guess based on the parameter's name alone).
"""

import uuid

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.evidence_screenshot import capture_and_store_evidence_screenshot
from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.agents.probing import ProbeTarget, fetch_with_value, form_probe_targets, query_probe_targets
from app.agents.recon import DiscoveredParameter, FormInfo
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.finding import Evidence, Finding

_CATALOG_FILE = "open_redirect_catalog.yaml"
_REDIRECT_PARAM_NAME_MARKERS = (
    "redirect",
    "redir",
    "url",
    "uri",
    "next",
    "return",
    "returnurl",
    "return_to",
    "continue",
    "dest",
    "destination",
    "target",
    "goto",
    "forward",
    "out",
    "link",
)
_EXTERNAL_TARGET = "https://verdikt-redirect-test.invalid/"
_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)


def _looks_redirect_shaped(param_name: str) -> bool:
    lowered = param_name.lower()
    return any(marker in lowered for marker in _REDIRECT_PARAM_NAME_MARKERS)


def _redirects_to_external_target(response: httpx.Response) -> bool:
    if response.status_code not in _REDIRECT_STATUS_CODES:
        return False
    location = response.headers.get("location", "")
    return location.startswith(_EXTERNAL_TARGET)


class OpenRedirectAgent:
    """No LLM needed — a single deterministic differential (§1.2
    safe-by-default: one GET/POST substitution per candidate parameter,
    never actually navigates a browser to the attacker URL)."""

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
        self, parameters: list[DiscoveredParameter], forms: list[FormInfo]
    ) -> list[Finding]:
        targets = [
            t
            for t in query_probe_targets(parameters) + form_probe_targets(forms)
            if _looks_redirect_shaped(t.param_name)
        ]
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        for target in targets:
            key = (target.url, target.method, target.param_name)
            if key in seen:
                continue
            seen.add(key)
            finding = await self._check_target(target)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _probe(self, target: ProbeTarget) -> httpx.Response | None:
        try:
            response = await fetch_with_value(self._client, target, _EXTERNAL_TARGET)
        except (ScopeViolationError, httpx.HTTPError):
            return None
        if not _redirects_to_external_target(response):
            return None
        return response

    async def _check_target(self, target: ProbeTarget) -> Finding | None:
        first = await self._probe(target)
        if first is None:
            return None

        # §2 step 1: deterministic re-execution before confirming.
        second = await self._probe(target)
        if second is None:
            return None

        check_def = get_check("open-redirect-confirmed", filename=_CATALOG_FILE)
        extra = {"parameter": target.param_name}
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="open-redirect-confirmed",
            title=check_def.title,
            severity=check_def.severity,
            owasp_2025_category=check_def.owasp_2025_category,
            cwe_id=check_def.cwe_id,
            portswigger_reference_url=check_def.portswigger_reference_url,
            cvss_vector=check_def.cvss_vector,
            cvss_score=check_def.cvss_score,
            affected_endpoints=[target.url],
            plain_language_summary=check_def.plain_language_summary,
            technical_description=render_check_template(
                check_def.technical_description, target.url, extra
            ),
            steps_to_reproduce=[
                f"1. Set the '{target.param_name}' parameter on {target.url} to an external "
                f'URL (e.g. "{_EXTERNAL_TARGET}").',
                "2. Observe the response is an HTTP redirect (3xx) whose Location header "
                "points at that exact external URL, with no same-site/allow-list check.",
            ],
            remediation=check_def.remediation,
            references=[*check_def.references, check_def.portswigger_reference_url],
            confirmation_status="ai_confirmed",
        )
        request_raw = format_request_raw(second)
        response_raw = format_response_raw(second)
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
                    payload=_EXTERNAL_TARGET,
                    screenshot_refs=screenshot_refs,
                    additional_notes=(
                        "Confirmed via a real 3xx response whose Location header echoed the "
                        "external URL substituted into the parameter above — see request/"
                        "response above."
                    ),
                )
            )
            await self._session.commit()
        return finding
