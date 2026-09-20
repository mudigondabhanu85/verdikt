"""SSRF (Server-Side Request Forgery) detection via out-of-band callback
(§3) — for each discovered parameter that looks URL-shaped by name,
substitutes a URL pointing back at a local HTTP listener this agent
starts for itself, and confirms the finding only if the target actually
makes a real out-of-band request to it. See app.agents.ssrf_callback for
the honest limitation on when this can work at all.
"""

import asyncio
import socket
import uuid

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.evidence_screenshot import capture_and_store_evidence_screenshot
from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.agents.probing import ProbeTarget, fetch_with_value, form_probe_targets, query_probe_targets
from app.agents.recon import DiscoveredParameter, FormInfo
from app.agents.ssrf_callback import SsrfCallbackServer, callback_url_for
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.config import get_settings
from app.models.finding import Evidence, Finding

_CATALOG_FILE = "ssrf_catalog.yaml"
_URL_PARAM_NAME_MARKERS = (
    "url",
    "uri",
    "link",
    "callback",
    "webhook",
    "redirect",
    "next",
    "image",
    "src",
    "fetch",
    "target",
    "dest",
    "return",
    "path",
    "endpoint",
    "avatar",
)
_CALLBACK_WAIT_SECONDS = 1.5


def _looks_url_shaped(param_name: str) -> bool:
    lowered = param_name.lower()
    return any(marker in lowered for marker in _URL_PARAM_NAME_MARKERS)


def _default_callback_host() -> str:
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


class SsrfAgent:
    """No LLM needed — confirmation is a real callback hit, not a
    heuristic (§1.2 safe-by-default: one outbound URL substitution per
    candidate parameter, read-only from the target's perspective)."""

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
            if _looks_url_shaped(t.param_name)
        ]
        if not targets:
            return []

        callback_host = get_settings().ssrf_callback_host or _default_callback_host()
        server = SsrfCallbackServer()
        server.start()
        try:
            findings: list[Finding] = []
            for target in targets:
                finding = await self._check_target(target, server, callback_host)
                if finding is not None:
                    findings.append(finding)
            return findings
        finally:
            server.shutdown()

    async def _probe(
        self, target: ProbeTarget, server: SsrfCallbackServer, callback_host: str
    ) -> tuple[str, httpx.Response] | None:
        token = server.new_token()
        callback_url = callback_url_for(callback_host, server.port, token)
        try:
            response = await fetch_with_value(self._client, target, callback_url)
        except (ScopeViolationError, httpx.HTTPError):
            return None
        await asyncio.sleep(_CALLBACK_WAIT_SECONDS)
        if not server.was_hit(token):
            return None
        return token, response

    async def _check_target(
        self, target: ProbeTarget, server: SsrfCallbackServer, callback_host: str
    ) -> Finding | None:
        first = await self._probe(target, server, callback_host)
        if first is None:
            return None

        # §2 step 1: deterministic re-execution — a fresh token, fresh
        # callback hit required, not just re-checking the same one.
        second = await self._probe(target, server, callback_host)
        if second is None:
            return None
        _token, response_again = second

        check_def = get_check("ssrf-confirmed", filename=_CATALOG_FILE)
        extra = {"parameter": target.param_name}
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="ssrf-confirmed",
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
                f"1. Set the '{target.param_name}' parameter on {target.url} to a URL you "
                "control (e.g. a request-bin/webhook-testing service, or your own listener).",
                "2. Observe your listener receives a real, independent HTTP request from the "
                "target application shortly afterward.",
            ],
            remediation=check_def.remediation,
            references=[*check_def.references, check_def.portswigger_reference_url],
            confirmation_status="ai_confirmed",
        )
        request_raw = format_request_raw(response_again)
        response_raw = format_response_raw(response_again)
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
                    payload=callback_url_for(callback_host, server.port, _token),
                    screenshot_refs=screenshot_refs,
                    additional_notes=(
                        "Confirmed via a real out-of-band HTTP callback received by a listener "
                        "this scan started for itself — see request/response above for the "
                        "callback URL that was substituted into the parameter."
                    ),
                )
            )
            await self._session.commit()
        return finding
