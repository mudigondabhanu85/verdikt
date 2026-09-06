"""OAuth 2.0 authorization flow — redirect_uri allow-list validation
(§3). A deterministic, confirmable check: does the authorization
endpoint accept an attacker-controlled redirect_uri instead of
validating it against a registered allow-list? If it redirects there
carrying the authorization grant, an attacker can steal a victim's
OAuth authorization by tricking them into visiting a crafted authorize
URL — this is the single most common, most impactful OAuth
misconfiguration found in real-world testing.

PKCE downgrade and state-parameter/CSRF testing would need driving a
full authenticated flow against a real, cooperating Identity Provider
(exchanging a code for a token, replaying a session), which isn't
safely automatable against an arbitrary third-party IdP mid-scan —
that's an honest, documented limitation here, the same category as
app.agents.ssrf_callback's "only detects SSRF that can call back to
the scanner."
"""

import uuid
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.evidence_screenshot import capture_and_store_evidence_screenshot
from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.finding import Evidence, Finding

_CATALOG_FILE = "oauth_catalog.yaml"
_ATTACKER_REDIRECT = "https://verdikt-oauth-test.invalid/callback"


def _is_authorize_url(url: str) -> bool:
    query = parse_qs(urlsplit(url).query)
    return "client_id" in query and "redirect_uri" in query and "response_type" in query


def _swap_redirect_uri(url: str, new_redirect: str) -> str:
    parts = urlsplit(url)
    query = parse_qs(parts.query, keep_blank_values=True)
    query["redirect_uri"] = [new_redirect]
    new_query = urlencode(query, doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def _accepts_attacker_redirect(response: httpx.Response) -> bool:
    location = response.headers.get("location", "")
    if location.startswith(_ATTACKER_REDIRECT):
        return True
    # Some authorization servers render an HTML "continue" page instead
    # of an HTTP redirect; an unescaped attacker redirect_uri carried
    # into that page is the same underlying acceptance.
    return response.status_code < 400 and _ATTACKER_REDIRECT in (response.text or "")


class OAuthAgent:
    """No LLM needed — a single differential, deterministic check
    (§1.2 safe-by-default: swaps one query parameter, no state-changing
    payload, never actually completes a real OAuth grant exchange)."""

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
        seen: set[tuple[str, str, str]] = set()
        for url in endpoints:
            if not _is_authorize_url(url):
                continue
            parts = urlsplit(url)
            key = (parts.scheme, parts.netloc, parts.path)
            if key in seen:
                # Same authorize endpoint discovered via different query
                # strings (e.g. different client_ids) — one confirmed/
                # rejected result per distinct endpoint is enough
                # signal; this is allow-list-validation behavior, not a
                # per-request one.
                continue
            seen.add(key)
            finding = await self._check(url)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _check(self, url: str) -> Finding | None:
        probe_url = _swap_redirect_uri(url, _ATTACKER_REDIRECT)
        try:
            probe = await self._client.get(probe_url)
        except (ScopeViolationError, httpx.HTTPError):
            return None
        if not _accepts_attacker_redirect(probe):
            return None

        # §2 step 1: deterministic re-execution before confirming.
        try:
            probe_again = await self._client.get(probe_url)
        except (ScopeViolationError, httpx.HTTPError):
            return None
        if not _accepts_attacker_redirect(probe_again):
            return None

        check_def = get_check("oauth-redirect-uri-validation-bypass", filename=_CATALOG_FILE)
        extra = {"attacker_redirect": _ATTACKER_REDIRECT}
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="oauth-redirect-uri-validation-bypass",
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
                f"1. Take the authorization URL {url} and replace its redirect_uri "
                f'parameter with an attacker-controlled value (e.g. "{_ATTACKER_REDIRECT}").',
                "2. Send a victim this crafted URL; observe the authorization server "
                "redirects the victim's browser (carrying the authorization code/token) "
                "to the attacker-controlled redirect_uri instead of rejecting the request.",
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
                    screenshot_refs=screenshot_refs,
                )
            )
            await self._session.commit()
        return finding
