"""CSRF detection (§3) — deterministic differential check: does a
state-changing (POST) form with no CSRF token field succeed identically
whether the request's Origin/Referer match the application's own origin
or a forged, attacker-controlled one? Only meaningful for cookie-based
sessions — a bearer token in an Authorization header isn't automatically
attached by a browser cross-site, so it isn't CSRF-vulnerable in the
classic sense.
"""

import uuid
from urllib.parse import urlencode, urlsplit

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.evidence_screenshot import capture_and_store_evidence_screenshot
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient, ScopeViolationError
from app.agents.recon import FormInfo
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.finding import Evidence, Finding

_CATALOG_FILE = "csrf_catalog.yaml"
_FORGED_ORIGIN = "https://verdikt-csrf-test.invalid"
_CSRF_FIELD_NAME_MARKERS = ("csrf", "_token", "authenticity_token", "xsrf")


def _has_csrf_token_field(form: FormInfo) -> bool:
    return any(
        field.type == "hidden" and any(marker in field.name.lower() for marker in _CSRF_FIELD_NAME_MARKERS)
        for field in form.fields
    )


def _build_payload(form: FormInfo) -> dict[str, str]:
    return {
        field.name: "verdikt-csrf-test"
        for field in form.fields
        if field.type not in ("submit", "button") and field.name
    }


def _origin_of(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class CsrfAgent:
    """No LLM needed — a single deterministic differential check per
    eligible form (§1.2 safe-by-default: this does submit the form for
    real, same as BusinessLogicAgent's state-changing checks — that's
    inherent to proving CSRF, not a departure from the guardrail)."""

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
        self, forms: list[FormInfo], sessions: dict[uuid.UUID, AuthenticatedSession]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for auth_session in sessions.values():
            if not auth_session.cookies:
                continue  # bearer-token-only auth isn't classically CSRF-vulnerable
            for form in forms:
                if form.method != "POST" or _has_csrf_token_field(form):
                    continue
                finding = await self._check_form(form, auth_session)
                if finding is not None:
                    findings.append(finding)
        return findings

    async def _submit(
        self, form: FormInfo, auth_session: AuthenticatedSession, origin: str
    ) -> httpx.Response | None:
        try:
            return await self._client.request(
                "POST",
                form.action_url,
                body=urlencode(_build_payload(form)),
                content_type="application/x-www-form-urlencoded",
                session=auth_session,
                extra_headers={"Origin": origin, "Referer": origin + "/"},
            )
        except (ScopeViolationError, httpx.HTTPError):
            return None

    async def _check_form(self, form: FormInfo, auth_session: AuthenticatedSession) -> Finding | None:
        same_origin_resp = await self._submit(form, auth_session, _origin_of(form.action_url))
        if same_origin_resp is None or same_origin_resp.status_code >= 400:
            return None  # can't establish a baseline if even the legitimate-looking request fails

        foreign_origin_resp = await self._submit(form, auth_session, _FORGED_ORIGIN)
        if foreign_origin_resp is None or foreign_origin_resp.status_code >= 400:
            return None  # rejected — likely validating Origin/Referer, not vulnerable
        if foreign_origin_resp.status_code != same_origin_resp.status_code:
            return None

        # §2 step 1: deterministic re-execution before confirming.
        reproduced = await self._submit(form, auth_session, _FORGED_ORIGIN)
        if reproduced is None or reproduced.status_code != same_origin_resp.status_code:
            return None

        check_def = get_check("csrf-missing-protection", filename=_CATALOG_FILE)
        extra = {"forged_origin": _FORGED_ORIGIN}
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="csrf-missing-protection",
            title=check_def.title,
            severity=check_def.severity,
            owasp_2025_category=check_def.owasp_2025_category,
            cwe_id=check_def.cwe_id,
            portswigger_reference_url=check_def.portswigger_reference_url,
            cvss_vector=check_def.cvss_vector,
            cvss_score=check_def.cvss_score,
            affected_endpoints=[form.action_url],
            plain_language_summary=check_def.plain_language_summary,
            technical_description=render_check_template(
                check_def.technical_description, form.action_url, extra
            ),
            steps_to_reproduce=[
                f"1. As a logged-in user (cookie-based session), submit the form at "
                f"{form.action_url} with a forged Origin/Referer header pointing at an "
                f'unrelated domain (e.g. "{_FORGED_ORIGIN}") and no CSRF token field.',
                "2. Observe the request succeeds identically to a legitimate same-origin "
                "submission — proving a real cross-site request (e.g. auto-submitted from "
                "a malicious page a victim visits) would also succeed.",
            ],
            remediation=check_def.remediation,
            references=[*check_def.references, check_def.portswigger_reference_url],
            confirmation_status="ai_confirmed",
        )
        request_raw = format_request_raw(reproduced)
        response_raw = format_response_raw(reproduced)
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
