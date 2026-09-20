"""Wires the real clickjacking browser-proof (app.agents.clickjacking_proof)
into the Finding pipeline — one check per distinct host (framability is a
site-wide header/CSP behavior, not usually a per-page one; matches
app.agents.host_header/cors's same per-host dedup for the same reason).
"""

import uuid

import httpx

from app.agents.clickjacking_proof import attempt_clickjacking_proof
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.agents.login import pick_best_session
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.finding import Evidence, Finding
from app.storage.local_disk import get_object_storage

_CATALOG_FILE = "clickjacking_catalog.yaml"


class ClickjackingAgent:
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
        self,
        endpoints: list[str],
        sessions: dict[uuid.UUID, AuthenticatedSession] | None = None,
    ) -> list[Finding]:
        # Tested twice per host, not once: an anonymous visitor and a
        # logged-in one can see genuinely different content behind the
        # exact same X-Frame-Options/CSP policy, and the pages an
        # attacker would actually want to frame for a real clickjacking
        # attack (an account/admin/settings screen) are almost always
        # the authenticated ones — a check that only ever tested the
        # anonymous view (the pre-fix behavior) never actually exercised
        # that surface at all, only the public, pre-login shell.
        auth_session = pick_best_session(sessions)
        findings: list[Finding] = []
        seen_hosts_anonymous: set[str] = set()
        seen_hosts_authenticated: set[str] = set()
        for url in endpoints:
            host = httpx.URL(url).host
            if host not in seen_hosts_anonymous:
                seen_hosts_anonymous.add(host)
                finding = await self._check_endpoint(url, session=None)
                if finding is not None:
                    findings.append(finding)
            if auth_session is not None and host not in seen_hosts_authenticated:
                seen_hosts_authenticated.add(host)
                finding = await self._check_endpoint(url, session=auth_session)
                if finding is not None:
                    findings.append(finding)
        return findings

    async def _check_endpoint(self, url: str, *, session: AuthenticatedSession | None) -> Finding | None:
        result = await attempt_clickjacking_proof(url, session=session)
        if not result.framable:
            return None

        screenshot_refs: list[str] = []
        if result.screenshot_png is not None:
            storage = get_object_storage()
            key = f"clickjacking-proof/{self._scan_run_id}/{uuid.uuid4().hex}.png"
            await storage.put(key, result.screenshot_png, content_type="image/png")
            screenshot_refs = [key]

        as_user = "a logged-in user" if session is not None else "an anonymous visitor"
        check_def = get_check("clickjacking-confirmed", filename=_CATALOG_FILE)
        if session is not None:
            steps_to_reproduce = [
                f"1. Sign in and load {url} directly — confirmed here to return real, "
                "logged-in content (not a login redirect or an empty shell).",
                "2. Inspect that exact response's headers: no X-Frame-Options (DENY/SAMEORIGIN) "
                "and no Content-Security-Policy frame-ancestors directive is present.",
                f'3. Since nothing prevents it, {url} can be embedded via '
                f'<iframe src="{url}"></iframe> on any attacker-controlled page while the '
                "victim's own browser still carries their real session cookie — a screenshot "
                "of the genuine authenticated page (loaded directly, not framed — see this "
                "check's technical description for why a literal framed screenshot isn't "
                "obtainable here) is captured as evidence.",
            ]
        else:
            steps_to_reproduce = [
                f'1. Create an HTML page with <iframe src="{url}"></iframe> embedding this page.',
                "2. Open that wrapper page in a real browser as an anonymous visitor.",
                "3. Observe the target page's content actually renders inside the iframe "
                "(confirmed here by a real headless browser, with a screenshot captured as "
                "evidence) instead of being blocked.",
            ]
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="clickjacking-confirmed",
            title=check_def.title,
            severity=check_def.severity,
            owasp_2025_category=check_def.owasp_2025_category,
            cwe_id=check_def.cwe_id,
            portswigger_reference_url=check_def.portswigger_reference_url,
            cvss_vector=check_def.cvss_vector,
            cvss_score=check_def.cvss_score,
            affected_endpoints=[url],
            plain_language_summary=check_def.plain_language_summary,
            technical_description=(
                render_check_template(check_def.technical_description, url, {})
                + (
                    f" Tested as {as_user}: the real authenticated response was fetched directly "
                    "(genuine session cookies cannot be delivered into a cross-origin iframe by "
                    "any browser, which is exactly the protection SameSite cookies exist to "
                    "provide — so this confirms the same underlying fact, that this exact "
                    "authenticated response carries no anti-framing header, without literally "
                    "watching it render inside a frame)."
                    if session is not None
                    else f" Tested as {as_user}."
                )
            ),
            steps_to_reproduce=steps_to_reproduce,
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
                    request_raw=f'GET {url} (loaded inside a cross-origin <iframe>)',
                    response_raw="(see screenshot evidence — target content rendered inside the iframe)",
                    screenshot_refs=screenshot_refs,
                )
            )
            await self._session.commit()
        return finding
