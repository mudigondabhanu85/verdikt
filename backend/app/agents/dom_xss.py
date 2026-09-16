"""DOM-based XSS (§3) — reuses the reflected-XSS browser-proof mechanism
(app.agents.xss_browser_proof) but injects the payload via the URL
fragment instead of a query/form parameter. A fragment is never sent to
the server, so execution here is definitive, self-contained proof of a
purely client-side sink (e.g. `el.innerHTML = location.hash`) — a
structurally different bug class from reflected XSS, and just as
confirmable via real browser execution, so this goes straight to a
confirmed Finding the same way browser-confirmed reflected XSS does.
"""

import uuid

from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.agents.login import pick_best_session
from app.agents.xss import XSS_FINDING_METADATA
from app.agents.xss_browser_proof import attempt_dom_xss_fragment_proof
from app.models.finding import Evidence, Finding
from app.storage.local_disk import get_object_storage


class DomXssAgent:
    # A real headless-browser navigation per endpoint (up to two payload
    # attempts each) is far more expensive than every other deterministic
    # check — bounding total endpoints tested keeps scan runtime sane
    # against a real target with a large discovered surface (§14 live
    # validation against OWASP Juice Shop: traffic-seeded discovery alone
    # found ~80 endpoints, which at ~10s/navigation would otherwise put a
    # single scan's runtime for this one check well over ten minutes).
    # Unlike clickjacking (a site-wide header/CSP behavior, one check per
    # host is enough), a DOM-XSS sink is often genuinely page-specific, so
    # this samples the first N endpoints rather than deduping per host.
    MAX_ENDPOINTS = 40

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
        self._auth_session: AuthenticatedSession | None = None

    async def run(
        self,
        endpoints: list[str],
        sessions: dict[uuid.UUID, AuthenticatedSession] | None = None,
    ) -> list[Finding]:
        # Same login-gated-page fix as app.agents.injection/stored_xss —
        # without a session cookie, a real headless browser navigating to
        # a login-gated page just lands on the login form, so a DOM XSS
        # sink behind auth never gets a chance to run at all.
        self._auth_session = pick_best_session(sessions)
        findings: list[Finding] = []
        for url in endpoints[: self.MAX_ENDPOINTS]:
            finding = await self._check_endpoint(url)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _check_endpoint(self, url: str) -> Finding | None:
        result = await attempt_dom_xss_fragment_proof(url, session=self._auth_session)
        if not result.executed:
            return None

        screenshot_refs: list[str] = []
        if result.screenshot_png is not None:
            storage = get_object_storage()
            key = f"dom-xss-proof/{self._scan_run_id}/{uuid.uuid4().hex}.png"
            await storage.put(key, result.screenshot_png, content_type="image/png")
            screenshot_refs = [key]

        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="dom-xss-fragment",
            title="DOM-Based Cross-Site Scripting (XSS)",
            severity="High",
            owasp_2025_category=XSS_FINDING_METADATA["owasp_2025_category"],
            cwe_id="CWE-79",
            portswigger_reference_url="https://portswigger.net/web-security/cross-site-scripting/dom-based",
            cvss_vector=XSS_FINDING_METADATA["cvss_vector"],
            cvss_score=XSS_FINDING_METADATA["cvss_score"],
            affected_endpoints=[url],
            plain_language_summary=(
                "This page reads part of its own web address (the portion after the #) and "
                "writes it directly into the page without removing dangerous content. Because "
                "this happens entirely inside the browser, an attacker-crafted link can run "
                "arbitrary JavaScript in a victim's browser session — the server never even "
                "sees the malicious part of the URL, so server-side filtering can't stop it."
            ),
            technical_description=(
                f"Loading {url} with an XSS payload placed in the URL fragment (never sent to "
                "the server) caused a real headless browser to execute the injected script, "
                "confirming a client-side JavaScript sink on this page reads "
                "location.hash/location.href and writes it into the DOM (e.g. via innerHTML, "
                "document.write, or eval) without sanitization."
            ),
            steps_to_reproduce=[
                f"1. Open {url}#{result.payload} in a browser — the fragment is "
                "never transmitted to the server, so no server-side reflection is needed.",
                "2. Observe the injected script executes — verified here by an automated "
                "headless-browser check, with a screenshot captured as evidence.",
            ],
            remediation=XSS_FINDING_METADATA["remediation"],
            references=[
                "https://portswigger.net/web-security/cross-site-scripting/dom-based",
                "https://cwe.mitre.org/data/definitions/79.html",
            ],
            confirmation_status="ai_confirmed",
        )
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()
            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=f"GET {url}#<payload> (fragment never sent to the server)",
                    response_raw="(see screenshot evidence — injected script executed client-side)",
                    screenshot_refs=screenshot_refs,
                )
            )
            await self._session.commit()
        return finding
