"""Known Vulnerable Components — client-side (ported from a sibling DAST
project) — a real headless browser evaluates each well-known JS
library's own self-reported `window.<Library>.version`-style global, and
a confirmed version is checked against OSV.dev's free vulnerability
database. Deterministic end to end: the library reports its own version
string directly (no fingerprint-guessing), and OSV.dev's response is
ground truth for "does a published CVE exist for this exact version" —
no LLM verdict adds anything on top of that.

Frameworks that don't expose their own runtime version on `window` at
all (Next.js chief among them — its dev-time `__NEXT_DATA__` blob
carries build metadata, not a queryable client-side version the running
page reports about itself) are deliberately not in the check list below
rather than probed for a global that was never going to exist — a
"missing" result there would be indistinguishable from "up to date" and
would just be noise.
"""

import uuid
from dataclasses import dataclass

import httpx
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright

from app.agents.browser_session import seed_authenticated_context
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.agents.login import pick_best_session
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.integrations.osv.client import OsvClient, OsvLookupError
from app.models.finding import Evidence, Finding
from app.storage.local_disk import get_object_storage

_CATALOG_FILE = "vulnerable_components_catalog.yaml"
_NAVIGATION_TIMEOUT_MS = 10000

# (display name, npm package name on OSV.dev, JS expression reading the
# library's own self-reported version off `window`). Angular (2+) is
# deliberately excluded — unlike AngularJS 1.x's `window.angular`, a
# modern Angular app doesn't expose a stable, always-present global to
# read a version off of outside of dev-mode devtools hooks, which would
# make "not found" and "not present in prod build" indistinguishable
# from "not installed" — the same reasoning that excludes Next.js.
_LIBRARY_PROBES: tuple[tuple[str, str, str], ...] = (
    ("jQuery", "jquery", 'window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery'),
    ("React", "react", "window.React && window.React.version"),
    ("Vue", "vue", "window.Vue && window.Vue.version"),
    ("AngularJS", "angular", "window.angular && window.angular.version && window.angular.version.full"),
    ("Lodash", "lodash", "window._ && window._.VERSION"),
    ("Moment", "moment", "window.moment && window.moment.version"),
    ("Axios", "axios", "window.axios && window.axios.VERSION"),
    ("D3", "d3", "window.d3 && window.d3.version"),
    ("Backbone", "backbone", "window.Backbone && window.Backbone.VERSION"),
)


@dataclass
class _Detection:
    display_name: str
    package_name: str
    version: str


async def _detect_libraries(
    url: str, session: AuthenticatedSession | None, *, headless: bool = True
) -> tuple[list[_Detection], bytes | None]:
    detections: list[_Detection] = []
    screenshot: bytes | None = None
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=headless)
            context = await browser.new_context(ignore_https_errors=True)
            await seed_authenticated_context(context, session, url)
            page = await context.new_page()
            try:
                await page.goto(url, wait_until="load", timeout=_NAVIGATION_TIMEOUT_MS)
            except PlaywrightError:
                await browser.close()
                return [], None

            for display_name, package_name, expression in _LIBRARY_PROBES:
                try:
                    version = await page.evaluate(expression)
                except PlaywrightError:
                    version = None
                if isinstance(version, str) and version.strip():
                    detections.append(_Detection(display_name, package_name, version.strip()))

            if detections:
                try:
                    screenshot = await page.screenshot(full_page=True)
                except PlaywrightError:
                    screenshot = None
            await browser.close()
    except PlaywrightError:
        return [], None
    return detections, screenshot


class VulnerableComponentsAgent:
    def __init__(
        self,
        client: ScopedHttpClient,
        *,
        scan_run_id: uuid.UUID,
        agent_job_id: uuid.UUID,
        db_session,
        osv_client: OsvClient | None = None,
    ):
        self._client = client
        self._scan_run_id = scan_run_id
        self._agent_job_id = agent_job_id
        self._session = db_session
        self._osv_client = osv_client or OsvClient()

    async def run(
        self,
        endpoints: list[str],
        sessions: dict[uuid.UUID, AuthenticatedSession] | None = None,
    ) -> list[Finding]:
        # A library loaded on one page is virtually always loaded
        # site-wide (a shared bundle/CDN <script> tag) — one check per
        # host, same dedup reasoning as app.agents.clickjacking, avoids
        # a real headless-browser navigation (the expensive part here)
        # per individual page for no additional signal.
        auth_session = pick_best_session(sessions)
        seen_hosts: set[str] = set()
        findings: list[Finding] = []
        for url in endpoints:
            host = httpx.URL(url).host
            if host in seen_hosts:
                continue
            seen_hosts.add(host)
            findings.extend(await self._check_endpoint(url, auth_session))
        return findings

    async def _check_endpoint(
        self, url: str, auth_session: AuthenticatedSession | None
    ) -> list[Finding]:
        detections, screenshot = await _detect_libraries(url, auth_session)
        findings: list[Finding] = []
        for detection in detections:
            try:
                vulns = await self._osv_client.query_npm_package(
                    name=detection.package_name, version=detection.version
                )
            except OsvLookupError:
                continue  # best-effort — an unreachable third-party API never fails the scan
            if not vulns:
                continue
            finding = await self._build_finding(url, detection, vulns, screenshot)
            findings.append(finding)
        return findings

    async def _build_finding(
        self, url: str, detection: _Detection, vulns: list[dict], screenshot: bytes | None
    ) -> Finding:
        check_def = get_check("vulnerable-client-side-component", filename=_CATALOG_FILE)
        vuln_ids = [v.get("id", "unknown") for v in vulns]
        extra = {
            "library": detection.display_name,
            "version": detection.version,
            "vuln_count": str(len(vulns)),
            "plural": "" if len(vulns) == 1 else "s",
            "vuln_ids": ", ".join(vuln_ids),
        }
        screenshot_refs: list[str] = []
        if screenshot is not None:
            storage = get_object_storage()
            key = f"vulnerable-component-proof/{self._scan_run_id}/{uuid.uuid4().hex}.png"
            await storage.put(key, screenshot, content_type="image/png")
            screenshot_refs = [key]

        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="vulnerable-client-side-component",
            title=f"{check_def.title}: {detection.display_name} {detection.version}",
            severity=check_def.severity,
            owasp_2025_category=check_def.owasp_2025_category,
            cwe_id=check_def.cwe_id,
            portswigger_reference_url=check_def.portswigger_reference_url,
            cvss_vector=check_def.cvss_vector,
            cvss_score=check_def.cvss_score,
            affected_endpoints=[url],
            plain_language_summary=render_check_template(check_def.plain_language_summary, url, extra),
            technical_description=render_check_template(check_def.technical_description, url, extra),
            steps_to_reproduce=[
                f"1. Load {url} in a browser and inspect `window.{detection.display_name}`.",
                f"2. Observe it reports version {detection.version}.",
                f"3. Query OSV.dev for npm package '{detection.package_name}' at that exact "
                f"version — {len(vulns)} known advisory/advisories returned: {', '.join(vuln_ids)}.",
            ],
            remediation=render_check_template(check_def.remediation, url, extra),
            references=[*check_def.references, *[f"https://osv.dev/vulnerability/{v}" for v in vuln_ids]],
            confirmation_status="ai_confirmed",
        )
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()
            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=f"GET {url} (real headless browser)",
                    response_raw=f"window.{detection.display_name} version {detection.version}; "
                    f"OSV.dev advisories: {', '.join(vuln_ids)}",
                    screenshot_refs=screenshot_refs,
                    payload=detection.version,
                )
            )
            await self._session.commit()
        return finding
