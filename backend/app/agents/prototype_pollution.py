"""Client-side prototype pollution (§3) — appends a __proto__-keyed
payload to each discovered page's URL and checks, in a real browser,
whether Object.prototype actually got polluted. Real pollution here is
unambiguous: a brand-new, unrelated object ({}) inheriting the injected
property only happens if a JS library on the page merged the __proto__
key into Object.prototype itself without guarding against it.
"""

import uuid
from urllib.parse import urlsplit

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright

from app.agents.http_client import ScopedHttpClient
from app.models.finding import Evidence, Finding
from app.storage.local_disk import get_object_storage

# Two common attacker-controlled-merge conventions: bracket notation
# (what libraries like `qs` produce from a[b]=c) and dotted-path
# notation (what some hand-rolled/simpler parsers use directly).
_PAYLOAD_TEMPLATES = (
    "__proto__[{marker}]=polluted",
    "__proto__.{marker}=polluted",
)


def _marker() -> str:
    return f"verdikt_pp_{uuid.uuid4().hex[:12]}"


def _append_payload(url: str, payload: str) -> str:
    separator = "&" if urlsplit(url).query else "?"
    return f"{url}{separator}{payload}"


_NAVIGATION_TIMEOUT_MS = 10_000


async def attempt_prototype_pollution_proof(
    url: str, *, headless: bool = True
) -> tuple[bool, bytes | None]:
    marker = _marker()
    executed = False
    screenshot: bytes | None = None
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=headless)
            page = await browser.new_page()
            for template in _PAYLOAD_TEMPLATES:
                payload = template.format(marker=marker)
                target_url = _append_payload(url, payload)
                # Force a real fresh navigation each attempt — see
                # app.agents.xss_browser_proof's DOM-XSS fragment proof
                # for why a same-path navigation alone isn't sufficient.
                await page.goto("about:blank")
                # "networkidle" never fires against a real SPA with a
                # persistent WebSocket connection or background polling
                # — see app.agents.xss_browser_proof's identical fix,
                # found via the same §14 live validation run.
                await page.goto(target_url, wait_until="load", timeout=_NAVIGATION_TIMEOUT_MS)
                executed = bool(await page.evaluate(f'({{}}).{marker} === "polluted"'))
                if executed:
                    break
            screenshot = await page.screenshot(full_page=True) if executed else None
            await browser.close()
    except PlaywrightError:
        return False, None
    return executed, screenshot


class PrototypePollutionAgent:
    # See app.agents.dom_xss.DomXssAgent.MAX_ENDPOINTS for why this is
    # bounded rather than per-host deduped — same real-browser-per-
    # endpoint cost, same §14 finding.
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

    async def run(self, endpoints: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for url in endpoints[: self.MAX_ENDPOINTS]:
            finding = await self._check_endpoint(url)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _check_endpoint(self, url: str) -> Finding | None:
        executed, screenshot_png = await attempt_prototype_pollution_proof(url)
        if not executed:
            return None

        screenshot_refs: list[str] = []
        if screenshot_png:
            storage = get_object_storage()
            key = f"prototype-pollution-proof/{self._scan_run_id}/{uuid.uuid4().hex}.png"
            await storage.put(key, screenshot_png, content_type="image/png")
            screenshot_refs = [key]

        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="client-side-prototype-pollution",
            title="Client-Side Prototype Pollution",
            severity="High",
            owasp_2025_category="A05 Injection",
            cwe_id="CWE-1321",
            portswigger_reference_url="https://portswigger.net/web-security/prototype-pollution",
            cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L",
            cvss_score=7.1,
            affected_endpoints=[url],
            plain_language_summary=(
                "A script on this page merges values from the URL into JavaScript objects "
                "without guarding against a special property name (__proto__), letting an "
                "attacker-crafted link modify the behavior of every object on the page. "
                "Depending on what the application's other code does with polluted objects, "
                "this can range from denial of service to bypassing security checks or "
                "enabling script execution."
            ),
            technical_description=(
                f"Loading {url} with a __proto__-keyed value in the URL caused Object.prototype "
                "itself to gain that property — confirmed by checking a brand-new, unrelated "
                "object literal in the page (it inherited the polluted property), proving a "
                "JavaScript library on this page performs an unguarded recursive merge/"
                "assignment using attacker-controlled URL data."
            ),
            steps_to_reproduce=[
                f"1. Open {url}?__proto__[polluted]=true (or the bracket/dot-path convention "
                "your app's query-string parser uses) in a browser.",
                '2. In the browser console, evaluate `({}).polluted` and observe it returns the '
                "injected value — proving Object.prototype was modified, not just one object.",
            ],
            remediation=(
                "Never recursively assign or merge attacker-controlled keys into objects "
                'without an explicit block-list for "__proto__", "constructor", and '
                '"prototype" — or upgrade to a merge/parsing library version with '
                "prototype-pollution protection built in (most modern libraries have patched "
                "this), or parse untrusted query strings into null-prototype objects "
                "(Object.create(null))."
            ),
            references=[
                "https://portswigger.net/web-security/prototype-pollution",
                "https://cwe.mitre.org/data/definitions/1321.html",
            ],
            confirmation_status="ai_confirmed",
        )
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()
            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=f"GET {url}?__proto__[marker]=polluted (client-side only, "
                    "never inspected by the server)",
                    response_raw="(see screenshot evidence — Object.prototype was polluted client-side)",
                    screenshot_refs=screenshot_refs,
                )
            )
            await self._session.commit()
        return finding
