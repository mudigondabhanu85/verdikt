"""Real Playwright-driven browser proof for reflected XSS (§2 step 2).

A deterministic HTTP-level reflection check (app.agents.xss._probe_reflected_xss)
only proves the payload string appears unescaped in the raw response body —
it does NOT prove a real browser would execute it (encoding differences,
a WAF/CSP that blocks it, a parser that doesn't treat it as a live
`<script>` context, etc.). This module actually loads the response in a
real headless browser and checks whether an injected script genuinely
ran, which is what lets the XSS agent promote a candidate straight to a
confirmed Finding instead of stopping at a ReviewCandidate for manual
review.

Scope for this pass: GET-based targets only. A POST-based reflected XSS
candidate still goes through deterministic HTTP-level re-confirmation and
LLM triage as before, but stops at ReviewCandidate rather than attempting
an automated browser proof — submitting a synthetic form via Playwright
and racing its navigation event is meaningfully more fragile than a GET
page load, and GET-based reflection covers the overwhelming majority of
real-world reflected XSS. Documented simplification, not a silent gap.
"""

import uuid
from dataclasses import dataclass

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright

from app.agents.http_client import AuthenticatedSession
from app.agents.probing import ProbeTarget, build_request


@dataclass
class BrowserProofResult:
    executed: bool
    screenshot_png: bytes | None


def _proof_marker() -> str:
    return f"verdikt_proof_{uuid.uuid4().hex[:12]}"


def _payload_for(marker: str) -> str:
    return f'<script>window["{marker}"]=true;</script>'


# DOM-based XSS payloads, tried via the URL *fragment* (app.agents.dom_xss)
# — the fragment is never sent to the server (only client-side JS ever
# sees it via location.hash), so execution here is definitive proof of a
# purely client-side sink (e.g. `el.innerHTML = location.hash`), distinct
# from the server-reflection case attempt_browser_proof above covers. Two
# variants since a <script> tag inserted via innerHTML does NOT execute
# per the HTML spec, but an event-handler-bearing element (onerror) does
# — different sinks call for different proof payloads.
def _dom_xss_payloads(marker: str) -> list[str]:
    return [
        f'<script>window["{marker}"]=true;</script>',
        f'<img src=x onerror=window["{marker}"]=true>',
    ]


_NAVIGATION_TIMEOUT_MS = 10_000


async def attempt_browser_proof(
    target: ProbeTarget,
    *,
    headless: bool = True,
    session: AuthenticatedSession | None = None,
) -> BrowserProofResult:
    """Only meaningful for target.method == "GET" — see module docstring.
    Callers are responsible for checking that before calling this.

    A fresh Playwright browser context carries no cookies at all, which
    silently defeated this proof for every login-gated page (a real,
    live-found gap — DVWA's own reflected-XSS page requires an
    authenticated session, matching the exact class of bug already fixed
    for the httpx-level probes in app.agents.probing.fetch_with_value):
    without the session's cookies, the browser just lands on the login
    redirect and the marker never gets a chance to execute, so proof
    always failed and every login-gated finding fell back to a
    ReviewCandidate instead of an auto-confirmed Finding with a
    screenshot.
    """
    marker = _proof_marker()
    payload = _payload_for(marker)
    url, _body, _content_type = build_request(target, payload)

    executed = False
    screenshot = None

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=headless)
        context = await browser.new_context()
        if session is not None and session.cookies:
            await context.add_cookies(
                [{"name": name, "value": value, "url": url} for name, value in session.cookies.items()]
            )
        page = await context.new_page()
        if session is not None and session.bearer_token:
            await page.set_extra_http_headers({"Authorization": f"Bearer {session.bearer_token}"})
        try:
            # "networkidle" (the Playwright-recommended default) never
            # fires against a real single-page app that keeps a
            # persistent WebSocket connection open (socket.io, live
            # reload, etc.) or polls in the background — confirmed via
            # §14 live validation against OWASP Juice Shop, where this
            # combination made every navigation eat the full default
            # 30s timeout. "load" waits for the page's own resources
            # (including deferred/module <script> tags) without waiting
            # for *ongoing* network activity to quiesce, and the
            # explicit timeout keeps a single slow/unreachable page from
            # ever stalling the whole scan.
            await page.goto(url, wait_until="load", timeout=_NAVIGATION_TIMEOUT_MS)
            executed = bool(await page.evaluate(f'window["{marker}"] === true'))
            screenshot = await page.screenshot(full_page=True) if executed else None
        except PlaywrightError:
            # Target unreachable from a real browser (DNS, TLS, timeout,
            # etc.), a synthetic test double the httpx-level agent could
            # reach but no browser can, or any other navigation failure —
            # treat as "proof not obtained", not a scan-crashing error.
            # The caller falls back to queuing a ReviewCandidate instead.
            executed = False
            screenshot = None
        finally:
            await browser.close()

    return BrowserProofResult(executed=executed, screenshot_png=screenshot)


async def attempt_dom_xss_fragment_proof(url: str, *, headless: bool = True) -> BrowserProofResult:
    """Loads `url` with an XSS payload appended as the URL fragment
    (`#...`), which never reaches the server — real execution here proves
    a client-side JS sink reads location.hash/location.href and writes it
    somewhere unsafe (innerHTML, document.write, eval, ...), independent
    of anything the server itself does.
    """
    marker = _proof_marker()
    executed = False
    screenshot = None

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=headless)
            page = await browser.new_page()
            for payload in _dom_xss_payloads(marker):
                # A navigation that changes only the fragment is treated
                # by the browser as same-document (fires "hashchange",
                # no reload) — the page's own <script> block, which is
                # what actually reads location.hash, would never re-run
                # for a second payload attempt without forcing a real
                # fresh navigation first.
                await page.goto("about:blank")
                await page.goto(f"{url}#{payload}", wait_until="load", timeout=_NAVIGATION_TIMEOUT_MS)
                executed = bool(await page.evaluate(f'window["{marker}"] === true'))
                if executed:
                    break
            screenshot = await page.screenshot(full_page=True) if executed else None
            await browser.close()
    except PlaywrightError:
        # Same reasoning as attempt_browser_proof above: unreachable
        # target or any other navigation failure means "proof not
        # obtained", not a vulnerability claim and not a crash.
        return BrowserProofResult(executed=False, screenshot_png=None)

    return BrowserProofResult(executed=executed, screenshot_png=screenshot)
