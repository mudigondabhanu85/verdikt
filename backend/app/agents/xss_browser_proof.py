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

from app.agents.probing import ProbeTarget, build_request


@dataclass
class BrowserProofResult:
    executed: bool
    screenshot_png: bytes | None


def _proof_marker() -> str:
    return f"verdikt_proof_{uuid.uuid4().hex[:12]}"


def _payload_for(marker: str) -> str:
    return f'<script>window["{marker}"]=true;</script>'


async def attempt_browser_proof(
    target: ProbeTarget, *, headless: bool = True
) -> BrowserProofResult:
    """Only meaningful for target.method == "GET" — see module docstring.
    Callers are responsible for checking that before calling this.
    """
    marker = _proof_marker()
    payload = _payload_for(marker)
    url, _body, _content_type = build_request(target, payload)

    executed = False
    screenshot = None

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=headless)
        page = await browser.new_page()
        try:
            await page.goto(url, wait_until="networkidle")
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
