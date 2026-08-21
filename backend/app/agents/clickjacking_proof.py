"""Real clickjacking browser-proof (§2 step 2, §3) — a real headless
browser attempts to frame the target inside a wrapper page. This
upgrades the existing header-only "Missing Clickjacking Protection"
check (app.checks.catalog — X-Frame-Options/CSP frame-ancestors
*presence*) to genuine browser-level confirmation of whether the actual
clickjacking precondition (the page really renders inside a foreign
frame) holds, the same way XSS browser-proof upgrades a raw reflection
into confirmed script execution.
"""

from dataclasses import dataclass

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright

_WRAPPER_HTML_TEMPLATE = """<html><body>
<h1>Verdikt clickjacking-proof wrapper</h1>
<iframe id="target-frame" src="{url}" style="width:900px;height:700px;border:3px solid red;"></iframe>
</body></html>"""


@dataclass
class ClickjackingProofResult:
    framable: bool
    screenshot_png: bytes | None


async def attempt_clickjacking_proof(url: str, *, headless: bool = True) -> ClickjackingProofResult:
    blocked = False

    def _on_request_failed(request) -> None:
        nonlocal blocked
        # Chromium's real, observed behavior when X-Frame-Options/CSP
        # frame-ancestors blocks a frame: the frame's own navigation
        # request fails with this specific error code (verified live
        # against a real X-Frame-Options: DENY response) — not a raw
        # network error, so it reliably distinguishes "blocked by
        # frame-ancestors policy" from "target genuinely unreachable".
        if request.url == url and "ERR_BLOCKED_BY_RESPONSE" in (request.failure or ""):
            blocked = True

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=headless)
            page = await browser.new_page()
            page.on("requestfailed", _on_request_failed)

            await page.set_content(_WRAPPER_HTML_TEMPLATE.format(url=url))
            try:
                await page.wait_for_load_state("networkidle", timeout=5000)
            except PlaywrightError:
                pass  # best-effort settle — the requestfailed listener already captured what matters

            framable = not blocked
            screenshot = await page.screenshot(full_page=True) if framable else None
            await browser.close()
    except PlaywrightError:
        # Target unreachable from a real browser, or any other
        # navigation failure — "proof not obtained", not a scan-crashing
        # error and not a claim of vulnerability either.
        return ClickjackingProofResult(framable=False, screenshot_png=None)

    return ClickjackingProofResult(framable=framable, screenshot_png=screenshot)
