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

# Real, live-found false positive this pair guards against: a page that
# X-Frame-Options/CSP doesn't block can still render essentially nothing
# inside the iframe — most commonly because it requires auth and this
# check never carries a session, so what actually loads is a blank or
# near-empty login-redirect page. Absent this check, that produced an
# identical "framable, screenshot attached" result to a genuinely
# framable page full of real content — a false positive an analyst would
# have to notice by eye on every single screenshot. Two independent
# signals, checked with OR rather than AND: a real page might be mostly
# non-text UI (a form-heavy admin screen with little running text, caught
# by the element-count side) or mostly prose with little DOM nesting
# (caught by the text-length side) — requiring both at once would
# reintroduce false negatives for whichever kind of page doesn't happen
# to satisfy the other signal.
_MIN_FRAME_TEXT_LENGTH = 10
_MIN_FRAME_ELEMENT_COUNT = 5


async def _frame_has_real_content(page) -> bool:
    frame_element = await page.query_selector("#target-frame")
    if frame_element is None:
        return False
    frame = await frame_element.content_frame()
    if frame is None:
        # A cross-origin iframe whose navigation genuinely never
        # committed (not the same thing as "blocked by frame-ancestors",
        # which the requestfailed listener already caught separately) —
        # nothing rendered, so there is nothing to confirm framable.
        return False
    try:
        text_length = await frame.evaluate("document.body ? document.body.innerText.length : 0")
        element_count = await frame.evaluate("document.querySelectorAll('*').length")
    except PlaywrightError:
        return False
    return text_length >= _MIN_FRAME_TEXT_LENGTH or element_count >= _MIN_FRAME_ELEMENT_COUNT


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
            # Internal staging/pre-prod targets routinely sit behind a
            # self-signed/internal-CA cert Chromium doesn't trust by
            # default — an analyst testing one of those is authorized,
            # scoped access, not a real end-user's browser, so trusting
            # it here is the correct call (see app.agents.macro's
            # identical fix/rationale for the real incident this closes).
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            page.on("requestfailed", _on_request_failed)

            await page.set_content(_WRAPPER_HTML_TEMPLATE.format(url=url))
            try:
                await page.wait_for_load_state("networkidle", timeout=5000)
            except PlaywrightError:
                pass  # best-effort settle — the requestfailed listener already captured what matters

            framable = not blocked and await _frame_has_real_content(page)
            screenshot = await page.screenshot(full_page=True) if framable else None
            await browser.close()
    except PlaywrightError:
        # Target unreachable from a real browser, or any other
        # navigation failure — "proof not obtained", not a scan-crashing
        # error and not a claim of vulnerability either.
        return ClickjackingProofResult(framable=False, screenshot_png=None)

    return ClickjackingProofResult(framable=framable, screenshot_png=screenshot)
