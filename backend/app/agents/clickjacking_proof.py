"""Real clickjacking browser-proof (§2 step 2, §3) — a real headless
browser attempts to frame the target inside a wrapper page. This
upgrades the existing header-only "Missing Clickjacking Protection"
check (app.checks.catalog — X-Frame-Options/CSP frame-ancestors
*presence*) to genuine browser-level confirmation of whether the actual
clickjacking precondition (the page really renders inside a foreign
frame) holds, the same way XSS browser-proof upgrades a raw reflection
into confirmed script execution.
"""

import asyncio
from dataclasses import dataclass

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright

from app.agents.browser_session import seed_authenticated_context
from app.agents.http_client import AuthenticatedSession

_WRAPPER_HTML_TEMPLATE = """<html><body>
<h1>Verdikt clickjacking-proof wrapper</h1>
<iframe id="target-frame" src="{url}" style="width:900px;height:700px;border:3px solid red;"></iframe>
</body></html>"""

# Same defensive backstop as app.agents.http_client's
# _HARD_REQUEST_TIMEOUT_SECONDS — see app.agents.xss_browser_proof's
# identical constant for the real, live-found scan hang this class of
# fix exists for. playwright.chromium.launch() has no timeout of its
# own.
_HARD_PROOF_TIMEOUT_SECONDS = 30.0

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


async def _page_has_real_content(page) -> bool:
    """Same two-signal check as _frame_has_real_content, applied to the
    top-level page itself instead of an iframe's content_frame — used by
    the authenticated path below, which never actually frames the page
    (see attempt_clickjacking_proof's docstring for why).
    """
    try:
        text_length = await page.evaluate("document.body ? document.body.innerText.length : 0")
        element_count = await page.evaluate("document.querySelectorAll('*').length")
    except PlaywrightError:
        return False
    return text_length >= _MIN_FRAME_TEXT_LENGTH or element_count >= _MIN_FRAME_ELEMENT_COUNT


def _response_blocks_framing(headers: dict[str, str]) -> bool:
    xfo = headers.get("x-frame-options", "").strip().lower()
    if xfo in ("deny", "sameorigin"):
        return True
    csp = headers.get("content-security-policy", "")
    return "frame-ancestors" in csp.lower()


@dataclass
class ClickjackingProofResult:
    framable: bool
    screenshot_png: bytes | None


async def attempt_clickjacking_proof(
    url: str, *, headless: bool = True, session: AuthenticatedSession | None = None
) -> ClickjackingProofResult:
    """Without a session: the original cross-origin iframe render test,
    unchanged — a real headless browser frames `url` from a deliberately
    different origin (the wrapper page) and checks whether real content
    renders inside it.

    With a session: NOT the same iframe technique — a hard browser
    constraint makes that structurally impossible here. A real session
    cookie's own SameSite attribute (DVWA's own PHPSESSID is
    SameSite=Strict, and even a bare SameSite=Lax already excludes this)
    means Chromium will never attach it to a cross-origin iframe's
    request no matter how the cookie is seeded into the context — and
    "just override the Cookie header on that one request" doesn't work
    either: Playwright's route.continue_(headers=...) silently drops
    Cookie (and a few other browser-managed headers) rather than sending
    whatever value is passed, confirmed live rather than assumed. Raising
    SameSite=None to sidestep this also requires Secure, which a
    plain-HTTP target (DVWA's own dev setup included) can never satisfy.

    So the authenticated path proves the equivalent thing a different
    way: a real, ordinary top-level navigation to `url` WITH the session
    (a same-site request from the browser's perspective, so the cookie
    attaches completely normally) confirms the page genuinely renders
    real authenticated content, and that exact response's own headers are
    checked for X-Frame-Options/frame-ancestors. Both together are the
    same underlying fact an iframe render would have shown — this
    specific authenticated response has no anti-framing protection — just
    established without literally watching it render inside a frame.
    """
    try:
        return await asyncio.wait_for(
            _attempt_clickjacking_proof(url, headless=headless, session=session),
            timeout=_HARD_PROOF_TIMEOUT_SECONDS,
        )
    except (TimeoutError, asyncio.TimeoutError):
        return ClickjackingProofResult(framable=False, screenshot_png=None)


async def _attempt_clickjacking_proof(
    url: str, *, headless: bool, session: AuthenticatedSession | None
) -> ClickjackingProofResult:
    if session is not None:
        return await _attempt_authenticated_clickjacking_proof(url, headless=headless, session=session)

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


async def _attempt_authenticated_clickjacking_proof(
    url: str, *, headless: bool, session: AuthenticatedSession
) -> ClickjackingProofResult:
    """See attempt_clickjacking_proof's docstring for why this doesn't
    frame the page at all."""
    response_headers: dict[str, str] = {}

    def _on_response(response) -> None:
        if response.url == url and not response_headers:
            response_headers.update(response.headers)

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=headless)
            context = await browser.new_context(ignore_https_errors=True)
            await seed_authenticated_context(context, session, url)
            page = await context.new_page()
            page.on("response", _on_response)
            try:
                await page.goto(url, wait_until="load", timeout=10_000)
            except PlaywrightError:
                await browser.close()
                return ClickjackingProofResult(framable=False, screenshot_png=None)

            has_content = await _page_has_real_content(page)
            protected = _response_blocks_framing(response_headers)
            framable = has_content and not protected
            screenshot = await page.screenshot(full_page=True) if framable else None
            await browser.close()
    except PlaywrightError:
        return ClickjackingProofResult(framable=False, screenshot_png=None)

    return ClickjackingProofResult(framable=framable, screenshot_png=screenshot)
