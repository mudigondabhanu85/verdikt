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

import asyncio
import uuid
from dataclasses import dataclass

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright

from app.agents.browser_session import seed_authenticated_context
from app.agents.http_client import AuthenticatedSession
from app.agents.probing import ProbeTarget, build_request

# Same defensive backstop as app.agents.http_client's
# _HARD_REQUEST_TIMEOUT_SECONDS, applied to every function in this module:
# playwright.chromium.launch() and page.evaluate() have no timeout of
# their own the way page.goto() does, and a real, live-found scan hang
# (app.agents.csp_bypass_proof, under heavy concurrent Playwright load
# from many checks launching browsers at once) proved this can leave a
# scan stuck at "running" forever with zero error and no diagnosable
# cause. Wrapping every attempt in one explicit asyncio-level deadline
# guarantees forward progress regardless of which specific call inside
# it doesn't return.
_HARD_PROOF_TIMEOUT_SECONDS = 30.0


@dataclass
class BrowserProofResult:
    executed: bool
    screenshot_png: bytes | None
    # Which of _xss_execution_payloads actually executed — None when
    # executed=False. Callers cite this in a Finding's reproduction
    # steps instead of assuming the plain <script> variant, since a
    # filter that strips "script" (DVWA Medium/High, and plenty of real
    # apps) is exactly the case the second payload exists to survive.
    payload: str | None = None


def _proof_marker() -> str:
    # No English prefix on purpose — "verdikt_proof_" (the original
    # prefix here) supplies exactly the "p" that a filter like DVWA
    # High's needs to complete its <(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t regex
    # against the surrounding `<img src=... onerror='window["{marker}"]=
    # true'>` skeleton, which otherwise has every other required letter
    # (s/src, c/src, r/onerror, i/window, t/true) but no "p" of its own.
    # A pure lowercase-hex marker can only ever contribute a-f, none of
    # which is s/i/p/t, so it can never complete that sequence no matter
    # what random hex comes out — see _xss_execution_payloads' docstring
    # for the full reasoning.
    return f"vfy{uuid.uuid4().hex[:12]}"


def visible_proof_banner_js(marker: str) -> str:
    """Injects an unmissable on-page proof of execution — the
    `window[marker]` flag alone is reliable, deterministic proof for
    `page.evaluate()` to check, but is invisible, so the resulting
    screenshot looked identical to a normal, unexploited page (a real
    complaint: "I don't see an XSS pop up, I just see the page"). A
    native `alert()` can't be used for this instead — Playwright/Chrome
    auto-dismisses or blocks JS dialogs, and even if it didn't, a native
    dialog is browser-chrome UI rendered outside the page's own DOM, so
    `page.screenshot()` can never capture it regardless. This renders a
    centered modal styled to read unambiguously as a real pop-up dialog
    ("This page says" + message + OK button, the same shape a real
    alert() takes) rather than a banner, which a second real complaint
    found didn't read as "a pop-up" even though it was genuine proof.

    Built with plain createElement/textContent, not innerHTML, and using
    only double quotes throughout — this same string also gets embedded
    inside a single-quoted `onerror='...'` HTML attribute value
    elsewhere (_xss_execution_payloads below), and a stray single quote here
    would prematurely terminate that attribute and corrupt the payload.
    """
    return (
        f'var o=document.createElement("div");'
        f'o.style.cssText="position:fixed;inset:0;background:rgba(0,0,0,.4);'
        f"z-index:2147483647;display:flex;align-items:center;justify-content:center;"
        f'font-family:-apple-system,sans-serif";'
        f'var d=document.createElement("div");'
        f'd.style.cssText="background:#fff;border-radius:8px;'
        f'box-shadow:0 10px 40px rgba(0,0,0,.45);min-width:300px;max-width:440px";'
        f'var t=document.createElement("div");'
        f't.textContent="This page says";'
        f't.style.cssText="padding:16px 18px 0;font:13px -apple-system,sans-serif;color:#5f6368";'
        f'var m=document.createElement("div");'
        f'm.textContent="\\u26a0 XSS PROOF-OF-CONCEPT \\u2014 JavaScript executed by Verdikt '
        f'(marker: {marker})";'
        f'm.style.cssText="padding:10px 18px 18px;font:14px -apple-system,sans-serif;'
        f'color:#202124;word-break:break-word";'
        f'var f=document.createElement("div");'
        f'f.style.cssText="padding:10px 16px;text-align:right;border-top:1px solid #e8eaed";'
        f'var k=document.createElement("button");'
        f'k.textContent="OK";'
        f'k.style.cssText="background:#1a73e8;color:#fff;border:0;border-radius:4px;'
        f'padding:8px 22px;font:14px -apple-system,sans-serif;cursor:pointer";'
        f"f.appendChild(k);d.appendChild(t);d.appendChild(m);d.appendChild(f);o.appendChild(d);"
        f"document.documentElement.appendChild(o);"
    )


# Paired with the real, banner-JS-carrying payloads below purely for
# reporting: a Finding's reproduction steps should read as a normal
# proof-of-concept an analyst can act on, not our internal window-flag +
# on-page-banner plumbing verbatim.
_DISPLAY_PAYLOADS = (
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
)


# Shared by both proof functions below. Two variants because a naive
# <script> tag is exactly what the weakest real-world filters strip —
# DVWA Medium's reflected-XSS filter is a literal `str_replace('<script>',
# '', $input)`, and DVWA High's is a regex matching "s.c.r.i.p.t" — both
# defeat a plain <script> payload while leaving the underlying reflection
# genuinely exploitable via a payload that never contains that substring.
# A real, live-found gap: DVWA Medium's reflected XSS was confirmed
# reflected (raw HTTP probe) but never browser-execution-confirmed, so it
# fell back to a ReviewCandidate every time even though this second
# payload proves it's a real, auto-confirmable Finding. Also used by
# attempt_dom_xss_fragment_proof below, since a <script> tag inserted via
# innerHTML does NOT execute per the HTML spec but an event-handler-
# bearing element (onerror) does — different sinks, same two payloads
# happen to cover both.
#
# The real_payload carries ONLY the flag-set — never the visible_proof_banner_js
# inline. A second, live-found gap: the original version *did* inline the
# full banner script here, and that banner's own English/JS text (words
# like "createElement", "appendChild", "cssText") is long enough that it
# almost always contains the letters s, c, r, i, p, t *somewhere* later in
# the string in that relative order — exactly the pattern DVWA High's
# regex (and plenty of real-world WAFs using the same "does this loosely
# resemble <script>" heuristic) matches on, greedily eating everything
# from the opening "<" through that incidental "t" and mangling the
# payload into a harmless fragment. `window["{marker}"]=true` alone has no
# "s" in it at all (the <img> wrapper's own "src" does have one, but
# nothing after it up to the closing quote ever supplies the "p" the
# pattern also needs), so it survives filters that strip anything
# resembling a <script> tag. The banner is drawn afterward, directly via
# page.evaluate() once execution is already confirmed — Playwright
# injecting it client-side never goes through the target's own filter at
# all, so its length/content is irrelevant to detection.
#
# Returns (real_payload, display_payload) pairs — real_payload is what's
# actually sent/navigated to (carries only the window-flag set);
# display_payload is what a Finding's write-up should cite instead.
def _xss_execution_payloads(marker: str) -> list[tuple[str, str]]:
    real_payloads = (
        f'<script>window["{marker}"]=true;</script>',
        f'<img src=x onerror=\'window["{marker}"]=true\'>',
    )
    return list(zip(real_payloads, _DISPLAY_PAYLOADS))


_NAVIGATION_TIMEOUT_MS = 10_000


async def attempt_browser_proof(
    target: ProbeTarget,
    *,
    headless: bool = True,
    session: AuthenticatedSession | None = None,
) -> BrowserProofResult:
    """Only meaningful for target.method == "GET" — see module docstring.
    Callers are responsible for checking that before calling this.
    """
    try:
        return await asyncio.wait_for(
            _attempt_browser_proof(target, headless=headless, session=session),
            timeout=_HARD_PROOF_TIMEOUT_SECONDS,
        )
    except (TimeoutError, asyncio.TimeoutError):
        return BrowserProofResult(executed=False, screenshot_png=None)


async def _attempt_browser_proof(
    target: ProbeTarget,
    *,
    headless: bool,
    session: AuthenticatedSession | None,
) -> BrowserProofResult:
    """A fresh Playwright browser context carries no cookies at all, which
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

    executed = False
    screenshot = None
    winning_payload: str | None = None

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=headless)
        # See app.agents.macro's identical fix/rationale — an internal
        # staging target's self-signed/internal-CA cert shouldn't fail
        # this check when the analyst already has authorized, scoped
        # access to it.
        context = await browser.new_context(ignore_https_errors=True)
        await seed_authenticated_context(context, session, target.url)
        page = await context.new_page()
        try:
            for payload, display_payload in _xss_execution_payloads(marker):
                url, _body, _content_type = build_request(target, payload)
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
                if executed:
                    winning_payload = display_payload
                    break
            if executed:
                # The banner is injected here, client-side via Playwright,
                # never as part of the payload the target itself sees —
                # see _xss_execution_payloads' docstring for why that
                # distinction is what makes this proof reliable against a
                # filter like DVWA High's at all.
                await page.evaluate(visible_proof_banner_js(marker))
                screenshot = await page.screenshot(full_page=True)
        except PlaywrightError:
            # Target unreachable from a real browser (DNS, TLS, timeout,
            # etc.), a synthetic test double the httpx-level agent could
            # reach but no browser can, or any other navigation failure —
            # treat as "proof not obtained", not a scan-crashing error.
            # The caller falls back to queuing a ReviewCandidate instead.
            executed = False
            screenshot = None
            winning_payload = None
        finally:
            await browser.close()

    return BrowserProofResult(executed=executed, screenshot_png=screenshot, payload=winning_payload)


async def attempt_dom_xss_fragment_proof(
    url: str,
    *,
    headless: bool = True,
    session: AuthenticatedSession | None = None,
    fragment_param_names: list[str] | None = None,
) -> BrowserProofResult:
    """Loads `url` with an XSS payload appended as the URL fragment
    (`#...`), which never reaches the server — real execution here proves
    a client-side JS sink reads location.hash/location.href and writes it
    somewhere unsafe (innerHTML, document.write, eval, ...), independent
    of anything the server itself does.

    Tries the bare fragment (`#<payload>`) first, then — if given any
    `fragment_param_names` — a `#{name}=<payload>` framing for each one.
    A real, live-found gap: a bare fragment alone misses any page whose
    own client-side JS parses the hash as `key=value` rather than reading
    the whole thing raw (a very common real-world pattern — hash-based
    SPA routing, "current tab" state, and DVWA High's own DOM-XSS page
    all work this way: `document.location.href.indexOf("default=")`
    requires the literal substring "default=" to be present before the
    sink even fires, silently doing nothing for a bare-fragment payload
    that never contains it). `fragment_param_names` should be whatever
    parameter/field names were already discovered for this exact URL
    elsewhere (a query string or a GET form) — a hash-parsing sink
    overwhelmingly reuses the same name as the page's own visible
    query-string convention, not an arbitrary new one.

    Same login-gated-page gap as attempt_browser_proof above applies here
    too — a DOM XSS sink on a page you can't even reach without a session
    cookie never gets a chance to run.
    """
    try:
        return await asyncio.wait_for(
            _attempt_dom_xss_fragment_proof(
                url, headless=headless, session=session, fragment_param_names=fragment_param_names
            ),
            timeout=_HARD_PROOF_TIMEOUT_SECONDS,
        )
    except (TimeoutError, asyncio.TimeoutError):
        return BrowserProofResult(executed=False, screenshot_png=None)


async def _attempt_dom_xss_fragment_proof(
    url: str,
    *,
    headless: bool,
    session: AuthenticatedSession | None,
    fragment_param_names: list[str] | None,
) -> BrowserProofResult:
    marker = _proof_marker()
    executed = False
    screenshot = None
    winning_payload: str | None = None
    fragment_prefixes = ["", *(f"{name}=" for name in dict.fromkeys(fragment_param_names or []))]

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=headless)
            context = await browser.new_context(ignore_https_errors=True)
            await seed_authenticated_context(context, session, url)
            page = await context.new_page()
            for prefix in fragment_prefixes:
                for payload, display_payload in _xss_execution_payloads(marker):
                    # A navigation that changes only the fragment is treated
                    # by the browser as same-document (fires "hashchange",
                    # no reload) — the page's own <script> block, which is
                    # what actually reads location.hash, would never re-run
                    # for a second payload attempt without forcing a real
                    # fresh navigation first.
                    await page.goto("about:blank")
                    await page.goto(
                        f"{url}#{prefix}{payload}", wait_until="load", timeout=_NAVIGATION_TIMEOUT_MS
                    )
                    executed = bool(await page.evaluate(f'window["{marker}"] === true'))
                    if executed:
                        winning_payload = f"{prefix}{display_payload}"
                        break
                if executed:
                    break
            if executed:
                await page.evaluate(visible_proof_banner_js(marker))
                screenshot = await page.screenshot(full_page=True)
            await browser.close()
    except PlaywrightError:
        # Same reasoning as attempt_browser_proof above: unreachable
        # target or any other navigation failure means "proof not
        # obtained", not a vulnerability claim and not a crash.
        return BrowserProofResult(executed=False, screenshot_png=None)

    return BrowserProofResult(executed=executed, screenshot_png=screenshot, payload=winning_payload)
