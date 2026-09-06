"""Universal evidence screenshots (§8) for finding types with nothing
browser-observable to prove — SQL injection, access control, business
logic, header/config, auth, CSRF, and every other HTTP-level-only check.
XSS, clickjacking, DOM-XSS, stored XSS, and prototype pollution already
capture a *real* browser-rendered screenshot proving actual exploitation
(see app.agents.xss_browser_proof, app.agents.clickjacking,
app.agents.dom_xss, app.agents.stored_xss, app.agents.prototype_pollution)
and must not go through this path.

Per docs/BUILD_SPEC.md §8: "For API-only findings with nothing to
render, capture an annotated, syntax-highlighted request/response pair
instead of a screenshot, so the evidence bundle is always visual and
self-explanatory without hunting for a separate attachment." This
renders exactly that — a real PNG of the request/response pair, via a
headless Playwright page rather than a Pillow+font stack (Playwright is
already a hard dependency here; managing cross-platform monospace font
availability for Pillow is a real, separate risk this avoids).
"""

import asyncio
import uuid

from playwright.async_api import Browser, Error as PlaywrightError, async_playwright

from app.agents.evidence import _strip_nul_bytes
from app.storage.local_disk import get_object_storage

_TRUNCATE = 2000

# A fresh Playwright browser launch is ~100-300ms — negligible for one
# finding, but a single agent run can legitimately confirm hundreds of
# findings in one pass (header_config confirmed 291 in a real scan this
# session against a HAR-seeded target). One shared, lazily-created
# browser instance avoids re-paying that launch cost per finding within
# one scan run (one asyncio event loop); a fresh *page* per capture
# (cheap) keeps captures independent.
#
# Real, observed bug: caching the browser at module scope naively hung
# indefinitely the second time it was reused across two different
# asyncio event loops (e.g. pytest-asyncio's default function-scoped
# loop — a fresh loop per test function) — a Playwright async Browser's
# connection is tied to the specific event loop it was created on, and
# reusing it from a different one doesn't error, it just hangs waiting
# on a transport that will never respond. Tracking which loop the cached
# browser belongs to and discarding/recreating on a mismatch (rather
# than trusting `is_connected()`, which doesn't detect this case) fixes
# it for both real scan runs (one loop, real caching benefit) and tests
# (a fresh loop per test, safely gets a fresh browser each time).
_shared_browser: Browser | None = None
_shared_browser_loop: asyncio.AbstractEventLoop | None = None
_shared_browser_lock = asyncio.Lock()
_playwright_cm = None


async def _get_shared_browser() -> Browser:
    global _shared_browser, _shared_browser_loop, _playwright_cm
    async with _shared_browser_lock:
        current_loop = asyncio.get_running_loop()
        stale = _shared_browser_loop is not None and _shared_browser_loop is not current_loop
        if stale or _shared_browser is None or not _shared_browser.is_connected():
            _playwright_cm = async_playwright()
            playwright = await _playwright_cm.start()
            _shared_browser = await playwright.chromium.launch(headless=True)
            _shared_browser_loop = current_loop
        return _shared_browser


def _escape_html(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _evidence_html(title: str, request_raw: str, response_raw: str) -> str:
    request_trunc = _strip_nul_bytes(request_raw or "")[:_TRUNCATE]
    response_trunc = _strip_nul_bytes(response_raw or "")[:_TRUNCATE]
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  body {{
    margin: 0; padding: 24px; background: #1e1e2e; color: #cdd6f4;
    font-family: -apple-system, "Segoe UI", sans-serif;
  }}
  h1 {{ font-size: 18px; margin: 0 0 16px; color: #f38ba8; }}
  .section-label {{
    font-size: 12px; text-transform: uppercase; letter-spacing: .05em;
    color: #89b4fa; margin: 20px 0 6px; font-weight: 700;
  }}
  pre {{
    background: #11111b; border: 1px solid #313244; border-radius: 6px;
    padding: 14px; margin: 0; white-space: pre-wrap; word-break: break-word;
    font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 13px;
    line-height: 1.5; color: #a6e3a1;
  }}
  pre.response {{ color: #f9e2af; }}
</style></head>
<body>
  <h1>Evidence — {_escape_html(title)}</h1>
  <div class="section-label">Request</div>
  <pre>{_escape_html(request_trunc)}</pre>
  <div class="section-label">Response</div>
  <pre class="response">{_escape_html(response_trunc)}</pre>
</body></html>"""


async def capture_evidence_screenshot(
    *, title: str, request_raw: str, response_raw: str, headless: bool = True
) -> bytes | None:
    """Renders a real PNG of the given request/response pair. Returns
    None (never raises) on any Playwright failure — evidence capture
    failing must never fail the scan, matching every other browser-proof
    path in this codebase (see app.agents.xss_browser_proof).
    """
    try:
        browser = await _get_shared_browser() if headless else None
        own_browser = None
        if browser is None:
            playwright_cm = async_playwright()
            playwright = await playwright_cm.start()
            own_browser = await playwright.chromium.launch(headless=headless)
            browser = own_browser
        page = await browser.new_page()
        try:
            await page.set_content(_evidence_html(title, request_raw, response_raw))
            return await page.screenshot(full_page=True)
        finally:
            await page.close()
            if own_browser is not None:
                await own_browser.close()
    except PlaywrightError:
        return None
    except Exception:  # noqa: BLE001 — evidence capture must never crash a scan
        return None


async def capture_and_store_evidence_screenshot(
    *, scan_run_id: uuid.UUID, check_id: str, title: str, request_raw: str, response_raw: str
) -> list[str]:
    """Convenience wrapper matching the shape every Evidence() call site
    needs: capture, persist to object storage under the same
    `{category}/{scan_run_id}/{uuid}.png` key convention the real
    browser-proof screenshots already use (see app.agents.xss's
    _persist_confirmed_finding), and return a ready-to-use
    screenshot_refs list — [] (not a raised error) if capture failed.
    """
    png = await capture_evidence_screenshot(title=title, request_raw=request_raw, response_raw=response_raw)
    if png is None:
        return []
    storage = get_object_storage()
    key = f"evidence-screenshot/{check_id}/{scan_run_id}/{uuid.uuid4().hex}.png"
    await storage.put(key, png, content_type="image/png")
    return [key]
