"""Login macro recorder/player (§4/§5) — Playwright-backed. An analyst
performs a real login once (including any manual OTP step); the tool
captures the action sequence as a reusable macro tied to a CredentialSet.
Any agent that needs a fresh session can replay the macro headlessly
instead of failing on session expiry mid-scan.
"""

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass

from playwright.async_api import Browser, Page, Playwright, async_playwright

from app.agents.http_client import AuthenticatedSession

# Chromium's own sandbox needs kernel namespace privileges Docker's
# default seccomp/capability profile doesn't grant — without
# --no-sandbox, launch() can fail/crash immediately inside a container
# (the standard, widely-documented Playwright-in-Docker gotcha; this is
# also exactly why a Chromium crash previously showed up in the browser
# as a misleading CORS error rather than any real message — a hard
# process crash drops the connection before app.main's global exception
# handler ever gets a chance to run). --disable-dev-shm-usage avoids a
# second, independent crash mode: Docker's default /dev/shm is only
# 64MB, too small for Chromium's shared memory needs under real
# rendering (as opposed to headless, which needs much less) — this
# makes it fall back to /tmp instead. The container is already Docker's
# own isolation boundary, so disabling Chromium's inner sandbox here
# doesn't remove process isolation, only one further layer of it —
# same tradeoff every "run headed Chromium in Docker" guide accepts.
# --disable-gpu/--disable-software-rasterizer: this container's Xvfb
# virtual display has no real GPU behind it — Chromium's GPU process
# crashing (rather than falling back cleanly) is a separate, common
# failure mode on top of the sandbox/shm ones above, and specific to
# headed mode rendering into a real (virtual) display; headless mode's
# rendering path doesn't hit this, which is why the existing
# headless-only agents (clickjacking/xss/dom_xss proofs) never needed
# these flags.
_CHROMIUM_DOCKER_ARGS = [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-software-rasterizer",
]

_RECORDER_INIT_SCRIPT = """
(() => {
  function cssPath(el) {
    if (el.id) return '#' + CSS.escape(el.id);
    if (el.name) return el.tagName.toLowerCase() + '[name="' + el.name.replace(/"/g, '\\\\"') + '"]';
    let path = [];
    let node = el;
    while (node && node.nodeType === 1 && path.length < 6) {
      let selector = node.tagName.toLowerCase();
      if (node.parentElement) {
        const siblings = Array.from(node.parentElement.children).filter(c => c.tagName === node.tagName);
        if (siblings.length > 1) {
          selector += ':nth-of-type(' + (siblings.indexOf(node) + 1) + ')';
        }
      }
      path.unshift(selector);
      node = node.parentElement;
    }
    return path.join(' > ');
  }

  document.addEventListener('input', (e) => {
    const el = e.target;
    if (!el || !el.tagName) return;
    if (el.tagName !== 'INPUT' && el.tagName !== 'TEXTAREA' && el.tagName !== 'SELECT') return;
    const type = (el.type || 'text').toLowerCase();
    const isSecret = type === 'password';
    window.__verdikt_record_step__({
      action: 'fill',
      selector: cssPath(el),
      value: isSecret ? null : el.value,
      input_type: type,
    });
  }, true);

  document.addEventListener('click', (e) => {
    const el = e.target.closest('button, a, input[type=submit], input[type=button]');
    if (!el) return;
    window.__verdikt_record_step__({
      action: 'click',
      selector: cssPath(el),
      value: null,
      input_type: null,
    });
  }, true);
})();
"""


@dataclass
class MacroStep:
    action: str  # "goto" | "click" | "fill"
    selector: str | None = None
    value: str | None = None
    field_role: str | None = None  # "username" | "password" | None
    url: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "MacroStep":
        return cls(**{k: data.get(k) for k in ("action", "selector", "value", "field_role", "url")})


def _infer_field_roles(steps: list[MacroStep]) -> list[MacroStep]:
    """Post-processing pass: the fill step immediately preceding a
    password fill, on a text/email input, is inferred as the username
    field — same heuristic as Phase 2's <form> auto-discovery
    (app.agents.login._guess_username_field), just applied to a recorded
    step sequence instead of a static form.
    """
    password_index = next(
        (i for i, s in enumerate(steps) if s.action == "fill" and s.field_role == "password"),
        None,
    )
    if password_index is None:
        return steps
    for i in range(password_index - 1, -1, -1):
        if steps[i].action == "fill" and steps[i].field_role is None:
            steps[i].field_role = "username"
            steps[i].value = None  # never store a typed username value either — replay substitutes it
            break
    return steps


def _build_steps(start_url: str, raw_steps: list[dict]) -> list[MacroStep]:
    steps = [MacroStep(action="goto", url=start_url)]
    for raw in raw_steps:
        field_role = "password" if raw.get("input_type") == "password" else None
        steps.append(
            MacroStep(
                action=raw["action"],
                selector=raw.get("selector"),
                value=raw.get("value"),
                field_role=field_role,
            )
        )
    return _infer_field_roles(steps)


@dataclass
class RecordingHandle:
    """Handle for a MacroRecorder.start()'d session, passed to finish()
    (or cancel()) once the analyst is done — see start()'s docstring for
    why recording is split into two phases instead of one call that
    blocks until the browser closes.
    """

    playwright: Playwright
    browser: Browser
    page: Page
    raw_steps: list[dict]
    start_url: str


class MacroRecorder:
    """Records a login action sequence. `drive`, if given, is awaited
    with the Page instead of waiting for a human to close the browser —
    lets tests simulate the analyst's interaction programmatically while
    exercising the exact same recording mechanism used interactively.
    """

    async def record(
        self,
        start_url: str,
        *,
        headless: bool = False,
        drive: Callable[[Page], Awaitable[None]] | None = None,
    ) -> list[MacroStep]:
        raw_steps: list[dict] = []

        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=headless, args=_CHROMIUM_DOCKER_ARGS)
            page = await browser.new_page()
            await page.expose_function("__verdikt_record_step__", lambda step: raw_steps.append(step))
            await page.add_init_script(_RECORDER_INIT_SCRIPT)
            await page.goto(start_url)

            if drive is not None:
                await drive(page)
                await browser.close()
            else:
                # Real interactive use: block until the analyst finishes
                # (including any manual OTP entry) and closes the browser.
                await page.wait_for_event("close", timeout=0)

        return _build_steps(start_url, raw_steps)

    async def start(self, start_url: str, *, headless: bool = False) -> RecordingHandle:
        """Split-phase counterpart to record(), for the interactive HTTP
        flow (app.api.routes.credentials' record-macro/start + .../finish):
        launches the browser and returns immediately instead of blocking
        a single HTTP request until someone closes it.

        record()'s "block until the browser closes" design assumed the
        analyst could reliably find and click the browser window's own
        close button — true on a real local display, but not once that
        window is only reachable through a VNC-streamed, scaled-down
        canvas (app.agents.macro's Docker/Xvfb path): a dropped VNC
        connection, or simply not finding the remote window's close
        button through the scaling, meant record()'s
        page.wait_for_event("close") sometimes never fired at all —
        silently losing the whole recording with no error, since the
        HTTP request itself was still just... waiting. finish() below
        closes the browser explicitly, itself, the moment the analyst
        clicks "Finish recording" in the Verdikt UI — no dependency on
        finding a control inside the remote view at all.
        """
        playwright = await async_playwright().start()
        try:
            browser = await playwright.chromium.launch(headless=headless, args=_CHROMIUM_DOCKER_ARGS)
            raw_steps: list[dict] = []
            # Internal staging/pre-prod targets routinely sit behind a
            # self-signed or internal-CA cert Chromium doesn't trust out
            # of the box (a real incident: net::ERR_CERT_AUTHORITY_INVALID
            # crashed this whole endpoint with an unhandled exception,
            # which — same as the earlier Playwright-crash-looks-like-CORS
            # incident — surfaces client-side as a misleading CORS error,
            # not the real cert problem). This is an authorized analyst
            # recording a login flow against a target they already have
            # scope over, not a real end-user's browser, so ignoring cert
            # trust here is the correct call, not a security downgrade.
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            await page.expose_function("__verdikt_record_step__", lambda step: raw_steps.append(step))
            await page.add_init_script(_RECORDER_INIT_SCRIPT)
            await page.goto(start_url)
        except Exception:
            await playwright.stop()
            raise
        return RecordingHandle(
            playwright=playwright, browser=browser, page=page, raw_steps=raw_steps, start_url=start_url
        )

    async def finish(self, handle: RecordingHandle) -> list[MacroStep]:
        """Closes the browser server-side and builds the same MacroStep
        list record() would have. Idempotent-ish in intent but not
        actually safe to call twice — the route layer is responsible for
        popping the handle out of its registry before calling this, so
        a second call can't happen (see credentials.py).
        """
        try:
            await handle.browser.close()
        finally:
            await handle.playwright.stop()
        return _build_steps(handle.start_url, handle.raw_steps)

    async def cancel(self, handle: RecordingHandle) -> None:
        """Analyst-initiated abort — closes the browser, discards
        whatever was captured so far, no LoginMacro row created.
        """
        try:
            await handle.browser.close()
        finally:
            await handle.playwright.stop()


@dataclass
class MacroReplayResult:
    """Richer than a bare AuthenticatedSession | None — "some cookies came
    back" is a weak signal on its own (plenty of apps set a session/CSRF
    cookie on the login page itself, before any credentials are even
    checked), which is exactly the gap behind "how do we know the
    application actually accepted the login": still_shows_password_field
    is the real corroborating signal — a login form still visible on the
    page the macro ended on almost always means the recorded steps didn't
    actually authenticate, no matter how many cookies got set along the
    way. Used both by the interactive replay-test route (an analyst
    checking a recorded macro directly) and by SessionManager._login_via_macro
    (every real scan's own macro-based login attempt).
    """

    session: AuthenticatedSession | None
    cookie_count: int
    final_url: str
    final_status: int | None
    still_shows_password_field: bool


class MacroPlayer:
    """Headless replay of a recorded macro, substituting a CredentialSet's
    decrypted username/secret into the username/password-role fill steps.
    Only cookie-based sessions are extracted (§4's target case for macro
    recording is classic form-login apps; SPA/token logins already have
    Phase 2's explicit-config path) — documented limitation, not a bug.
    """

    async def replay(
        self,
        steps: list[MacroStep],
        *,
        credential_set_id: uuid.UUID,
        username: str,
        password: str,
        headless: bool = True,
    ) -> MacroReplayResult:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=headless, args=_CHROMIUM_DOCKER_ARGS)
            # See MacroRecorder.start's identical rationale — replay hits
            # the same real (possibly self-signed/internal-CA) target
            # every scan's login step, not a real end-user's browser.
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()

            # Tracks the status of the last real page navigation (the
            # initial goto, plus any full-page navigation a later click
            # triggers) — a click-driven SPA login that never navigates
            # simply leaves this at the initial page load's status,
            # which is an honest reflection of what this mechanism can
            # actually observe (§4's documented classic-form-login scope).
            last_status: dict[str, int | None] = {"status": None}

            def _on_response(response) -> None:
                request = response.request
                if request.is_navigation_request() and request.frame == page.main_frame:
                    last_status["status"] = response.status

            page.on("response", _on_response)

            for step in steps:
                if step.action == "goto" and step.url:
                    await page.goto(step.url)
                elif step.action == "fill" and step.selector:
                    value = step.value
                    if step.field_role == "username":
                        value = username
                    elif step.field_role == "password":
                        value = password
                    await page.fill(step.selector, value or "")
                elif step.action == "click" and step.selector:
                    await page.click(step.selector)
                    try:
                        await page.wait_for_load_state("networkidle", timeout=3000)
                    except Exception:  # noqa: BLE001 — best-effort settle, never fatal
                        pass

            cookies = await context.cookies()
            final_url = page.url
            # Visible, specifically — some real post-login dashboards
            # legitimately have an unrelated, hidden password input
            # somewhere in the DOM (a reauth-to-confirm modal, a
            # password-change widget not currently open); only a
            # password field the page is actually presenting to the
            # user is a real "still on the login page" signal.
            password_fields = await page.query_selector_all("input[type=password]")
            still_shows_password_field = any([await field.is_visible() for field in password_fields])
            await browser.close()

        cookie_dict = {c["name"]: c["value"] for c in cookies}
        session = (
            AuthenticatedSession(credential_set_id=credential_set_id, cookies=cookie_dict) if cookie_dict else None
        )
        return MacroReplayResult(
            session=session,
            cookie_count=len(cookie_dict),
            final_url=final_url,
            final_status=last_status["status"],
            still_shows_password_field=still_shows_password_field,
        )
