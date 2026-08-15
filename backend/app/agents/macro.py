"""Login macro recorder/player (§4/§5) — Playwright-backed. An analyst
performs a real login once (including any manual OTP step); the tool
captures the action sequence as a reusable macro tied to a CredentialSet.
Any agent that needs a fresh session can replay the macro headlessly
instead of failing on session expiry mid-scan.
"""

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass

from playwright.async_api import Page, async_playwright

from app.agents.http_client import AuthenticatedSession

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
            browser = await playwright.chromium.launch(headless=headless)
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
    ) -> AuthenticatedSession | None:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=headless)
            context = await browser.new_context()
            page = await context.new_page()

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
            await browser.close()

        if not cookies:
            return None

        cookie_dict = {c["name"]: c["value"] for c in cookies}
        return AuthenticatedSession(credential_set_id=credential_set_id, cookies=cookie_dict)
