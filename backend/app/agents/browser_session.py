"""Shared helper for seeding a real Playwright browser context with an
AuthenticatedSession — consolidates three independently-evolved copies
(app.agents.xss_browser_proof had two, app.agents.stored_xss a third)
that had accumulated real, subtle inconsistencies between them:

- Cookies were registered via `context.add_cookies([{..., "url": url}])`
  using whichever URL that particular call site happened to have handy
  (a per-payload URL in one copy, the first candidate URL in another).
  Playwright derives the cookie's effective domain *and path* from that
  URL when no explicit domain/path is given — a real session cookie
  (set by the server with no Path attribute, which defaults to
  host-wide) registered this way could silently stop being sent the
  moment a check navigates to a different path than the one the cookie
  happened to be seeded against, looking exactly like "not logged in"
  with no error anywhere. Explicit `domain` + `path="/"` is what an
  unscoped real session cookie actually means and is what every one of
  these three copies was trying to approximate with a workaround.
- The Authorization header was set on individual `page` objects, at a
  different point in each copy relative to when the page/context were
  created — functionally fine for a single-page check, but page-level
  means a fresh page created later in the same context (or a redirect
  target) would silently lose it if a future copy forgot to repeat the
  same call.
- None of the three ever seeded localStorage — not a regression (nothing
  in this codebase captures localStorage-held auth today), but a real
  gap for the day a SPA login path that does exists, now closed once
  here instead of needing to be remembered three more times.

Call this exactly once, immediately after `browser.new_context(...)` and
before creating or navigating any page — context-level cookies/headers/
init-scripts apply to every page and every future navigation in that
context, so seeding here (rather than per-page or per-payload) is both
simpler and the actual fix for the cookie-path bug above.
"""

import json
from urllib.parse import urlsplit

from app.agents.http_client import AuthenticatedSession


async def seed_authenticated_context(
    context, session: AuthenticatedSession | None, reference_url: str
) -> None:
    if session is None:
        return

    if session.cookies:
        host = urlsplit(reference_url).hostname or ""
        await context.add_cookies(
            [
                {"name": name, "value": value, "domain": host, "path": "/"}
                for name, value in session.cookies.items()
            ]
        )

    if session.bearer_token:
        await context.set_extra_http_headers({"Authorization": f"Bearer {session.bearer_token}"})

    if session.local_storage:
        # localStorage is origin-scoped and isn't reachable via
        # add_cookies at all — an init script is the only mechanism that
        # reliably runs before a page's own scripts on every future
        # navigation in this context. A page.evaluate() call after the
        # fact would be too late for the very first navigation, and
        # simply wrong for a navigation to a different origin than
        # whatever the context happened to already have loaded.
        # json.dumps both escapes the values safely for embedding in JS
        # and produces syntax that's already valid JS (JSON is a JS
        # literal subset), so no separate JS-string-escaping is needed.
        pairs = json.dumps(list(session.local_storage.items()))
        await context.add_init_script(
            f"for (const [k, v] of {pairs}) window.localStorage.setItem(k, v);"
        )
