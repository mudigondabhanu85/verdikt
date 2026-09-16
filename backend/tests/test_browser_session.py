import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from playwright.async_api import async_playwright

from app.agents.browser_session import seed_authenticated_context
from app.agents.http_client import AuthenticatedSession


class _TwoPathFixtureHandler(BaseHTTPRequestHandler):
    """/account/login-landing and /other/page are both cookie-gated —
    real, unrelated paths on the same host, the way a session cookie set
    without an explicit Path attribute is expected to reach every path.
    The seed URL is deliberately nested (/account/...): Playwright's
    `url=`-based add_cookies derives the cookie's Path from that URL's
    own directory (confirmed here to be "/account/", not "/") — a
    top-level seed URL like "/login" would have coincidentally already
    resolved to path "/" and hidden the very bug this test exists to
    catch.
    """

    def do_GET(self):  # noqa: N802
        cookie_header = self.headers.get("Cookie", "")
        authed = "sid=real-session-value" in cookie_header
        if self.path in ("/account/login-landing", "/other/page"):
            body = b"AUTHENTICATED CONTENT" if authed else b"please log in"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):  # noqa: A002
        pass


def _server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _TwoPathFixtureHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_cookie_seeded_via_one_path_reaches_a_different_path_on_same_host():
    """The real bug this consolidation fixes: registering a cookie via
    Playwright's `url=` param derives the cookie's Path from that URL's
    own directory, not "/" — confirmed directly: seeding against
    ".../account/login-landing" produces a cookie scoped to path
    "/account/", which a request to the unrelated "/other/page" would
    never match. A cookie seeded via seed_authenticated_context's
    explicit domain+path="/" must reach both.
    """
    server, thread = _server()
    try:
        host, port = server.server_address
        session = AuthenticatedSession(credential_set_id=uuid.uuid4(), cookies={"sid": "real-session-value"})

        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            context = await browser.new_context()
            await seed_authenticated_context(context, session, f"http://{host}:{port}/account/login-landing")
            page = await context.new_page()

            await page.goto(f"http://{host}:{port}/account/login-landing")
            landing_text = await page.text_content("body")

            await page.goto(f"http://{host}:{port}/other/page")
            other_text = await page.text_content("body")

            await browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=2)

    assert landing_text == "AUTHENTICATED CONTENT"
    assert other_text == "AUTHENTICATED CONTENT"


async def test_bearer_token_applies_at_context_level():
    class _BearerHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            auth = self.headers.get("Authorization", "")
            body = b"OK" if auth == "Bearer test-token-123" else b"unauthorized"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):  # noqa: A002
            pass

    bearer_server = ThreadingHTTPServer(("127.0.0.1", 0), _BearerHandler)
    bearer_server.daemon_threads = True
    bearer_thread = threading.Thread(target=bearer_server.serve_forever, daemon=True)
    bearer_thread.start()
    try:
        host, port = bearer_server.server_address
        session = AuthenticatedSession(credential_set_id=uuid.uuid4(), bearer_token="test-token-123")

        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            context = await browser.new_context()
            await seed_authenticated_context(context, session, f"http://{host}:{port}/")
            page = await context.new_page()
            await page.goto(f"http://{host}:{port}/")
            text = await page.text_content("body")
            await browser.close()
    finally:
        bearer_server.shutdown()
        bearer_thread.join(timeout=2)

    assert text == "OK"


async def test_none_session_seeds_nothing_and_never_raises():
    server, thread = _server()
    try:
        host, port = server.server_address
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            context = await browser.new_context()
            await seed_authenticated_context(context, None, f"http://{host}:{port}/account/login-landing")
            page = await context.new_page()
            await page.goto(f"http://{host}:{port}/account/login-landing")
            text = await page.text_content("body")
            await browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=2)

    assert text == "please log in"
