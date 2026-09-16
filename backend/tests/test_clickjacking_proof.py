import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.agents.clickjacking_proof import attempt_clickjacking_proof


class _ClickjackingFixtureHandler(BaseHTTPRequestHandler):
    """/framable has no protection; /blocked sends X-Frame-Options: DENY."""

    def do_GET(self):  # noqa: N802
        if self.path == "/framable":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>sensitive account settings</body></html>")
        elif self.path == "/blocked":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(b"<html><body>sensitive account settings</body></html>")
        elif self.path == "/blank_but_unblocked":
            # No X-Frame-Options/CSP at all (so nothing blocks the framing
            # itself), but nothing real renders either — the real,
            # live-found shape of a login-gated page this check never
            # carries a session for, and the exact false positive
            # app.agents.clickjacking_proof's content check exists to
            # catch.
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body></body></html>")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):  # noqa: A002
        pass


def _server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ClickjackingFixtureHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_page_without_protection_is_confirmed_framable():
    server, thread = _server()
    try:
        host, port = server.server_address
        result = await attempt_clickjacking_proof(f"http://{host}:{port}/framable", headless=True)

        assert result.framable is True
        assert result.screenshot_png is not None
        assert result.screenshot_png[:8] == b"\x89PNG\r\n\x1a\n"
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_page_with_x_frame_options_deny_is_not_framable():
    server, thread = _server()
    try:
        host, port = server.server_address
        result = await attempt_clickjacking_proof(f"http://{host}:{port}/blocked", headless=True)

        assert result.framable is False
        assert result.screenshot_png is None
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_unblocked_but_empty_page_is_not_a_false_positive():
    # No X-Frame-Options/CSP present — an old, naive "not blocked ==
    # framable" check would have wrongly confirmed this one too.
    server, thread = _server()
    try:
        host, port = server.server_address
        result = await attempt_clickjacking_proof(f"http://{host}:{port}/blank_but_unblocked", headless=True)

        assert result.framable is False
        assert result.screenshot_png is None
    finally:
        server.shutdown()
        thread.join(timeout=2)
