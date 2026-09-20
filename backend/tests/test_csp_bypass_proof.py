import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from app.agents.csp_bypass_proof import attempt_csp_bypass_proof


class _CspFixtureHandler(BaseHTTPRequestHandler):
    """/protected-self sends `script-src 'self'` (same-origin scripts
    allowed — the precondition this bypass needs); /protected-none sends
    `script-src 'none'` (nothing runs, not even same-origin — the real
    negative case a working CSP looks like). /jsonp reflects its
    "callback" parameter completely unescaped, exactly like DVWA's own
    teaching example (§14).
    """

    def do_GET(self):  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/protected-self":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Security-Policy", "script-src 'self'")
            self.end_headers()
            self.wfile.write(b"<html><body>protected page</body></html>")
        elif parsed.path == "/protected-none":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Security-Policy", "script-src 'none'")
            self.end_headers()
            self.wfile.write(b"<html><body>protected page</body></html>")
        elif parsed.path == "/jsonp":
            callback = parse_qs(parsed.query).get("callback", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(f'{callback}({{"answer":15}})'.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):  # noqa: A002
        pass


def _server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CspFixtureHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_script_src_self_allows_the_jsonp_gadget_through():
    server, thread = _server()
    try:
        host, port = server.server_address
        page_url = f"http://{host}:{port}/protected-self"
        template = f"http://{host}:{port}/jsonp?callback={{callback}}"

        result = await attempt_csp_bypass_proof(page_url, template)

        assert result.executed is True
        assert result.screenshot_png is not None
        assert result.screenshot_png[:8] == b"\x89PNG\r\n\x1a\n"
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_script_src_none_genuinely_blocks_it():
    server, thread = _server()
    try:
        host, port = server.server_address
        page_url = f"http://{host}:{port}/protected-none"
        template = f"http://{host}:{port}/jsonp?callback={{callback}}"

        result = await attempt_csp_bypass_proof(page_url, template)

        assert result.executed is False
        assert result.screenshot_png is None
    finally:
        server.shutdown()
        thread.join(timeout=2)
