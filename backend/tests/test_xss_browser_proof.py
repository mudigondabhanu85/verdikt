import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from app.agents.probing import ProbeTarget
from app.agents.xss_browser_proof import attempt_browser_proof


class _ReflectionFixtureHandler(BaseHTTPRequestHandler):
    """Two GET endpoints: /vulnerable reflects the "q" param raw into the
    HTML body (a real reflected-XSS sink); /safe HTML-escapes it first.
    """

    def do_GET(self):  # noqa: N802
        parsed = urlsplit(self.path)
        params = parse_qs(parsed.query)
        value = params.get("q", [""])[0]

        if parsed.path == "/vulnerable":
            body = f"<html><body>You searched for: {value}</body></html>".encode()
        elif parsed.path == "/safe":
            escaped = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            body = f"<html><body>You searched for: {escaped}</body></html>".encode()
        else:
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002
        pass


def _server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ReflectionFixtureHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_browser_proof_executes_on_genuinely_vulnerable_endpoint():
    server, thread = _server()
    try:
        host, port = server.server_address
        target = ProbeTarget(url=f"http://{host}:{port}/vulnerable?q=x", method="GET", param_name="q")

        result = await attempt_browser_proof(target, headless=True)

        assert result.executed is True
        assert result.screenshot_png is not None
        assert result.screenshot_png[:8] == b"\x89PNG\r\n\x1a\n"
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_browser_proof_does_not_execute_when_output_is_escaped():
    server, thread = _server()
    try:
        host, port = server.server_address
        target = ProbeTarget(url=f"http://{host}:{port}/safe?q=x", method="GET", param_name="q")

        result = await attempt_browser_proof(target, headless=True)

        assert result.executed is False
        assert result.screenshot_png is None
    finally:
        server.shutdown()
        thread.join(timeout=2)
