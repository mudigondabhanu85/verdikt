import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.integrations.vgs.client import VGSClient, VGSPushError


def _make_handler(*, accept: bool):
    received = []
    received_headers = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            received.append(self.rfile.read(length))
            received_headers.append(dict(self.headers))
            if accept:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            else:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"internal error")

        def log_message(self, format, *args):  # noqa: A002
            pass

    return Handler, received, received_headers


def _server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_push_findings_sends_the_documented_payload_shape():
    handler, received, _headers = _make_handler(accept=True)
    server, thread = _server(handler)
    try:
        host, port = server.server_address
        client = VGSClient(f"http://{host}:{port}/ingest")
        findings = [{"check_id": "missing-hsts", "severity": "Low"}]
        await client.push_findings("scan-run-1", findings)

        assert len(received) == 1
        payload = json.loads(received[0])
        assert payload["source"] == "ai-multi-agent"
        assert payload["scan_run_id"] == "scan-run-1"
        assert payload["findings"] == findings
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_push_findings_raises_on_rejection():
    handler, _received, _headers = _make_handler(accept=False)
    server, thread = _server(handler)
    try:
        host, port = server.server_address
        client = VGSClient(f"http://{host}:{port}/ingest")
        try:
            await client.push_findings("scan-run-1", [])
            raise AssertionError("expected VGSPushError")
        except VGSPushError as exc:
            assert "500" in str(exc)
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_push_findings_raises_on_unreachable_host():
    client = VGSClient("http://127.0.0.1:1/ingest")
    try:
        await client.push_findings("scan-run-1", [])
        raise AssertionError("expected VGSPushError")
    except VGSPushError:
        pass


async def test_push_findings_with_no_auth_configured_sends_no_auth_header():
    """Backward compatibility: existing configs created before auth_type
    existed (auth_type=None) must keep working exactly as before — the
    real, connected VGS instance has no auth of its own at all."""
    handler, _received, received_headers = _make_handler(accept=True)
    server, thread = _server(handler)
    try:
        host, port = server.server_address
        client = VGSClient(f"http://{host}:{port}/ingest")
        await client.push_findings("scan-run-1", [])

        assert len(received_headers) == 1
        assert "X-API-Key" not in received_headers[0]
        assert "Authorization" not in received_headers[0]
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_push_findings_with_api_key_auth_sends_x_api_key_header():
    handler, _received, received_headers = _make_handler(accept=True)
    server, thread = _server(handler)
    try:
        host, port = server.server_address
        client = VGSClient(
            f"http://{host}:{port}/ingest", auth_type="api_key", auth_value="secret-key-123"
        )
        await client.push_findings("scan-run-1", [])

        assert received_headers[0]["X-API-Key"] == "secret-key-123"
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_push_findings_with_bearer_token_auth_sends_authorization_header():
    handler, _received, received_headers = _make_handler(accept=True)
    server, thread = _server(handler)
    try:
        host, port = server.server_address
        client = VGSClient(
            f"http://{host}:{port}/ingest", auth_type="bearer_token", auth_value="jwt-abc-123"
        )
        await client.push_findings("scan-run-1", [])

        assert received_headers[0]["Authorization"] == "Bearer jwt-abc-123"
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_push_findings_with_basic_auth_sends_basic_auth_header():
    handler, _received, received_headers = _make_handler(accept=True)
    server, thread = _server(handler)
    try:
        host, port = server.server_address
        client = VGSClient(
            f"http://{host}:{port}/ingest", auth_type="basic", auth_value="vgsuser:vgspass"
        )
        await client.push_findings("scan-run-1", [])

        assert received_headers[0]["Authorization"].startswith("Basic ")
    finally:
        server.shutdown()
        thread.join(timeout=2)
