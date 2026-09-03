import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.integrations.vgs.client import VGSClient, VGSPushError


def _make_handler(*, accept: bool):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            received.append(self.rfile.read(length))
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

    return Handler, received


def _server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_push_findings_sends_the_documented_payload_shape():
    handler, received = _make_handler(accept=True)
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
    handler, _received = _make_handler(accept=False)
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
