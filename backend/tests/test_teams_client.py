import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.integrations.teams.client import TeamsClient, TeamsNotificationError


def _make_teams_fixture(*, accept: bool):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            received.append(self.rfile.read(length))
            if accept:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"1")
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"bad card")

        def log_message(self, format, *args):  # noqa: A002
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, received


async def test_teams_client_posts_message_card_shaped_payload():
    server, thread, received = _make_teams_fixture(accept=True)
    try:
        host, port = server.server_address
        client = TeamsClient(f"http://{host}:{port}/webhook")
        await client.post_message("Scan complete: 5 findings")
        assert len(received) == 1
        import json

        body = json.loads(received[0])
        assert body["@type"] == "MessageCard"
        assert body["text"] == "Scan complete: 5 findings"
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_teams_client_raises_on_rejection():
    server, thread, _received = _make_teams_fixture(accept=False)
    try:
        host, port = server.server_address
        client = TeamsClient(f"http://{host}:{port}/webhook")
        with pytest.raises(TeamsNotificationError):
            await client.post_message("hi")
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_teams_client_raises_on_unreachable_host():
    client = TeamsClient("http://127.0.0.1:1", timeout=1.0)
    with pytest.raises(TeamsNotificationError):
        await client.post_message("hi")
