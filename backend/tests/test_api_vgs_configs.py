import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tests.conftest import register_org_admin


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
                self.wfile.write(b"no_service")

        def log_message(self, format, *args):  # noqa: A002
            pass

    return Handler, received


def _server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_vgs_config_crud_never_returns_plaintext_webhook(client):
    admin = await register_org_admin(client)

    created = await client.post(
        "/vgs-configs",
        json={"label": "Primary VGS", "webhook_url": "https://vgs.example.test/ingest/SECRET"},
        headers=admin["headers"],
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert "SECRET" not in created.text
    assert body["push_on_scan_completed"] is True

    listed = await client.get("/vgs-configs", headers=admin["headers"])
    assert "SECRET" not in listed.text
    assert len(listed.json()) == 1

    deleted = await client.delete(f"/vgs-configs/{body['id']}", headers=admin["headers"])
    assert deleted.status_code == 204

    listed_after = await client.get("/vgs-configs", headers=admin["headers"])
    assert listed_after.json() == []


async def test_test_endpoint_sends_a_real_tagged_payload(client):
    admin = await register_org_admin(client)
    handler, received = _make_handler(accept=True)
    server, thread = _server(handler)
    try:
        host, port = server.server_address
        created = await client.post(
            "/vgs-configs",
            json={"label": "Fixture VGS", "webhook_url": f"http://{host}:{port}/ingest"},
            headers=admin["headers"],
        )
        config_id = created.json()["id"]

        resp = await client.post(f"/vgs-configs/{config_id}/test", headers=admin["headers"])
        assert resp.status_code == 204, resp.text
        assert len(received) == 1
        assert b"ai-multi-agent" in received[0]
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_test_endpoint_surfaces_a_real_rejection_cleanly(client):
    admin = await register_org_admin(client)
    handler, _received = _make_handler(accept=False)
    server, thread = _server(handler)
    try:
        host, port = server.server_address
        created = await client.post(
            "/vgs-configs",
            json={"label": "Rejecting VGS", "webhook_url": f"http://{host}:{port}/ingest"},
            headers=admin["headers"],
        )
        config_id = created.json()["id"]

        resp = await client.post(f"/vgs-configs/{config_id}/test", headers=admin["headers"])
        assert resp.status_code == 502
    finally:
        server.shutdown()
        thread.join(timeout=2)
