import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tests.conftest import register_org_admin


def _make_slack_fixture(*, accept: bool):
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
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"no_service")

        def log_message(self, format, *args):  # noqa: A002
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, received


async def test_notification_config_crud_never_returns_plaintext_webhook(client):
    admin = await register_org_admin(client)

    created = await client.post(
        "/notification-configs",
        json={"label": "Team Slack", "provider": "slack", "webhook_url": "https://hooks.slack.com/services/SECRET/PATH"},
        headers=admin["headers"],
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert "SECRET" not in created.text
    assert body["provider"] == "slack"
    assert body["notify_on_scan_completed"] is True

    listed = await client.get("/notification-configs", headers=admin["headers"])
    assert "SECRET" not in listed.text
    assert len(listed.json()) == 1

    deleted = await client.delete(f"/notification-configs/{body['id']}", headers=admin["headers"])
    assert deleted.status_code == 204

    listed_after = await client.get("/notification-configs", headers=admin["headers"])
    assert listed_after.json() == []


async def test_unknown_provider_type_rejected(client):
    admin = await register_org_admin(client)
    resp = await client.post(
        "/notification-configs",
        json={"label": "x", "provider": "msteams", "webhook_url": "https://example.test/hook"},
        headers=admin["headers"],
    )
    assert resp.status_code == 422


async def test_test_endpoint_sends_a_real_message_to_the_webhook(client):
    admin = await register_org_admin(client)
    server, thread, received = _make_slack_fixture(accept=True)
    try:
        host, port = server.server_address
        created = await client.post(
            "/notification-configs",
            json={"label": "Fixture Slack", "provider": "slack", "webhook_url": f"http://{host}:{port}/webhook"},
            headers=admin["headers"],
        )
        config_id = created.json()["id"]

        resp = await client.post(f"/notification-configs/{config_id}/test", headers=admin["headers"])
        assert resp.status_code == 204, resp.text
        assert len(received) == 1
        assert b"Fixture Slack" in received[0]
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_test_endpoint_surfaces_a_real_rejection_cleanly(client):
    admin = await register_org_admin(client)
    server, thread, _received = _make_slack_fixture(accept=False)
    try:
        host, port = server.server_address
        created = await client.post(
            "/notification-configs",
            json={"label": "Rejecting Slack", "provider": "slack", "webhook_url": f"http://{host}:{port}/webhook"},
            headers=admin["headers"],
        )
        config_id = created.json()["id"]

        resp = await client.post(f"/notification-configs/{config_id}/test", headers=admin["headers"])
        assert resp.status_code == 502
        assert "rejected" in resp.text
    finally:
        server.shutdown()
        thread.join(timeout=2)
