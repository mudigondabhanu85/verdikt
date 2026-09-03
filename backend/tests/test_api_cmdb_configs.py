import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tests.conftest import register_org_admin


def _make_asset_handler():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = json.dumps({"owner": "ops@example.test", "criticality": "Critical"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):  # noqa: A002
            pass

    return Handler


def _server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_cmdb_config_crud_never_returns_plaintext_auth_header(client):
    admin = await register_org_admin(client)

    created = await client.post(
        "/cmdb-configs",
        json={
            "label": "Corp CMDB",
            "provider": "generic_rest",
            "lookup_url_template": "https://cmdb.example.test/assets/{identifier}",
            "auth_header_name": "X-Api-Key",
            "auth_header_value": "SUPER_SECRET_KEY",
            "owner_json_path": "owner",
            "criticality_json_path": "criticality",
        },
        headers=admin["headers"],
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert "SUPER_SECRET_KEY" not in created.text
    assert body["provider"] == "generic_rest"
    assert body["auth_header_name"] == "X-Api-Key"

    listed = await client.get("/cmdb-configs", headers=admin["headers"])
    assert "SUPER_SECRET_KEY" not in listed.text
    assert len(listed.json()) == 1

    deleted = await client.delete(f"/cmdb-configs/{body['id']}", headers=admin["headers"])
    assert deleted.status_code == 204

    listed_after = await client.get("/cmdb-configs", headers=admin["headers"])
    assert listed_after.json() == []


async def test_unknown_provider_type_rejected(client):
    admin = await register_org_admin(client)
    resp = await client.post(
        "/cmdb-configs",
        json={
            "label": "x",
            "provider": "servicenow",
            "lookup_url_template": "https://example.test/{identifier}",
            "auth_header_value": "x",
            "owner_json_path": "owner",
            "criticality_json_path": "criticality",
        },
        headers=admin["headers"],
    )
    assert resp.status_code == 422


async def test_lookup_endpoint_returns_a_real_asset_from_the_fixture(client):
    admin = await register_org_admin(client)
    server, thread = _server(_make_asset_handler())
    try:
        host, port = server.server_address
        created = await client.post(
            "/cmdb-configs",
            json={
                "label": "Fixture CMDB",
                "provider": "generic_rest",
                "lookup_url_template": f"http://{host}:{port}/assets/{{identifier}}",
                "auth_header_name": "X-Api-Key",
                "auth_header_value": "secret",
                "owner_json_path": "owner",
                "criticality_json_path": "criticality",
            },
            headers=admin["headers"],
        )
        config_id = created.json()["id"]

        resp = await client.post(
            f"/cmdb-configs/{config_id}/lookup", json={"identifier": "host-1"}, headers=admin["headers"]
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["identifier"] == "host-1"
        assert body["owner"] == "ops@example.test"
        assert body["criticality"] == "Critical"
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_lookup_endpoint_surfaces_a_real_failure_cleanly(client):
    admin = await register_org_admin(client)
    created = await client.post(
        "/cmdb-configs",
        json={
            "label": "Unreachable CMDB",
            "provider": "generic_rest",
            "lookup_url_template": "http://127.0.0.1:1/assets/{identifier}",
            "auth_header_value": "x",
            "owner_json_path": "owner",
            "criticality_json_path": "criticality",
        },
        headers=admin["headers"],
    )
    config_id = created.json()["id"]

    resp = await client.post(f"/cmdb-configs/{config_id}/lookup", json={"identifier": "x"}, headers=admin["headers"])
    assert resp.status_code == 502
