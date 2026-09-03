import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.integrations.cmdb.client import CMDBClient, CMDBLookupError


def _make_handler(*, status_code: int = 200, body: dict | None = None, expected_auth: str | None = None):
    received_headers = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            received_headers.append(dict(self.headers))
            if expected_auth is not None and self.headers.get("X-Api-Key") != expected_auth:
                self.send_response(403)
                self.end_headers()
                return
            payload = json.dumps(body or {}).encode()
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):  # noqa: A002
            pass

    return Handler, received_headers


def _server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_get_asset_extracts_owner_and_criticality_via_json_paths():
    handler, _headers = _make_handler(
        body={"asset": {"owner": {"email": "owner@example.test"}, "risk": {"criticality": "High"}}}
    )
    server, thread = _server(handler)
    try:
        host, port = server.server_address
        client = CMDBClient(
            f"http://{host}:{port}/assets/{{identifier}}",
            "X-Api-Key",
            "secret-key",
            "asset.owner.email",
            "asset.risk.criticality",
        )
        asset = await client.get_asset("host-42")
        assert asset.identifier == "host-42"
        assert asset.owner == "owner@example.test"
        assert asset.criticality == "High"
        assert asset.raw["asset"]["owner"]["email"] == "owner@example.test"
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_url_template_and_auth_header_are_applied():
    handler, headers = _make_handler(body={}, expected_auth="secret-key")
    server, thread = _server(handler)
    try:
        host, port = server.server_address
        client = CMDBClient(
            f"http://{host}:{port}/assets?name={{identifier}}",
            "X-Api-Key",
            "secret-key",
            "owner",
            "criticality",
        )
        await client.get_asset("db-01")
        assert len(headers) == 1
        assert headers[0]["X-Api-Key"] == "secret-key"
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_missing_json_path_resolves_to_none_not_an_error():
    handler, _headers = _make_handler(body={"owner": "someone@example.test"})
    server, thread = _server(handler)
    try:
        host, port = server.server_address
        client = CMDBClient(
            f"http://{host}:{port}/assets/{{identifier}}",
            "Authorization",
            "Bearer x",
            "owner",
            "nested.path.that.does.not.exist",
        )
        asset = await client.get_asset("x")
        assert asset.owner == "someone@example.test"
        assert asset.criticality is None
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_non_2xx_response_raises_cmdb_lookup_error():
    handler, _headers = _make_handler(status_code=404, body={"error": "not found"})
    server, thread = _server(handler)
    try:
        host, port = server.server_address
        client = CMDBClient(
            f"http://{host}:{port}/assets/{{identifier}}",
            "Authorization",
            "Bearer x",
            "owner",
            "criticality",
        )
        try:
            await client.get_asset("missing")
            raise AssertionError("expected CMDBLookupError")
        except CMDBLookupError as exc:
            assert "404" in str(exc)
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_unreachable_host_raises_cmdb_lookup_error():
    # Port 1 is reserved/unreachable — a real, guaranteed connection failure.
    client = CMDBClient("http://127.0.0.1:1/assets/{identifier}", "Authorization", "Bearer x", "owner", "criticality")
    try:
        await client.get_asset("x")
        raise AssertionError("expected CMDBLookupError")
    except CMDBLookupError:
        pass
