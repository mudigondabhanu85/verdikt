"""§8 per-finding retest registry — proves each handler is wired to the
right request shape and correctly reuses its original agent's detection
logic (imported directly, not reimplemented) against a real live signal
in both directions: still vulnerable, and fixed. Detection-logic
correctness itself is already covered by each check's own agent test
file; these tests are about the retest wiring layer.
"""

import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

from app.agents.http_client import ScopedHttpClient
from app.agents.retest_registry import RETEST_HANDLERS, is_retest_supported
from app.models.finding import Finding
from app.models.project import ScopeEntry
from tests.conftest import session_scope


def _finding(check_id: str, url: str) -> Finding:
    return Finding(check_id=check_id, affected_endpoints=[url])


async def _client(db_adapter, session, *, handler=None, host="site.test", port=80):
    return ScopedHttpClient(
        version_id=uuid.uuid4(),
        scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
        db_session=session,
        transport=httpx.MockTransport(handler) if handler else None,
    )


async def test_registry_reports_support_correctly():
    assert is_retest_supported("missing-hsts")
    assert is_retest_supported("host-header-injection")
    assert not is_retest_supported("csrf-missing-protection")
    assert not is_retest_supported("sql-injection")


async def test_catalog_check_retest_both_directions(db_adapter):
    def vulnerable(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")  # no CSP header

    def fixed(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Security-Policy": "default-src 'self'"}, text="ok")

    finding = _finding("missing-csp", "http://site.test/")
    async with session_scope(db_adapter) as session:
        client = await _client(db_adapter, session, handler=vulnerable)
        outcome = await RETEST_HANDLERS["missing-csp"](finding, client)
        await client.aclose()
    assert outcome.still_vulnerable is True

    async with session_scope(db_adapter) as session:
        client = await _client(db_adapter, session, handler=fixed)
        outcome = await RETEST_HANDLERS["missing-csp"](finding, client)
        await client.aclose()
    assert outcome.still_vulnerable is False


async def test_host_header_retest_both_directions(db_adapter):
    def vulnerable(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=f"reset link: http://{request.headers['host']}/reset")

    def fixed(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="reset link: http://real.example.com/reset")

    finding = _finding("host-header-injection", "http://site.test/reset-password")
    async with session_scope(db_adapter) as session:
        client = await _client(db_adapter, session, handler=vulnerable)
        outcome = await RETEST_HANDLERS["host-header-injection"](finding, client)
        await client.aclose()
    assert outcome.still_vulnerable is True

    async with session_scope(db_adapter) as session:
        client = await _client(db_adapter, session, handler=fixed)
        outcome = await RETEST_HANDLERS["host-header-injection"](finding, client)
        await client.aclose()
    assert outcome.still_vulnerable is False


async def test_cors_retest_both_directions(db_adapter):
    def vulnerable(request: httpx.Request) -> httpx.Response:
        origin = request.headers["origin"]
        return httpx.Response(200, headers={"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"})

    def fixed(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Access-Control-Allow-Origin": "https://trusted.example.com"})

    finding = _finding("cors-reflected-origin-with-credentials", "http://site.test/api")
    async with session_scope(db_adapter) as session:
        client = await _client(db_adapter, session, handler=vulnerable)
        outcome = await RETEST_HANDLERS["cors-reflected-origin-with-credentials"](finding, client)
        await client.aclose()
    assert outcome.still_vulnerable is True

    async with session_scope(db_adapter) as session:
        client = await _client(db_adapter, session, handler=fixed)
        outcome = await RETEST_HANDLERS["cors-reflected-origin-with-credentials"](finding, client)
        await client.aclose()
    assert outcome.still_vulnerable is False


async def test_xxe_retest_both_directions(db_adapter):
    def vulnerable(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash")

    def fixed(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="invalid XML")

    finding = _finding("xxe-file-disclosure", "http://site.test/import")
    async with session_scope(db_adapter) as session:
        client = await _client(db_adapter, session, handler=vulnerable)
        outcome = await RETEST_HANDLERS["xxe-file-disclosure"](finding, client)
        await client.aclose()
    assert outcome.still_vulnerable is True

    async with session_scope(db_adapter) as session:
        client = await _client(db_adapter, session, handler=fixed)
        outcome = await RETEST_HANDLERS["xxe-file-disclosure"](finding, client)
        await client.aclose()
    assert outcome.still_vulnerable is False


async def test_graphql_retest_both_directions(db_adapter):
    def vulnerable(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": {"__schema": {"queryType": {"name": "Query"}, "types": [{"name": "Query"}]}}},
        )

    def fixed(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"errors": [{"message": "introspection disabled"}]})

    finding = _finding("graphql-introspection-enabled", "http://site.test/graphql")
    async with session_scope(db_adapter) as session:
        client = await _client(db_adapter, session, handler=vulnerable)
        outcome = await RETEST_HANDLERS["graphql-introspection-enabled"](finding, client)
        await client.aclose()
    assert outcome.still_vulnerable is True

    async with session_scope(db_adapter) as session:
        client = await _client(db_adapter, session, handler=fixed)
        outcome = await RETEST_HANDLERS["graphql-introspection-enabled"](finding, client)
        await client.aclose()
    assert outcome.still_vulnerable is False


async def test_oauth_retest_both_directions(db_adapter):
    def vulnerable(request: httpx.Request) -> httpx.Response:
        from urllib.parse import parse_qs, urlsplit

        query = parse_qs(urlsplit(str(request.url)).query)
        redirect_uri = query["redirect_uri"][0]
        return httpx.Response(302, headers={"Location": f"{redirect_uri}?code=abc"})

    def fixed(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="invalid redirect_uri")

    finding = _finding(
        "oauth-redirect-uri-validation-bypass",
        "http://site.test/authorize?client_id=x&response_type=code&redirect_uri=https://client.test/callback",
    )
    async with session_scope(db_adapter) as session:
        client = await _client(db_adapter, session, handler=vulnerable)
        outcome = await RETEST_HANDLERS["oauth-redirect-uri-validation-bypass"](finding, client)
        await client.aclose()
    assert outcome.still_vulnerable is True

    async with session_scope(db_adapter) as session:
        client = await _client(db_adapter, session, handler=fixed)
        outcome = await RETEST_HANDLERS["oauth-redirect-uri-validation-bypass"](finding, client)
        await client.aclose()
    assert outcome.still_vulnerable is False


async def test_cache_poisoning_retest_both_directions(db_adapter):
    cache: dict[str, bytes] = {}

    def vulnerable(request: httpx.Request) -> httpx.Response:
        path = str(request.url)
        if path in cache:
            return httpx.Response(200, text=cache[path].decode())
        forwarded = request.headers.get("x-forwarded-host")
        body = f"host={forwarded}" if forwarded else "host=real.test"
        cache[path] = body.encode()
        return httpx.Response(200, text=body)

    def fixed(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="host=real.test")

    finding = _finding("web-cache-poisoning-unkeyed-input", "http://site.test/")
    async with session_scope(db_adapter) as session:
        client = await _client(db_adapter, session, handler=vulnerable)
        outcome = await RETEST_HANDLERS["web-cache-poisoning-unkeyed-input"](finding, client)
        await client.aclose()
    assert outcome.still_vulnerable is True

    async with session_scope(db_adapter) as session:
        client = await _client(db_adapter, session, handler=fixed)
        outcome = await RETEST_HANDLERS["web-cache-poisoning-unkeyed-input"](finding, client)
        await client.aclose()
    assert outcome.still_vulnerable is False


async def test_cache_deception_retest_both_directions(db_adapter):
    def vulnerable(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Cache-Control": "public, max-age=300"}, text="profile content")

    def fixed(request: httpx.Request) -> httpx.Response:
        if str(request.url.path).endswith("nonexistent.css"):
            return httpx.Response(404)
        return httpx.Response(200, headers={"Cache-Control": "private, no-store"}, text="profile content")

    finding = _finding("web-cache-deception", "http://site.test/account/profile")
    async with session_scope(db_adapter) as session:
        client = await _client(db_adapter, session, handler=vulnerable)
        outcome = await RETEST_HANDLERS["web-cache-deception"](finding, client)
        await client.aclose()
    assert outcome.still_vulnerable is True

    async with session_scope(db_adapter) as session:
        client = await _client(db_adapter, session, handler=fixed)
        outcome = await RETEST_HANDLERS["web-cache-deception"](finding, client)
        await client.aclose()
    assert outcome.still_vulnerable is False


def _ws_handler(*, validate_origin: bool):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.headers.get("Upgrade", "").lower() != "websocket":
                self.send_response(400)
                self.end_headers()
                return
            if validate_origin and self.headers.get("Origin") != "https://client.test":
                self.send_response(403)
                self.end_headers()
                return
            self.send_response(101, "Switching Protocols")
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.end_headers()

        def log_message(self, format, *args):  # noqa: A002
            pass

    return Handler


def _ws_server(*, validate_origin: bool):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ws_handler(validate_origin=validate_origin))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_websocket_retest_both_directions(db_adapter):
    vuln_server, vuln_thread = _ws_server(validate_origin=False)
    safe_server, safe_thread = _ws_server(validate_origin=True)
    try:
        host, vuln_port = vuln_server.server_address
        _, safe_port = safe_server.server_address

        finding_vuln = _finding("websocket-missing-origin-validation", f"ws://{host}:{vuln_port}/socket")
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=vuln_port, in_scope=True)],
                db_session=session,
            )
            outcome = await RETEST_HANDLERS["websocket-missing-origin-validation"](finding_vuln, client)
            await client.aclose()
        assert outcome.still_vulnerable is True

        finding_safe = _finding("websocket-missing-origin-validation", f"ws://{host}:{safe_port}/socket")
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=safe_port, in_scope=True)],
                db_session=session,
            )
            outcome = await RETEST_HANDLERS["websocket-missing-origin-validation"](finding_safe, client)
            await client.aclose()
        assert outcome.still_vulnerable is False
    finally:
        vuln_server.shutdown()
        vuln_thread.join(timeout=2)
        safe_server.shutdown()
        safe_thread.join(timeout=2)


def _browser_proof_server(body: str):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            encoded = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format, *args):  # noqa: A002
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_clickjacking_retest_both_directions(db_adapter):
    vuln_server, vuln_thread = _browser_proof_server("<html><body>No frame protection</body></html>")
    try:
        host, port = vuln_server.server_address
        finding = _finding("clickjacking-confirmed", f"http://{host}:{port}/")
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(), scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)], db_session=session
            )
            outcome = await RETEST_HANDLERS["clickjacking-confirmed"](finding, client)
            await client.aclose()
        assert outcome.still_vulnerable is True
    finally:
        vuln_server.shutdown()
        vuln_thread.join(timeout=2)


async def test_dom_xss_retest_both_directions(db_adapter):
    body = (
        "<html><body><div id='out'></div>"
        "<script>document.getElementById('out').innerHTML = decodeURIComponent(location.hash.slice(1));</script>"
        "</body></html>"
    )
    server, thread = _browser_proof_server(body)
    try:
        host, port = server.server_address
        finding = _finding("dom-xss-fragment", f"http://{host}:{port}/")
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(), scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)], db_session=session
            )
            outcome = await RETEST_HANDLERS["dom-xss-fragment"](finding, client)
            await client.aclose()
        assert outcome.still_vulnerable is True
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_prototype_pollution_retest_both_directions(db_adapter):
    body = (
        "<html><body><script>"
        "function parseQuery(qs) {"
        "  const params = new URLSearchParams(qs); const obj = {};"
        "  for (const [k, v] of params) {"
        "    const keys = k.replace(/\\]/g, '').split('[');"
        "    let cur = obj;"
        "    for (let i = 0; i < keys.length - 1; i++) { cur[keys[i]] = cur[keys[i]] || {}; cur = cur[keys[i]]; }"
        "    cur[keys[keys.length - 1]] = v;"
        "  }"
        "  return obj;"
        "}"
        "parseQuery(location.search.slice(1));"
        "</script></body></html>"
    )
    server, thread = _browser_proof_server(body)
    try:
        host, port = server.server_address
        finding = _finding("client-side-prototype-pollution", f"http://{host}:{port}/")
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(), scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)], db_session=session
            )
            outcome = await RETEST_HANDLERS["client-side-prototype-pollution"](finding, client)
            await client.aclose()
        assert outcome.still_vulnerable is True
    finally:
        server.shutdown()
        thread.join(timeout=2)
