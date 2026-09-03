import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
from sqlalchemy import select

from app.agents.http_client import ScopedHttpClient
from app.agents.prototype_pollution import (
    PrototypePollutionAgent,
    attempt_prototype_pollution_proof,
)
from app.models.finding import Finding
from app.models.project import ScopeEntry
from tests.conftest import session_scope

_VULNERABLE_PAGE = b"""<html><body>
<script>
function parseQuery(qs) {
    const params = {};
    qs.split('&').forEach(function(pair) {
        if (!pair) return;
        const parts = pair.split('=');
        const key = decodeURIComponent(parts[0]);
        const value = decodeURIComponent(parts[1] || '');
        const match = key.match(/^([^\\[]+)\\[([^\\]]+)\\]$/);
        if (match) {
            const obj = match[1];
            const prop = match[2];
            if (!params[obj]) params[obj] = {};
            params[obj][prop] = value;
        } else {
            params[key] = value;
        }
    });
    return params;
}
function deepMerge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
deepMerge({}, parseQuery(location.search.substring(1)));
</script>
</body></html>"""

_SAFE_PAGE = b"""<html><body>
<script>
function parseQuery(qs) {
    const params = new Map();
    qs.split('&').forEach(function(pair) {
        if (!pair) return;
        const parts = pair.split('=');
        params.set(decodeURIComponent(parts[0]), decodeURIComponent(parts[1] || ''));
    });
    return params;
}
parseQuery(location.search.substring(1));
</script>
</body></html>"""


def _make_handler(page_body: bytes):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(page_body)

        def log_message(self, format, *args):  # noqa: A002
            pass

    return Handler


def _server(page_body: bytes):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(page_body))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


_NEVER_IDLE_VULNERABLE_PAGE = _VULNERABLE_PAGE.replace(
    b"</script>", b"fetch('/never-responds');\n</script>"
)


class _NeverIdleHandler(BaseHTTPRequestHandler):
    """Simulates a real single-page app that keeps a background
    connection open after load (Juice Shop's persistent socket.io
    WebSocket, or any polling/live-reload connection) — Playwright's
    "networkidle" wait_until never fires against this, only "load"
    does."""

    def do_GET(self):  # noqa: N802
        if self.path == "/never-responds":
            time.sleep(60)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(_NEVER_IDLE_VULNERABLE_PAGE)

    def log_message(self, format, *args):  # noqa: A002
        pass


def _never_idle_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _NeverIdleHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_proof_completes_fast_despite_persistent_background_connection():
    """A real bug found via §14 live validation against OWASP Juice
    Shop: Playwright's "networkidle" wait_until never fires against a
    page that keeps a persistent connection open in the background
    (Juice Shop's socket.io WebSocket) — every navigation ate the full
    default 30s timeout instead of the sink being probed quickly.
    Confirms the fix (wait_until="load" with an explicit bounded
    timeout) still detects the vulnerability and returns fast, even
    against a page that never goes network-idle.
    """
    server, thread = _never_idle_server()
    try:
        host, port = server.server_address
        start = time.monotonic()
        executed, screenshot = await attempt_prototype_pollution_proof(f"http://{host}:{port}/")
        elapsed = time.monotonic() - start

        assert executed is True
        assert screenshot is not None
        assert elapsed < 15
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_vulnerable_merge_is_confirmed():
    server, thread = _server(_VULNERABLE_PAGE)
    try:
        host, port = server.server_address
        executed, screenshot = await attempt_prototype_pollution_proof(f"http://{host}:{port}/")
        assert executed is True
        assert screenshot is not None
        assert screenshot[:8] == b"\x89PNG\r\n\x1a\n"
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_safe_map_based_parsing_is_not_flagged():
    server, thread = _server(_SAFE_PAGE)
    try:
        host, port = server.server_address
        executed, screenshot = await attempt_prototype_pollution_proof(f"http://{host}:{port}/")
        assert executed is False
        assert screenshot is None
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_agent_persists_confirmed_finding_with_screenshot(db_adapter):
    server, thread = _server(_VULNERABLE_PAGE)
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
                transport=httpx.MockTransport(lambda r: httpx.Response(404)),
            )
            agent = PrototypePollutionAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            findings = await agent.run([f"http://{host}:{port}/"])

            assert len(findings) == 1
            finding = findings[0]
            assert finding.check_id == "client-side-prototype-pollution"
            assert finding.cwe_id == "CWE-1321"
            assert finding.confirmation_status == "ai_confirmed"

            stored = (await session.execute(select(Finding))).scalars().all()
            assert len(stored) == 1
            await session.refresh(stored[0], attribute_names=["evidence"])
            assert len(stored[0].evidence.screenshot_refs) == 1

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_endpoints_beyond_the_cap_are_never_probed(db_adapter, monkeypatch):
    """See app.agents.dom_xss's identical test — same real-browser-per-
    endpoint cost, same §14 finding (traffic-seeded discovery can
    legitimately surface dozens of real endpoints for one target)."""
    calls: list[str] = []

    async def _fake_proof(url, *, headless=True):
        calls.append(url)
        return False, None

    monkeypatch.setattr(
        "app.agents.prototype_pollution.attempt_prototype_pollution_proof", _fake_proof
    )

    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(lambda r: httpx.Response(404)),
        )
        agent = PrototypePollutionAgent(
            client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
        )
        endpoints = [
            f"http://site.test/page{i}" for i in range(PrototypePollutionAgent.MAX_ENDPOINTS + 20)
        ]
        await agent.run(endpoints)
        await client.aclose()

    assert len(calls) == PrototypePollutionAgent.MAX_ENDPOINTS
    assert calls == endpoints[: PrototypePollutionAgent.MAX_ENDPOINTS]
