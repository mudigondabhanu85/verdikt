import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
from sqlalchemy import select

from app.agents.dom_xss import DomXssAgent
from app.agents.http_client import ScopedHttpClient
from app.agents.xss_browser_proof import attempt_dom_xss_fragment_proof
from app.models.finding import Finding
from app.models.project import ScopeEntry
from tests.conftest import session_scope


class _DomXssFixtureHandler(BaseHTTPRequestHandler):
    """/vulnerable writes location.hash straight into innerHTML (a real
    DOM XSS sink); /safe uses textContent instead (safe)."""

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/vulnerable"):
            body = b"""<html><body><div id="out"></div>
            <script>document.getElementById('out').innerHTML = decodeURIComponent(location.hash.substring(1));</script>
            </body></html>"""
        elif self.path.startswith("/safe"):
            body = b"""<html><body><div id="out"></div>
            <script>document.getElementById('out').textContent = decodeURIComponent(location.hash.substring(1));</script>
            </body></html>"""
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
    server = ThreadingHTTPServer(("127.0.0.1", 0), _DomXssFixtureHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


class _NeverIdleHandler(BaseHTTPRequestHandler):
    """Simulates a real single-page app that keeps a background
    connection open after load (Juice Shop's persistent socket.io
    WebSocket, or any polling/live-reload connection) — Playwright's
    "networkidle" wait_until never fires against this, only "load"
    does."""

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/vulnerable"):
            body = b"""<html><body><div id="out"></div>
            <script>
            document.getElementById('out').innerHTML = decodeURIComponent(location.hash.substring(1));
            fetch('/never-responds');
            </script>
            </body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/never-responds":
            time.sleep(60)  # the handler thread blocks; the test itself must not wait for this
        else:
            self.send_response(404)
            self.end_headers()

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
        result = await attempt_dom_xss_fragment_proof(f"http://{host}:{port}/vulnerable")
        elapsed = time.monotonic() - start

        assert result.executed is True
        assert elapsed < 15
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_innerhtml_sink_is_confirmed_via_fragment():
    server, thread = _server()
    try:
        host, port = server.server_address
        result = await attempt_dom_xss_fragment_proof(f"http://{host}:{port}/vulnerable")

        assert result.executed is True
        assert result.screenshot_png is not None
        assert result.screenshot_png[:8] == b"\x89PNG\r\n\x1a\n"
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_textcontent_sink_is_not_flagged():
    server, thread = _server()
    try:
        host, port = server.server_address
        result = await attempt_dom_xss_fragment_proof(f"http://{host}:{port}/safe")

        assert result.executed is False
        assert result.screenshot_png is None
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_dom_xss_agent_persists_confirmed_finding_with_screenshot(db_adapter):
    server, thread = _server()
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
                transport=httpx.MockTransport(lambda r: httpx.Response(404)),
            )
            agent = DomXssAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            findings = await agent.run([f"http://{host}:{port}/vulnerable"])

            assert len(findings) == 1
            finding = findings[0]
            assert finding.check_id == "dom-xss-fragment"
            assert finding.confirmation_status == "ai_confirmed"
            assert finding.severity == "High"

            stored = (await session.execute(select(Finding))).scalars().all()
            assert len(stored) == 1
            await session.refresh(stored[0], attribute_names=["evidence"])
            assert len(stored[0].evidence.screenshot_refs) == 1

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_dom_xss_agent_finds_nothing_on_safe_page(db_adapter):
    server, thread = _server()
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
                transport=httpx.MockTransport(lambda r: httpx.Response(404)),
            )
            agent = DomXssAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            findings = await agent.run([f"http://{host}:{port}/safe"])
            assert findings == []
            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_endpoints_beyond_the_cap_are_never_probed(db_adapter, monkeypatch):
    """A real headless-browser navigation per endpoint is far more
    expensive than any other check — §14 live validation against OWASP
    Juice Shop showed the traffic-seeding bridge (app.agents.traffic_seed)
    can legitimately surface ~80 real endpoints for one target, which
    without a cap made this single check's runtime alone exceed ten
    minutes. Confirms MAX_ENDPOINTS is actually enforced, using a fast
    call counter instead of real browser navigations."""
    calls: list[str] = []

    async def _fake_proof(url, *, headless=True):
        calls.append(url)
        from app.agents.xss_browser_proof import BrowserProofResult

        return BrowserProofResult(executed=False, screenshot_png=None)

    monkeypatch.setattr("app.agents.dom_xss.attempt_dom_xss_fragment_proof", _fake_proof)

    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(lambda r: httpx.Response(404)),
        )
        agent = DomXssAgent(
            client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
        )
        endpoints = [f"http://site.test/page{i}" for i in range(DomXssAgent.MAX_ENDPOINTS + 20)]
        await agent.run(endpoints)
        await client.aclose()

    assert len(calls) == DomXssAgent.MAX_ENDPOINTS
    assert calls == endpoints[: DomXssAgent.MAX_ENDPOINTS]
