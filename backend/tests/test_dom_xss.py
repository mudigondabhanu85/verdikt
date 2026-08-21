import threading
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
