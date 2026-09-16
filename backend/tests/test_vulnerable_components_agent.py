import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

from app.agents.http_client import ScopedHttpClient
from app.agents.vulnerable_components import VulnerableComponentsAgent
from app.integrations.osv.client import OsvClient
from app.models.project import ScopeEntry
from tests.conftest import session_scope

_OLD_JQUERY_PAGE = b"""<html><body>
<script>window.jQuery = { fn: { jquery: "1.7.0" } };</script>
</body></html>"""

_NO_LIBRARY_PAGE = b"<html><body>plain page, no JS libraries</body></html>"


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/old-jquery":
            body = _OLD_JQUERY_PAGE
        elif self.path == "/clean":
            body = _NO_LIBRARY_PAGE
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
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _osv_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"vulns": [{"id": "GHSA-fake-jquery-xss"}]})


async def _run_agent(db_adapter, endpoints, osv_client=None):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="127.0.0.1", port=None, in_scope=True)],
            db_session=session,
            transport=httpx.AsyncHTTPTransport(),
        )
        agent = VulnerableComponentsAgent(
            client,
            scan_run_id=uuid.uuid4(),
            agent_job_id=uuid.uuid4(),
            db_session=session,
            osv_client=osv_client or OsvClient(transport=httpx.MockTransport(_osv_handler)),
        )
        findings = await agent.run(endpoints, {})
        await client.aclose()
        return findings


async def test_vulnerable_jquery_version_is_flagged(db_adapter):
    server, thread = _server()
    try:
        host, port = server.server_address
        findings = await _run_agent(db_adapter, [f"http://{host}:{port}/old-jquery"])
    finally:
        server.shutdown()
        thread.join(timeout=2)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "vulnerable-client-side-component"
    assert "jQuery" in finding.title
    assert "1.7.0" in finding.title


async def test_page_with_no_known_libraries_yields_no_finding(db_adapter):
    server, thread = _server()
    try:
        host, port = server.server_address
        findings = await _run_agent(db_adapter, [f"http://{host}:{port}/clean"])
    finally:
        server.shutdown()
        thread.join(timeout=2)

    assert findings == []


async def test_osv_returning_no_vulns_yields_no_finding(db_adapter):
    def clean_osv_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulns": []})

    server, thread = _server()
    try:
        host, port = server.server_address
        findings = await _run_agent(
            db_adapter,
            [f"http://{host}:{port}/old-jquery"],
            osv_client=OsvClient(transport=httpx.MockTransport(clean_osv_handler)),
        )
    finally:
        server.shutdown()
        thread.join(timeout=2)

    assert findings == []
