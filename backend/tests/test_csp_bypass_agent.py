import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from sqlalchemy import select

from app.agents.csp_bypass import CspBypassAgent
from app.agents.http_client import ScopedHttpClient
from app.models.finding import Finding
from app.models.project import ScopeEntry
from tests.conftest import session_scope


class _CspPageFixtureHandler(BaseHTTPRequestHandler):
    """Mirrors DVWA's own CSP-bypass teaching page exactly (§14): the
    vulnerable JSONP URL is never present in the page's own HTML — it's a
    string literal inside a separate, external same-origin .js file the
    page loads via <script src>. /page-safe has the same CSP but its own
    loader references an endpoint that validates the callback name
    against an allow-list, so no bypass is possible.
    """

    def do_GET(self):  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/page":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Security-Policy", "script-src 'self'")
            self.end_headers()
            self.wfile.write(
                b'<html><body><button id="solve">Solve</button>'
                b'<script src="/loader.js"></script></body></html>'
            )
        elif parsed.path == "/page-safe":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Security-Policy", "script-src 'self'")
            self.end_headers()
            self.wfile.write(
                b'<html><body><button id="solve">Solve</button>'
                b'<script src="/loader-safe.js"></script></body></html>'
            )
        elif parsed.path == "/loader.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(
                b'function clickButton() {\n'
                b'  var s = document.createElement("script");\n'
                b'  s.src = "/jsonp.php?callback=solveSum";\n'
                b'  document.body.appendChild(s);\n'
                b'}\n'
            )
        elif parsed.path == "/loader-safe.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(b'function clickButton() { fetch("/api/solve").then(); }\n')
        elif parsed.path == "/jsonp.php":
            callback = parse_qs(parsed.query).get("callback", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(f'{callback}({{"answer":15}})'.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):  # noqa: A002
        pass


def _server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CspPageFixtureHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_finds_jsonp_endpoint_referenced_only_in_external_script(db_adapter):
    server, thread = _server()
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            page_url = f"http://{host}:{port}/page"
            page_response = await client.get(page_url)

            agent = CspBypassAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            findings = await agent.run({page_url: page_response})

            assert len(findings) == 1
            finding = findings[0]
            assert finding.check_id == "csp-bypass-jsonp-callback"
            assert page_url in finding.affected_endpoints
            assert any("jsonp.php" in e for e in finding.affected_endpoints)

            stored = (await session.execute(select(Finding))).scalars().all()
            assert len(stored) == 1
            await session.refresh(stored[0], attribute_names=["evidence"])
            assert len(stored[0].evidence.screenshot_refs) == 1

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_no_finding_when_the_loader_has_no_jsonp_gadget(db_adapter):
    server, thread = _server()
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            page_url = f"http://{host}:{port}/page-safe"
            page_response = await client.get(page_url)

            agent = CspBypassAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            findings = await agent.run({page_url: page_response})

            assert findings == []
            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_no_csp_header_is_skipped_entirely(db_adapter):
    """No CSP at all is already covered by the separate missing-CSP
    header check — this agent has nothing to say about a page that never
    claimed to restrict scripts in the first place."""
    server, thread = _server()
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            page_url = f"http://{host}:{port}/jsonp.php?callback=x"
            page_response = await client.get(page_url)

            agent = CspBypassAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            findings = await agent.run({page_url: page_response})

            assert findings == []
            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)
