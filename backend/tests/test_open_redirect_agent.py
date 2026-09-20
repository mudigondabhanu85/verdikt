import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from sqlalchemy import select

from app.agents.http_client import ScopedHttpClient
from app.agents.open_redirect import OpenRedirectAgent, _EXTERNAL_TARGET
from app.agents.recon import DiscoveredParameter
from app.models.finding import Evidence, Finding
from app.models.project import ScopeEntry
from tests.conftest import session_scope


class _VulnerableRedirectHandler(BaseHTTPRequestHandler):
    """Real DVWA-style open redirect — a 'redirect' query param is sent
    straight back as the Location header, unvalidated."""

    def do_GET(self):  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/go":
            target = parse_qs(parsed.query).get("redirect", [""])[0]
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):  # noqa: A002
        pass


class _SafeRedirectHandler(BaseHTTPRequestHandler):
    """Only ever redirects to a fixed, safe internal path, ignoring the
    supplied value entirely."""

    def do_GET(self):  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/go":
            self.send_response(302)
            self.send_header("Location", "/home")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):  # noqa: A002
        pass


def _server(handler_cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_open_redirect_confirmed_via_real_location_header(db_adapter):
    server, thread = _server(_VulnerableRedirectHandler)
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            agent = OpenRedirectAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            parameters = [
                DiscoveredParameter(
                    url=f"http://{host}:{port}/go?redirect=info.php", method="GET", name="redirect"
                )
            ]

            findings = await agent.run(parameters, [])

            assert len(findings) == 1
            finding = findings[0]
            assert finding.check_id == "open-redirect-confirmed"
            assert finding.severity == "Medium"
            assert finding.confirmation_status == "ai_confirmed"

            stored = (await session.execute(select(Finding))).scalars().all()
            assert len(stored) == 1
            evidence = (await session.execute(select(Evidence))).scalars().all()
            assert len(evidence) == 1
            assert evidence[0].payload == _EXTERNAL_TARGET

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_no_finding_when_redirect_target_is_ignored(db_adapter):
    server, thread = _server(_SafeRedirectHandler)
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            agent = OpenRedirectAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            parameters = [
                DiscoveredParameter(
                    url=f"http://{host}:{port}/go?redirect=info.php", method="GET", name="redirect"
                )
            ]

            findings = await agent.run(parameters, [])
            assert findings == []

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_non_redirect_shaped_parameters_are_never_probed(db_adapter):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
        )
        agent = OpenRedirectAgent(
            client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
        )
        # "id" doesn't look redirect-shaped by name — the agent should
        # skip it entirely (and never even issue a request for it).
        parameters = [
            DiscoveredParameter(url="http://site.test/product?id=1", method="GET", name="id")
        ]
        findings = await agent.run(parameters, [])
        assert findings == []
        await client.aclose()
