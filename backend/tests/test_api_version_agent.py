import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from sqlalchemy import select

from app.agents.api_version import ApiVersionAgent
from app.agents.http_client import ScopedHttpClient
from app.models.finding import Evidence, Finding
from app.models.project import ScopeEntry
from tests.conftest import session_scope

_V1_USERS = [{"id": 1, "name": "tony", "password": "deadbeef"}]
_V2_USERS = [{"id": 1, "name": "tony"}]


class _LeakyVersionedApiHandler(BaseHTTPRequestHandler):
    """Real DVWA-style API versioning bug — v1 still returns a password
    field a later, currently-referenced v2 correctly omits."""

    def do_GET(self):  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/api/v2/user/":
            body = json.dumps(_V2_USERS).encode()
        elif path == "/api/v1/user/":
            body = json.dumps(_V1_USERS).encode()
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002
        pass


class _ConsistentVersionedApiHandler(BaseHTTPRequestHandler):
    """Every version returns the same fields — nothing to find."""

    def do_GET(self):  # noqa: N802
        path = urlsplit(self.path).path
        if path in ("/api/v1/user/", "/api/v2/user/"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(_V2_USERS).encode())
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


async def test_api_version_confirmed_when_older_version_leaks_a_sensitive_field(db_adapter):
    server, thread = _server(_LeakyVersionedApiHandler)
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            agent = ApiVersionAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            findings = await agent.run([f"http://{host}:{port}/api/v2/user/"])

            assert len(findings) == 1
            finding = findings[0]
            assert finding.check_id == "api-deprecated-version-excessive-data-exposure"
            assert finding.severity == "High"
            assert "password" in finding.technical_description

            stored = (await session.execute(select(Finding))).scalars().all()
            assert len(stored) == 1
            evidence = (await session.execute(select(Evidence))).scalars().all()
            assert len(evidence) == 1
            assert "password" in evidence[0].additional_notes

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_no_finding_when_every_version_returns_the_same_fields(db_adapter):
    server, thread = _server(_ConsistentVersionedApiHandler)
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            agent = ApiVersionAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            findings = await agent.run([f"http://{host}:{port}/api/v2/user/"])
            assert findings == []

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_urls_without_a_version_segment_are_skipped(db_adapter):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
        )
        agent = ApiVersionAgent(
            client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
        )
        findings = await agent.run(["http://site.test/api/user/", "http://site.test/api/v1/user/"])
        # v1 has no older version to compare against (current <= 1) —
        # nothing to try, no request even issued.
        assert findings == []
        await client.aclose()
