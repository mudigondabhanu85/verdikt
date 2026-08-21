import uuid
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sqlalchemy import select

from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.agents.websocket_security import WebSocketAgent
from app.models.finding import Finding
from app.models.project import ScopeEntry
from tests.conftest import session_scope

_ALLOWED_ORIGIN = "https://client.test"


def _make_handler(*, validate_origin: bool):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.headers.get("Upgrade", "").lower() != "websocket":
                self.send_response(400)
                self.end_headers()
                return
            origin = self.headers.get("Origin", "")
            if validate_origin and origin != _ALLOWED_ORIGIN:
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


def _server(*, validate_origin: bool):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(validate_origin=validate_origin))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_endpoint_accepting_foreign_origin_is_flagged(db_adapter):
    server, thread = _server(validate_origin=False)
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            scope_entries = [ScopeEntry(host=host, port=port, in_scope=True)]
            agent = WebSocketAgent(
                client,
                scan_run_id=uuid.uuid4(),
                agent_job_id=uuid.uuid4(),
                db_session=session,
                scope_entries=scope_entries,
            )
            sessions = {
                uuid.uuid4(): AuthenticatedSession(credential_set_id=uuid.uuid4(), cookies={"sid": "abc123"})
            }
            findings = await agent.run([f"ws://{host}:{port}/socket"], sessions)

            assert len(findings) == 1
            assert findings[0].check_id == "websocket-missing-origin-validation"
            assert findings[0].severity == "High"

            stored = (await session.execute(select(Finding))).scalars().all()
            assert len(stored) == 1

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_endpoint_validating_origin_is_not_flagged(db_adapter):
    server, thread = _server(validate_origin=True)
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            scope_entries = [ScopeEntry(host=host, port=port, in_scope=True)]
            agent = WebSocketAgent(
                client,
                scan_run_id=uuid.uuid4(),
                agent_job_id=uuid.uuid4(),
                db_session=session,
                scope_entries=scope_entries,
            )
            findings = await agent.run([f"ws://{host}:{port}/socket"], {})
            assert findings == []
            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_out_of_scope_websocket_endpoint_is_skipped(db_adapter):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
        )
        scope_entries = [ScopeEntry(host="site.test", port=80, in_scope=True)]
        agent = WebSocketAgent(
            client,
            scan_run_id=uuid.uuid4(),
            agent_job_id=uuid.uuid4(),
            db_session=session,
            scope_entries=scope_entries,
        )
        findings = await agent.run(["ws://evil.test/socket"], {})
        assert findings == []
        await client.aclose()
