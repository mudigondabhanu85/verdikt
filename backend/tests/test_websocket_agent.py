import uuid
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from sqlalchemy import select

from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.agents.websocket_security import WebSocketAgent, _strip_stale_session_id
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


def _make_socketio_style_handler():
    # Mimics real socket.io/Engine.IO server behaviour (confirmed live
    # against OWASP Juice Shop during §14 validation): a `sid` query
    # param identifies one specific, already-established polling
    # session — replaying a stale one is rejected outright, *before*
    # Origin is ever considered. Only a request with no `sid` at all
    # (a fresh connection) reaches the point of accepting the upgrade.
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            query = parse_qs(urlsplit(self.path).query)
            if "sid" in query:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Session ID unknown")
                return
            if self.headers.get("Upgrade", "").lower() != "websocket":
                self.send_response(400)
                self.end_headers()
                return
            self.send_response(101, "Switching Protocols")
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.end_headers()

        def log_message(self, format, *args):  # noqa: A002
            pass

    return Handler


def _socketio_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_socketio_style_handler())
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


def test_strip_stale_session_id_removes_only_sid():
    assert (
        _strip_stale_session_id("/socket.io/?EIO=4&transport=websocket&sid=abc123")
        == "/socket.io/?EIO=4&transport=websocket"
    )


def test_strip_stale_session_id_leaves_url_without_sid_unchanged():
    assert _strip_stale_session_id("/socket.io/?EIO=4&transport=websocket") == (
        "/socket.io/?EIO=4&transport=websocket"
    )
    assert _strip_stale_session_id("/socket") == "/socket"


async def test_stale_sid_from_captured_traffic_does_not_hide_a_real_finding(db_adapter):
    """A real false negative found via §14 live validation against OWASP
    Juice Shop: a WebSocket URL discovered from captured HAR traffic
    carries a `sid` bound to that capture's own, now-long-expired
    Engine.IO session. Replaying it verbatim always gets rejected before
    Origin is even checked — which would misreport a genuinely
    CSWSH-vulnerable endpoint as safe. Verdikt must strip it and probe
    as a fresh connection, the same as an actual attacker would."""
    server, thread = _socketio_server()
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
            stale_url = f"ws://{host}:{port}/socket.io/?EIO=4&transport=websocket&sid=stale-and-expired"
            findings = await agent.run([stale_url], {})

            assert len(findings) == 1
            assert findings[0].check_id == "websocket-missing-origin-validation"

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)
