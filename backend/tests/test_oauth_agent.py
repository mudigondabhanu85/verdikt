import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from sqlalchemy import select

from app.agents.http_client import ScopedHttpClient
from app.agents.oauth import OAuthAgent
from app.models.finding import Finding
from app.models.project import ScopeEntry
from tests.conftest import session_scope

_REGISTERED_REDIRECT = "https://client.test/callback"


def _make_handler(*, validate_redirect: bool):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            parsed = urlsplit(self.path)
            if parsed.path != "/authorize":
                self.send_response(404)
                self.end_headers()
                return
            query = parse_qs(parsed.query)
            redirect_uri = query.get("redirect_uri", [""])[0]

            if validate_redirect and redirect_uri != _REGISTERED_REDIRECT:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"invalid redirect_uri")
                return

            self.send_response(302)
            self.send_header("Location", f"{redirect_uri}?code=AUTHCODE123")
            self.end_headers()

        def log_message(self, format, *args):  # noqa: A002
            pass

    return Handler


def _server(*, validate_redirect: bool):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(validate_redirect=validate_redirect))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _authorize_url(host, port) -> str:
    return (
        f"http://{host}:{port}/authorize"
        f"?client_id=abc123&response_type=code&redirect_uri={_REGISTERED_REDIRECT}"
    )


async def test_endpoint_accepting_arbitrary_redirect_uri_is_flagged(db_adapter):
    server, thread = _server(validate_redirect=False)
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            agent = OAuthAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            findings = await agent.run([_authorize_url(host, port)])

            assert len(findings) == 1
            finding = findings[0]
            assert finding.check_id == "oauth-redirect-uri-validation-bypass"
            assert finding.severity == "Critical"

            stored = (await session.execute(select(Finding))).scalars().all()
            assert len(stored) == 1

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_endpoint_validating_redirect_uri_allowlist_is_not_flagged(db_adapter):
    server, thread = _server(validate_redirect=True)
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            agent = OAuthAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            findings = await agent.run([_authorize_url(host, port)])
            assert findings == []
            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_non_authorize_endpoints_are_skipped(db_adapter):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
        )
        agent = OAuthAgent(
            client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
        )
        findings = await agent.run(["http://site.test/about", "http://site.test/authorize?foo=bar"])
        assert findings == []
        await client.aclose()
