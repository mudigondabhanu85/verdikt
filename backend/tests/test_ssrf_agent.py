import threading
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from sqlalchemy import select

from app.agents.http_client import ScopedHttpClient
from app.agents.recon import DiscoveredParameter
from app.agents.ssrf import SsrfAgent
from app.models.finding import Finding
from app.models.project import ScopeEntry
from tests.conftest import session_scope


class _VulnerableFetchHandler(BaseHTTPRequestHandler):
    """Simulates a real "fetch this URL server-side" feature — an
    attacker-supplied URL in the image_url param gets genuinely fetched
    by the server, which is exactly the SSRF precondition.
    """

    def do_GET(self):  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/fetch-image":
            image_url = parse_qs(parsed.query).get("image_url", [""])[0]
            if image_url:
                try:
                    urllib.request.urlopen(image_url, timeout=3).read()  # noqa: S310
                except Exception:
                    pass
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"image fetched (or attempted)")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):  # noqa: A002
        pass


class _SafeFetchHandler(BaseHTTPRequestHandler):
    """Never actually fetches the supplied URL — just acknowledges it."""

    def do_GET(self):  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/fetch-image":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"image_url received, not fetched")
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


async def test_ssrf_confirmed_via_real_out_of_band_callback(db_adapter):
    server, thread = _server(_VulnerableFetchHandler)
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            agent = SsrfAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            parameters = [
                DiscoveredParameter(
                    url=f"http://{host}:{port}/fetch-image?image_url=x",
                    method="GET",
                    name="image_url",
                )
            ]

            findings = await agent.run(parameters, [])

            assert len(findings) == 1
            finding = findings[0]
            assert finding.check_id == "ssrf-confirmed"
            assert finding.severity == "Critical"
            assert finding.confirmation_status == "ai_confirmed"

            stored = (await session.execute(select(Finding))).scalars().all()
            assert len(stored) == 1

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_no_finding_when_url_never_fetched(db_adapter):
    server, thread = _server(_SafeFetchHandler)
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            agent = SsrfAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            parameters = [
                DiscoveredParameter(
                    url=f"http://{host}:{port}/fetch-image?image_url=x",
                    method="GET",
                    name="image_url",
                )
            ]

            findings = await agent.run(parameters, [])
            assert findings == []

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_non_url_shaped_parameters_are_never_probed(db_adapter):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
        )
        agent = SsrfAgent(
            client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
        )
        # "id" doesn't look URL-shaped by name — the agent should skip it
        # entirely (and therefore never even start the callback server).
        parameters = [
            DiscoveredParameter(url="http://site.test/product?id=1", method="GET", name="id")
        ]
        findings = await agent.run(parameters, [])
        assert findings == []
        await client.aclose()
