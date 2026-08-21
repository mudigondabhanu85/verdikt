import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from sqlalchemy import select

from app.agents.cache_poisoning import CachePoisoningAgent
from app.agents.http_client import ScopedHttpClient
from app.models.finding import Finding
from app.models.project import ScopeEntry
from tests.conftest import session_scope


def _make_handler(*, vulnerable: bool):
    # Simulates a shared/CDN cache in front of the app: keyed on the
    # full request path+query string (so each cache-busted probe
    # attempt gets its own fresh entry) but — the vulnerability itself
    # — blind to headers, so a poisoned entry gets replayed verbatim to
    # a later plain request for the same path+query.
    cache: dict[str, tuple[bytes, str]] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            path = urlsplit(self.path).path
            if path == "/":
                if self.path in cache:
                    body, cache_control = cache[self.path]
                else:
                    forwarded_host = self.headers.get("X-Forwarded-Host")
                    if vulnerable and forwarded_host:
                        body = f"<html><link rel=canonical href='https://{forwarded_host}/'></html>".encode()
                    else:
                        body = b"<html><link rel=canonical href='https://real.test/'></html>"
                    cache_control = "public, max-age=300" if vulnerable else "private, no-store"
                    if vulnerable:
                        cache[self.path] = (body, cache_control)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Cache-Control", cache_control)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/nonexistent.css" and vulnerable:  # noqa: SIM102
                # Vulnerable routing: an unmapped trailing path is
                # ignored and the app falls back to serving "/"'s
                # content (a real Rails/Spring-style prefix-match bug).
                body = b"<html><link rel=canonical href='https://real.test/'></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/css")
                self.send_header("Cache-Control", "public, max-age=300")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            self.send_response(404)
            self.end_headers()

        def log_message(self, format, *args):  # noqa: A002
            pass

    return Handler


def _server(*, vulnerable: bool):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(vulnerable=vulnerable))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_vulnerable_server_flags_poisoning_and_deception(db_adapter):
    server, thread = _server(vulnerable=True)
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            agent = CachePoisoningAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            findings = await agent.run([f"http://{host}:{port}/"])

            check_ids = {f.check_id for f in findings}
            assert check_ids == {"web-cache-poisoning-unkeyed-input", "web-cache-deception"}

            stored = (await session.execute(select(Finding))).scalars().all()
            assert len(stored) == 2

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_safe_server_is_not_flagged(db_adapter):
    server, thread = _server(vulnerable=False)
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            agent = CachePoisoningAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            findings = await agent.run([f"http://{host}:{port}/"])
            assert findings == []
            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)
