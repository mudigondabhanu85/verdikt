import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import httpx
from sqlalchemy import select

from app.agents.http_client import ScopedHttpClient
from app.agents.recon import FormField, FormInfo
from app.agents.stored_xss import StoredXssAgent
from app.models.finding import Finding
from app.models.project import ScopeEntry
from tests.conftest import session_scope


def _make_vulnerable_handler():
    state = {"comments": []}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/comments":
                body = "<html><body>" + "".join(f"<p>{c}</p>" for c in state["comments"]) + "</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body.encode())
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):  # noqa: N802
            if self.path == "/submit-comment":
                length = int(self.headers.get("Content-Length", 0))
                body = parse_qs(self.rfile.read(length).decode())
                comment = body.get("comment", [""])[0]
                # Stored unescaped — the vulnerability.
                state["comments"].append(comment)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Comment submitted")
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):  # noqa: A002
            pass

    return Handler


def _make_safe_handler():
    import html

    state = {"comments": []}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/comments":
                body = "<html><body>" + "".join(f"<p>{html.escape(c)}</p>" for c in state["comments"]) + "</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body.encode())
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):  # noqa: N802
            if self.path == "/submit-comment":
                length = int(self.headers.get("Content-Length", 0))
                body = parse_qs(self.rfile.read(length).decode())
                comment = body.get("comment", [""])[0]
                state["comments"].append(comment)  # stored, but rendered escaped
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Comment submitted")
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):  # noqa: A002
            pass

    return Handler


def _server(handler_cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _form(host, port) -> FormInfo:
    return FormInfo(
        action_url=f"http://{host}:{port}/submit-comment",
        method="POST",
        fields=[FormField(name="comment", type="text")],
    )


async def test_stored_xss_confirmed_across_two_pages(db_adapter):
    server, thread = _server(_make_vulnerable_handler())
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            agent = StoredXssAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            findings = await agent.run(
                [_form(host, port)], [f"http://{host}:{port}/comments"]
            )

            assert len(findings) == 1
            finding = findings[0]
            assert finding.check_id == "xss-stored"
            assert finding.severity == "Critical"
            assert finding.confirmation_status == "ai_confirmed"

            stored = (await session.execute(select(Finding))).scalars().all()
            assert len(stored) == 1
            await session.refresh(stored[0], attribute_names=["evidence"])
            assert len(stored[0].evidence.screenshot_refs) == 1

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_escaped_output_is_not_flagged(db_adapter):
    server, thread = _server(_make_safe_handler())
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            agent = StoredXssAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            findings = await agent.run(
                [_form(host, port)], [f"http://{host}:{port}/comments"]
            )
            assert findings == []
            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)
