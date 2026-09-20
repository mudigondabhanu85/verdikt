import re
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


_SCRIPT_TAG_RE = re.compile(r"<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t", re.IGNORECASE)


def _make_dvwa_high_style_handler():
    """Mirrors DVWA High's own real guestbook exactly (§14): the 'name'
    field is filtered with only the same "does this contain s.c.r.i.p.t"
    regex its reflected-XSS page uses, while 'message' goes through
    strip_tags() first — which removes any tag at all, no bypass exists.
    A <script> payload in 'name' gets stripped just like in 'message', but
    an <img onerror> payload survives in 'name' specifically.
    """
    state = {"entries": []}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/comments":
                rows = "".join(f"<p>{name}: {msg}</p>" for name, msg in state["entries"])
                body = f"<html><body>{rows}</body></html>"
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
                name = body.get("name", [""])[0]
                message = body.get("comment", [""])[0]
                name = _SCRIPT_TAG_RE.sub("", name)
                message = re.sub(r"<[^>]*>", "", message)  # strip_tags() equivalent
                state["entries"].append((name, message))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Comment submitted")
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):  # noqa: A002
            pass

    return Handler


def _dvwa_style_form(host, port) -> FormInfo:
    return FormInfo(
        action_url=f"http://{host}:{port}/submit-comment",
        method="POST",
        fields=[FormField(name="name", type="text"), FormField(name="comment", type="text")],
    )


async def test_script_tag_filter_is_bypassed_via_img_onerror_fallback(db_adapter):
    """The real, live-found DVWA High gap this fallback exists for: a
    <script> payload in the 'name' field is correctly stripped, but the
    agent still confirms the finding via the <img onerror> fallback
    instead of silently giving up. The 'message' field's strip_tags()
    defeats both variants and correctly yields no finding for it.
    """
    server, thread = _server(_make_dvwa_high_style_handler())
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
                [_dvwa_style_form(host, port)], [f"http://{host}:{port}/comments"]
            )

            assert len(findings) == 1
            finding = findings[0]
            assert finding.technical_description.count("onerror") >= 1
            assert "name" in finding.technical_description

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
