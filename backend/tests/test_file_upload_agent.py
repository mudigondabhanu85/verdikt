import re
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sqlalchemy import select

from app.agents.file_upload import FileUploadAgent
from app.agents.http_client import ScopedHttpClient
from app.agents.recon import FormField, FormInfo
from app.models.finding import Finding
from app.models.project import ScopeEntry
from tests.conftest import session_scope

_FILENAME_RE = re.compile(rb'filename="([^"]+)"')
_DANGEROUS_EXTENSIONS = (".php", ".jsp", ".asp")


def _extract_filename(body: bytes) -> str | None:
    match = _FILENAME_RE.search(body)
    return match.group(1).decode() if match else None


def _make_handler(*, reject_dangerous: bool):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            if self.path != "/upload":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            filename = _extract_filename(body) or ""

            if reject_dangerous and any(filename.endswith(ext) for ext in _DANGEROUS_EXTENSIONS):
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"File type not allowed")
                return

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Upload successful")

        def log_message(self, format, *args):  # noqa: A002
            pass

    return Handler


def _server(*, reject_dangerous: bool):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(reject_dangerous=reject_dangerous))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _form(host, port) -> FormInfo:
    return FormInfo(
        action_url=f"http://{host}:{port}/upload",
        method="POST",
        fields=[FormField(name="avatar", type="file"), FormField(name="caption", type="text")],
    )


async def test_endpoint_accepting_php_upload_is_flagged(db_adapter):
    server, thread = _server(reject_dangerous=False)
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            agent = FileUploadAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            findings = await agent.run([_form(host, port)])

            assert len(findings) == 1
            finding = findings[0]
            assert finding.check_id == "file-upload-insufficient-validation"
            assert finding.cwe_id == "CWE-434"
            assert finding.severity == "High"
            assert ".php" in finding.technical_description

            stored = (await session.execute(select(Finding))).scalars().all()
            assert len(stored) == 1

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_endpoint_rejecting_dangerous_extensions_is_not_flagged(db_adapter):
    server, thread = _server(reject_dangerous=True)
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            agent = FileUploadAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            findings = await agent.run([_form(host, port)])
            assert findings == []
            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_forms_without_a_file_field_are_skipped(db_adapter):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
        )
        agent = FileUploadAgent(
            client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
        )
        form = FormInfo(
            action_url="http://site.test/contact",
            method="POST",
            fields=[FormField(name="message", type="text")],
        )
        findings = await agent.run([form])
        assert findings == []
        await client.aclose()
