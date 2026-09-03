import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.models.finding import Finding
from app.models.scan import AgentJob, ScanRun
from app.models.vgs_config import VGSConfig
from app.notifications.vgs_push import push_findings_to_vgs
from app.vault.credential_vault import encrypt_secret, mask_secret
from tests.conftest import create_project_and_version, register_org_admin, session_scope


def _make_vgs_fixture(*, accept: bool = True):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            received.append(self.rfile.read(length))
            if accept:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            else:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"nope")

        def log_message(self, format, *args):  # noqa: A002
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, received


async def _make_scan_with_finding(client, admin, session, version_id):
    scan_run = ScanRun(version_id=uuid.UUID(version_id), status="completed", requested_by=uuid.uuid4())
    session.add(scan_run)
    await session.commit()
    await session.refresh(scan_run)

    job = AgentJob(scan_run_id=scan_run.id, agent_type="header_config", status="completed")
    session.add(job)
    await session.commit()
    await session.refresh(job)

    session.add(
        Finding(
            scan_run_id=scan_run.id,
            agent_job_id=job.id,
            check_id="missing-hsts",
            title="Missing HSTS",
            severity="Low",
            owasp_2025_category="A02 Security Misconfiguration",
            cwe_id="CWE-693",
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            cvss_score=3.0,
            affected_endpoints=["http://site.test/"],
            plain_language_summary="summary",
            technical_description="technical",
            remediation="remediate",
        )
    )
    await session.commit()
    return scan_run


async def test_push_findings_to_vgs_sends_real_confirmed_findings(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    server, thread, received = _make_vgs_fixture(accept=True)
    try:
        host, port = server.server_address
        webhook_url = f"http://{host}:{port}/ingest"

        async with session_scope(db_adapter) as session:
            me = await client.get("/auth/me", headers=admin["headers"])
            org_id = uuid.UUID(me.json()["org_id"])

            session.add(
                VGSConfig(
                    org_id=org_id,
                    label="Fixture VGS",
                    encrypted_webhook_url=encrypt_secret(webhook_url),
                    masked_reference=mask_secret(webhook_url),
                    push_on_scan_completed=True,
                )
            )
            scan_run = await _make_scan_with_finding(client, admin, session, version_id)

            await push_findings_to_vgs(session, scan_run)

        assert len(received) == 1
        payload = json.loads(received[0])
        assert payload["source"] == "ai-multi-agent"
        assert payload["scan_run_id"] == str(scan_run.id)
        assert len(payload["findings"]) == 1
        assert payload["findings"][0]["check_id"] == "missing-hsts"
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_push_findings_to_vgs_is_a_silent_no_op_without_a_config(db_adapter, client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.UUID(version_id), status="completed", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        # No VGSConfig exists for this org — must not raise.
        await push_findings_to_vgs(session, scan_run)


async def test_one_broken_config_does_not_stop_a_second_working_one(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    server, thread, received = _make_vgs_fixture(accept=True)
    try:
        host, port = server.server_address
        working_url = f"http://{host}:{port}/ingest"
        # Port 1 is reserved/unreachable — a real, guaranteed connection failure.
        broken_url = "http://127.0.0.1:1/ingest"

        async with session_scope(db_adapter) as session:
            me = await client.get("/auth/me", headers=admin["headers"])
            org_id = uuid.UUID(me.json()["org_id"])

            session.add(
                VGSConfig(
                    org_id=org_id,
                    label="Broken VGS",
                    encrypted_webhook_url=encrypt_secret(broken_url),
                    masked_reference=mask_secret(broken_url),
                    push_on_scan_completed=True,
                )
            )
            session.add(
                VGSConfig(
                    org_id=org_id,
                    label="Working VGS",
                    encrypted_webhook_url=encrypt_secret(working_url),
                    masked_reference=mask_secret(working_url),
                    push_on_scan_completed=True,
                )
            )
            scan_run = await _make_scan_with_finding(client, admin, session, version_id)

            # Must not raise despite the first config being unreachable.
            await push_findings_to_vgs(session, scan_run)

        assert len(received) == 1
    finally:
        server.shutdown()
        thread.join(timeout=2)
