import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.models.finding import Finding
from app.models.notification_config import NotificationConfig
from app.models.scan import AgentJob, ScanRun
from app.notifications.scan_notifications import notify_scan_completed
from app.vault.credential_vault import encrypt_secret, mask_secret
from tests.conftest import create_project_and_version, register_org_admin, session_scope


def _make_slack_fixture():
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            received.append(self.rfile.read(length))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format, *args):  # noqa: A002
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, received


async def test_notify_scan_completed_posts_a_real_summary_to_slack(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    server, thread, received = _make_slack_fixture()
    try:
        host, port = server.server_address
        webhook_url = f"http://{host}:{port}/webhook"

        async with session_scope(db_adapter) as session:
            # register_org_admin() doesn't return org_id directly — look
            # it up from the real /auth/me identity instead of guessing.
            me = await client.get("/auth/me", headers=admin["headers"])
            org_id = uuid.UUID(me.json()["org_id"])

            session.add(
                NotificationConfig(
                    org_id=org_id,
                    label="Fixture Slack",
                    provider="slack",
                    encrypted_webhook_url=encrypt_secret(webhook_url),
                    masked_reference=mask_secret(webhook_url),
                    notify_on_scan_completed=True,
                )
            )

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

            await notify_scan_completed(session, scan_run)

        assert len(received) == 1
        text = received[0].decode()
        assert "completed" in text
        assert "Low: 1" in text
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_notify_scan_completed_is_a_silent_no_op_without_a_config(db_adapter, client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.UUID(version_id), status="completed", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        # No NotificationConfig exists for this org — must not raise.
        await notify_scan_completed(session, scan_run)


async def test_notify_scan_completed_swallows_a_real_unreachable_webhook(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    async with session_scope(db_adapter) as session:
        me = await client.get("/auth/me", headers=admin["headers"])
        org_id = uuid.UUID(me.json()["org_id"])

        # Port 1 is reserved/unreachable — a real, guaranteed connection failure.
        webhook_url = "http://127.0.0.1:1/webhook"
        session.add(
            NotificationConfig(
                org_id=org_id,
                label="Unreachable",
                provider="slack",
                encrypted_webhook_url=encrypt_secret(webhook_url),
                masked_reference=mask_secret(webhook_url),
                notify_on_scan_completed=True,
            )
        )
        scan_run = ScanRun(version_id=uuid.UUID(version_id), status="completed", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        # Must not raise despite the webhook being unreachable.
        await notify_scan_completed(session, scan_run)
