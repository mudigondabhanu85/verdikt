import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.models.finding import Finding
from app.models.scan import AgentJob, ScanRun
from tests.conftest import create_project_and_version, register_org_admin, session_scope


def _make_jira_fixture(*, accept: bool):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            if self.path != "/rest/api/3/issue":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", 0))
            received.append(json.loads(self.rfile.read(length).decode()))
            if accept:
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                body = json.dumps({"id": "10099", "key": "SEC-99", "self": "http://jira.invalid/rest/api/3/issue/10099"}).encode()
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"errors": {"project": "project is required"}}')

        def log_message(self, format, *args):  # noqa: A002
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, received


async def _seed_finding(db_adapter, version_id: str) -> str:
    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.UUID(version_id), status="completed", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        job = AgentJob(scan_run_id=scan_run.id, agent_type="header_config", status="completed")
        session.add(job)
        await session.commit()
        await session.refresh(job)

        finding = Finding(
            scan_run_id=scan_run.id,
            agent_job_id=job.id,
            check_id="missing-csp",
            title="Missing Content-Security-Policy Header",
            severity="Medium",
            owasp_2025_category="A02 Security Misconfiguration",
            cwe_id="CWE-693",
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            cvss_score=5.0,
            affected_endpoints=["http://site.test/"],
            plain_language_summary="summary",
            technical_description="technical",
            remediation="remediate",
        )
        session.add(finding)
        await session.commit()
        await session.refresh(finding)
        return str(finding.id)


async def _seed_ticketing_config(client, headers, base_url: str) -> str:
    resp = await client.post(
        "/ticketing-configs",
        json={
            "label": "Fixture Jira",
            "provider": "jira",
            "base_url": base_url,
            "email": "analyst@example.io",
            "api_token": "fixture-token",
            "project_key": "SEC",
        },
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def test_create_ticket_persists_real_external_reference(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    finding_id = await _seed_finding(db_adapter, version_id)

    server, thread, received = _make_jira_fixture(accept=True)
    try:
        host, port = server.server_address
        config_id = await _seed_ticketing_config(client, admin["headers"], f"http://{host}:{port}")

        resp = await client.post(
            f"/findings/{finding_id}/tickets", json={"ticketing_config_id": config_id}, headers=admin["headers"]
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["external_key"] == "SEC-99"
        assert body["external_url"] == f"http://{host}:{port}/browse/SEC-99"
        assert body["finding_id"] == finding_id

        assert len(received) == 1
        assert received[0]["fields"]["project"]["key"] == "SEC"
        assert "Missing Content-Security-Policy" in received[0]["fields"]["summary"]

        listed = await client.get(f"/findings/{finding_id}/tickets", headers=admin["headers"])
        assert listed.status_code == 200
        assert len(listed.json()) == 1
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_create_ticket_surfaces_a_real_jira_failure_cleanly(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    finding_id = await _seed_finding(db_adapter, version_id)

    server, thread, _received = _make_jira_fixture(accept=False)
    try:
        host, port = server.server_address
        config_id = await _seed_ticketing_config(client, admin["headers"], f"http://{host}:{port}")

        resp = await client.post(
            f"/findings/{finding_id}/tickets", json={"ticketing_config_id": config_id}, headers=admin["headers"]
        )
        assert resp.status_code == 502
        assert "issue creation failed" in resp.text
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_create_ticket_404_for_unknown_ticketing_config(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    finding_id = await _seed_finding(db_adapter, version_id)

    resp = await client.post(
        f"/findings/{finding_id}/tickets",
        json={"ticketing_config_id": str(uuid.uuid4())},
        headers=admin["headers"],
    )
    assert resp.status_code == 404
