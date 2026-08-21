import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.models.finding import Finding
from app.models.project import ScopeEntry
from app.models.scan import AgentJob, ScanRun
from tests.conftest import create_project_and_version, register_org_admin, session_scope


def _make_handler(*, csp_present: bool):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            if csp_present:
                self.send_header("Content-Security-Policy", "default-src 'self'")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format, *args):  # noqa: A002
            pass

    return Handler


def _server(*, csp_present: bool):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(csp_present=csp_present))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def _seed_finding(
    db_adapter,
    version_id: str,
    *,
    check_id: str,
    affected_endpoint: str,
    retest_status: str = "open",
) -> str:
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
            check_id=check_id,
            title="Test Finding",
            severity="Medium",
            owasp_2025_category="A02 Security Misconfiguration",
            cwe_id="CWE-693",
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            cvss_score=5.0,
            affected_endpoints=[affected_endpoint],
            plain_language_summary="test",
            technical_description="test",
            remediation="test",
            retest_status=retest_status,
        )
        session.add(finding)
        await session.commit()
        await session.refresh(finding)
        return str(finding.id)


async def _add_scope(client, headers, version_id: str, host: str, port: int) -> None:
    resp = await client.post(
        f"/versions/{version_id}/scope-entries", json={"host": host, "port": port}, headers=headers
    )
    assert resp.status_code == 201, resp.text


async def test_retest_still_vulnerable_then_fixed(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    vuln_server, vuln_thread = _server(csp_present=False)
    try:
        host, port = vuln_server.server_address
        await _add_scope(client, admin["headers"], version_id, host, port)
        finding_id = await _seed_finding(
            db_adapter, version_id, check_id="missing-csp", affected_endpoint=f"http://{host}:{port}/"
        )

        resp = await client.post(f"/findings/{finding_id}/retest", headers=admin["headers"])
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["status"] == "completed"
        assert body["result"] == "still_vulnerable"
        assert body["finding_id"] == finding_id
        assert body["response_raw"]
    finally:
        vuln_server.shutdown()
        vuln_thread.join(timeout=2)


async def test_retest_updates_finding_retest_status_to_fixed(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    fixed_server, fixed_thread = _server(csp_present=True)
    try:
        host, port = fixed_server.server_address
        await _add_scope(client, admin["headers"], version_id, host, port)
        finding_id = await _seed_finding(
            db_adapter, version_id, check_id="missing-csp", affected_endpoint=f"http://{host}:{port}/"
        )

        resp = await client.post(f"/findings/{finding_id}/retest", headers=admin["headers"])
        assert resp.status_code == 201, resp.text
        assert resp.json()["result"] == "fixed"

        async with session_scope(db_adapter) as session:
            finding = await session.get(Finding, uuid.UUID(finding_id))
            assert finding.retest_status == "fixed"
    finally:
        fixed_server.shutdown()
        fixed_thread.join(timeout=2)


async def test_retest_not_supported_for_unregistered_check(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    finding_id = await _seed_finding(
        db_adapter, version_id, check_id="sql-injection", affected_endpoint="http://site.test/search?q=1"
    )

    resp = await client.post(f"/findings/{finding_id}/retest", headers=admin["headers"])
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "completed"
    assert body["result"] == "not_supported"
    assert "full rescan" in body["error"]


async def test_retest_never_overrides_analyst_locked_status(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    vuln_server, vuln_thread = _server(csp_present=False)
    try:
        host, port = vuln_server.server_address
        await _add_scope(client, admin["headers"], version_id, host, port)
        finding_id = await _seed_finding(
            db_adapter,
            version_id,
            check_id="missing-csp",
            affected_endpoint=f"http://{host}:{port}/",
            retest_status="risk_accepted",
        )

        resp = await client.post(f"/findings/{finding_id}/retest", headers=admin["headers"])
        assert resp.status_code == 201, resp.text
        assert resp.json()["result"] == "still_vulnerable"

        async with session_scope(db_adapter) as session:
            finding = await session.get(Finding, uuid.UUID(finding_id))
            assert finding.retest_status == "risk_accepted"
    finally:
        vuln_server.shutdown()
        vuln_thread.join(timeout=2)


async def test_list_retest_jobs_returns_history_in_order(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    vuln_server, vuln_thread = _server(csp_present=False)
    try:
        host, port = vuln_server.server_address
        await _add_scope(client, admin["headers"], version_id, host, port)
        finding_id = await _seed_finding(
            db_adapter, version_id, check_id="missing-csp", affected_endpoint=f"http://{host}:{port}/"
        )

        empty = await client.get(f"/findings/{finding_id}/retest-jobs", headers=admin["headers"])
        assert empty.status_code == 200
        assert empty.json() == []

        await client.post(f"/findings/{finding_id}/retest", headers=admin["headers"])
        await client.post(f"/findings/{finding_id}/retest", headers=admin["headers"])

        listed = await client.get(f"/findings/{finding_id}/retest-jobs", headers=admin["headers"])
        assert listed.status_code == 200
        body = listed.json()
        assert len(body) == 2
        assert body[0]["created_at"] <= body[1]["created_at"]
    finally:
        vuln_server.shutdown()
        vuln_thread.join(timeout=2)


async def test_retest_requires_auth(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    finding_id = await _seed_finding(
        db_adapter, version_id, check_id="missing-csp", affected_endpoint="http://site.test/"
    )

    resp = await client.post(f"/findings/{finding_id}/retest")
    assert resp.status_code == 401


async def test_retest_404_for_finding_in_another_org(client, db_adapter):
    admin_a = await register_org_admin(client, org_name="Org A", email="a@example.io")
    _, version_id_a = await create_project_and_version(client, admin_a["headers"])
    finding_id = await _seed_finding(
        db_adapter, version_id_a, check_id="missing-csp", affected_endpoint="http://site.test/"
    )

    admin_b = await register_org_admin(client, org_name="Org B", email="b@example.io")
    resp = await client.post(f"/findings/{finding_id}/retest", headers=admin_b["headers"])
    assert resp.status_code == 404
