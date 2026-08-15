import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests.conftest import create_project_and_version, register_org_admin


class _FixtureSiteHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 — http.server's required method name
        if self.path == "/":
            body = b'<html><body><a href="/about">About</a></body></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "sid=abc123; Path=/")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/about":
            body = b"<html><body>About this fixture site</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):  # noqa: A002 — silence default logging
        pass


@pytest.fixture
def fixture_site():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureSiteHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address  # (host, port)
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def _authorize_and_target(client, headers, version_id, host, port):
    await client.post(
        f"/versions/{version_id}/scope-entries",
        json={"host": host, "port": port, "in_scope": True},
        headers=headers,
    )
    await client.post(
        f"/versions/{version_id}/authorization",
        data={"approver_name": "Self", "attestation_text": "local fixture site, self-authorized"},
        headers=headers,
    )
    await client.post(
        f"/versions/{version_id}/targets",
        json={"host": host, "port": port, "base_url": f"http://{host}:{port}/"},
        headers=headers,
    )


async def test_scan_run_rejected_without_authorization(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(f"/versions/{version_id}/scan-runs", headers=admin["headers"])
    assert resp.status_code == 403


async def test_full_scan_flow_completes_and_produces_report(client, fixture_site):
    host, port = fixture_site
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    await _authorize_and_target(client, admin["headers"], version_id, host, port)

    created = await client.post(f"/versions/{version_id}/scan-runs", headers=admin["headers"])
    assert created.status_code == 201
    scan_run_id = created.json()["id"]

    # httpx's ASGITransport runs Starlette's BackgroundTasks to completion
    # before the POST call returns, so the scan has already finished here.
    detail = await client.get(f"/scan-runs/{scan_run_id}", headers=admin["headers"])
    assert detail.status_code == 200
    body = detail.json()
    assert body["status"] == "completed", body
    # The LangGraph orchestrator runs the full agent set (§13) even with
    # no credentials/business rules configured — auth/access-control/
    # injection/xss/business-logic just find nothing to do rather than
    # failing.
    assert {job["agent_type"] for job in body["agent_jobs"]} == {
        "recon",
        "header_config",
        "login",
        "injection",
        "xss",
        "auth",
        "access_control",
        "business_logic",
    }
    assert all(job["status"] == "completed" for job in body["agent_jobs"]), body["agent_jobs"]
    assert sum(body["finding_counts_by_severity"].values()) > 0

    findings = await client.get(f"/scan-runs/{scan_run_id}/findings", headers=admin["headers"])
    assert findings.status_code == 200
    findings_body = findings.json()
    assert len(findings_body) > 0
    check_ids = {f["check_id"] for f in findings_body}
    assert "missing-csp" in check_ids
    assert "cookie-missing-httponly" in check_ids
    assert "cookie-missing-samesite" in check_ids
    assert "plaintext-http" in check_ids
    # HSTS and Secure-cookie only apply over https; the fixture site is
    # plain http, so these must NOT fire (would be a false positive).
    assert "missing-hsts" not in check_ids
    assert "cookie-missing-secure" not in check_ids
    for f in findings_body:
        assert f["confirmation_status"] == "ai_confirmed"
        assert f["evidence"]["request_raw"]
        assert f["evidence"]["response_raw"]

    report_json = await client.get(f"/scan-runs/{scan_run_id}/report.json", headers=admin["headers"])
    assert report_json.status_code == 200
    assert len(report_json.json()["findings"]) == len(findings_body)

    report_html = await client.get(f"/scan-runs/{scan_run_id}/report.html", headers=admin["headers"])
    assert report_html.status_code == 200
    assert "Verdikt Security Assessment Report" in report_html.text
    assert "cookie-missing-secure" not in report_html.text  # check id isn't user-facing
    assert "Missing Content-Security-Policy" in report_html.text

    traffic = await client.get(f"/versions/{version_id}/traffic", headers=admin["headers"])
    agent_traffic = [t for t in traffic.json() if t["source"] == "agent"]
    assert len(agent_traffic) > 0
