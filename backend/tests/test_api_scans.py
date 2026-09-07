import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

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


class _MutableFixtureHandler(BaseHTTPRequestHandler):
    """Same as _FixtureSiteHandler, but whether the CSP header is present
    can be toggled between requests (class-level flag) — lets a retest
    test simulate "the missing-CSP finding got fixed between scans."
    """

    csp_enabled = False

    def do_GET(self):  # noqa: N802
        if self.path == "/":
            body = b'<html><body><a href="/about">About</a></body></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "sid=abc123; Path=/")
            if type(self).csp_enabled:
                self.send_header("Content-Security-Policy", "default-src 'self'")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):  # noqa: A002
        pass


@pytest.fixture
def mutable_fixture_site():
    _MutableFixtureHandler.csp_enabled = False
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MutableFixtureHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
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


class _XssFixtureHandler(BaseHTTPRequestHandler):
    """A homepage linking to a real reflected-XSS search endpoint — real
    enough for recon to discover the parameter and for a real headless
    browser (§2 step 2 browser-proof) to actually execute the payload.
    """

    def do_GET(self):  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/":
            body = b'<html><body><a href="/search?q=x">Search</a></body></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path == "/search":
            value = parse_qs(parsed.query).get("q", [""])[0]
            body = f"<html><body>Results for: {value}</body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):  # noqa: A002
        pass


@pytest.fixture
def xss_fixture_site():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _XssFixtureHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_screenshot_from_real_xss_browser_proof_appears_in_all_report_formats(
    client, xss_fixture_site, monkeypatch
):
    """End-to-end: real scan -> real Playwright browser-proof captures a
    real screenshot -> auto-confirmed Finding -> report.html/pdf/docx all
    embed it. Only the LLM triage call is a test double (ScriptedAIProviderAdapter,
    same pattern used everywhere else in this codebase for AI) — recon,
    the reflected-XSS detection, the headless-browser proof, screenshot
    capture/storage, and report rendering are all real.
    """
    from tests.fakes import ScriptedAIProviderAdapter

    provider = ScriptedAIProviderAdapter.from_responses(
        '{"vulnerable": true, "confidence": "high", "reasoning": "unescaped reflection in HTML body"}'
    )
    monkeypatch.setattr("app.ai.provider.get_ai_provider", lambda: provider)

    host, port = xss_fixture_site
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    await _authorize_and_target(client, admin["headers"], version_id, host, port)

    created = await client.post(f"/versions/{version_id}/scan-runs", headers=admin["headers"])
    assert created.status_code == 201
    scan_run_id = created.json()["id"]

    findings = (
        await client.get(f"/scan-runs/{scan_run_id}/findings", headers=admin["headers"])
    ).json()
    xss_findings = [f for f in findings if f["check_id"] == "xss-reflected"]
    assert len(xss_findings) == 1, findings
    assert xss_findings[0]["confirmation_status"] == "ai_confirmed"
    assert len(xss_findings[0]["evidence"]["screenshot_refs"]) == 1

    html = (await client.get(f"/scan-runs/{scan_run_id}/report.html", headers=admin["headers"])).text
    assert "Evidence — screenshot" in html
    assert 'src="data:image/png;base64,' in html

    pdf_resp = await client.get(f"/scan-runs/{scan_run_id}/report.pdf", headers=admin["headers"])
    assert pdf_resp.content[:5] == b"%PDF-"
    from pypdf import PdfReader
    import io

    reader = PdfReader(io.BytesIO(pdf_resp.content))
    assert sum(len(page.images) for page in reader.pages) >= 1

    docx_resp = await client.get(f"/scan-runs/{scan_run_id}/report.docx", headers=admin["headers"])
    from docx import Document

    document = Document(io.BytesIO(docx_resp.content))
    assert len(document.inline_shapes) >= 1


async def test_retest_marks_fixed_findings_and_keeps_open_ones_open(client, mutable_fixture_site):
    host, port = mutable_fixture_site
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    await _authorize_and_target(client, admin["headers"], version_id, host, port)

    first = await client.post(f"/versions/{version_id}/scan-runs", headers=admin["headers"])
    assert first.status_code == 201
    first_scan_run_id = first.json()["id"]

    first_findings = (
        await client.get(f"/scan-runs/{first_scan_run_id}/findings", headers=admin["headers"])
    ).json()
    check_ids = {f["check_id"] for f in first_findings}
    assert "missing-csp" in check_ids
    assert "cookie-missing-httponly" in check_ids
    assert all(f["retest_status"] == "open" for f in first_findings)

    # Fix the CSP issue (but not the cookie one) before retesting.
    _MutableFixtureHandler.csp_enabled = True

    retest = await client.post(
        f"/versions/{version_id}/scan-runs/{first_scan_run_id}/retest", headers=admin["headers"]
    )
    assert retest.status_code == 201, retest.text
    second_scan_run_id = retest.json()["id"]
    assert second_scan_run_id != first_scan_run_id

    second_detail = await client.get(f"/scan-runs/{second_scan_run_id}", headers=admin["headers"])
    assert second_detail.json()["status"] == "completed"

    # The prior run's findings should now reflect the diff.
    first_findings_after = (
        await client.get(f"/scan-runs/{first_scan_run_id}/findings", headers=admin["headers"])
    ).json()
    by_check_id = {f["check_id"]: f for f in first_findings_after}
    assert by_check_id["missing-csp"]["retest_status"] == "fixed"
    assert by_check_id["cookie-missing-httponly"]["retest_status"] == "open"

    # The new scan run's own findings must NOT include missing-csp again.
    second_findings = (
        await client.get(f"/scan-runs/{second_scan_run_id}/findings", headers=admin["headers"])
    ).json()
    assert "missing-csp" not in {f["check_id"] for f in second_findings}
    assert "cookie-missing-httponly" in {f["check_id"] for f in second_findings}


async def test_retest_rejects_prior_scan_run_from_another_version(client, mutable_fixture_site):
    host, port = mutable_fixture_site
    admin = await register_org_admin(client)
    _, version_id_a = await create_project_and_version(client, admin["headers"], project_name="A")
    _, version_id_b = await create_project_and_version(client, admin["headers"], project_name="B")
    await _authorize_and_target(client, admin["headers"], version_id_a, host, port)
    await _authorize_and_target(client, admin["headers"], version_id_b, host, port)

    first = await client.post(f"/versions/{version_id_a}/scan-runs", headers=admin["headers"])
    first_scan_run_id = first.json()["id"]

    retest = await client.post(
        f"/versions/{version_id_b}/scan-runs/{first_scan_run_id}/retest", headers=admin["headers"]
    )
    assert retest.status_code == 404


async def test_scan_run_no_longer_requires_authorization(client, fixture_site):
    """The §1 authorization gate was removed from scan creation per user
    request — a Version with a Target but no authorization record must
    be allowed to scan (only the target guardrail below still applies)."""
    host, port = fixture_site
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    await client.post(
        f"/versions/{version_id}/targets",
        json={"host": host, "port": port, "base_url": f"http://{host}:{port}/"},
        headers=admin["headers"],
    )

    resp = await client.post(f"/versions/{version_id}/scan-runs", headers=admin["headers"])
    assert resp.status_code == 201, resp.text


async def test_scan_run_rejected_without_a_target(client):
    """Regression test: a Version with authorization but no Target used
    to let a scan through — every agent 'completed' having crawled
    nothing, looking like a successful-but-empty scan rather than a
    misconfigured one. Now caught up front with a clear 400."""
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    await client.post(
        f"/versions/{version_id}/authorization",
        data={"approver_name": "Self", "attestation_text": "no target on purpose"},
        headers=admin["headers"],
    )

    resp = await client.post(f"/versions/{version_id}/scan-runs", headers=admin["headers"])
    assert resp.status_code == 400
    assert "target" in resp.json()["detail"].lower()


async def test_scan_run_rejects_unknown_ai_provider_config(client, fixture_site):
    host, port = fixture_site
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    await _authorize_and_target(client, admin["headers"], version_id, host, port)

    resp = await client.post(
        f"/versions/{version_id}/scan-runs",
        json={"ai_provider_config_id": str(uuid.uuid4())},
        headers=admin["headers"],
    )
    assert resp.status_code == 404


async def test_scan_run_attaches_chosen_ai_provider_config(client, fixture_site):
    host, port = fixture_site
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    await _authorize_and_target(client, admin["headers"], version_id, host, port)

    config = await client.post(
        "/ai-provider-configs",
        json={
            "label": "In-house",
            "provider": "custom",
            "model": "llama3.1:8b",
            "api_key": "sk-abc",
            "base_url": "http://localhost:11434/v1",
        },
        headers=admin["headers"],
    )
    config_id = config.json()["id"]

    created = await client.post(
        f"/versions/{version_id}/scan-runs",
        json={"ai_provider_config_id": config_id},
        headers=admin["headers"],
    )
    assert created.status_code == 201, created.text
    assert created.json()["ai_provider_config_id"] == config_id


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
        "host_header",
        "cors",
        "clickjacking",
        "xxe",
        "graphql",
        "deserialization",
        "dom_xss",
        "ssrf",
        "prototype_pollution",
        "request_smuggling",
        "oauth",
        "cache_poisoning",
        "login",
        "authenticated_recon",
        "injection",
        "xss",
        "auth",
        "access_control",
        "business_logic",
        "csrf",
        "stored_xss",
        "file_upload",
        "websocket",
        "chain_analysis",
    }
    assert all(job["status"] == "completed" for job in body["agent_jobs"]), body["agent_jobs"]
    assert sum(body["finding_counts_by_severity"].values()) > 0
    # §10 smart scan: recon's fingerprint runs against a real fixture
    # server, so it should detect at least the Python http.server default
    # Server header.
    assert body["tech_stack_fingerprint"] is not None
    assert any("Python" in s or "BaseHTTP" in s for s in body["tech_stack_fingerprint"]["server_software"])

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
    report_json_body = report_json.json()
    assert len(report_json_body["findings"]) == len(findings_body)
    assert report_json_body["executive_summary"]  # populated (fallback text, no AI provider configured)

    report_html = await client.get(f"/scan-runs/{scan_run_id}/report.html", headers=admin["headers"])
    assert report_html.status_code == 200
    assert "Verdikt Security Assessment Report" in report_html.text
    assert "cookie-missing-secure" not in report_html.text  # check id isn't user-facing
    assert "Missing Content-Security-Policy" in report_html.text
    assert "Executive Summary" in report_html.text

    # Executive summary is generated once and cached on the ScanRun — a
    # second report request must return byte-identical text, not
    # regenerate it (§10.5: don't re-spend LLM budget on repeat views).
    report_json_again = await client.get(
        f"/scan-runs/{scan_run_id}/report.json", headers=admin["headers"]
    )
    assert report_json_again.json()["executive_summary"] == report_json_body["executive_summary"]

    report_pdf = await client.get(f"/scan-runs/{scan_run_id}/report.pdf", headers=admin["headers"])
    assert report_pdf.status_code == 200
    assert report_pdf.headers["content-type"] == "application/pdf"
    assert report_pdf.content[:5] == b"%PDF-"

    report_docx = await client.get(f"/scan-runs/{scan_run_id}/report.docx", headers=admin["headers"])
    assert report_docx.status_code == 200
    assert (
        report_docx.headers["content-type"]
        == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    assert report_docx.content[:2] == b"PK"

    traffic = await client.get(f"/versions/{version_id}/traffic", headers=admin["headers"])
    agent_traffic = [t for t in traffic.json() if t["source"] == "agent"]
    assert len(agent_traffic) > 0


async def test_cancel_on_an_already_completed_scan_is_rejected(client, fixture_site):
    host, port = fixture_site
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    await _authorize_and_target(client, admin["headers"], version_id, host, port)

    created = await client.post(f"/versions/{version_id}/scan-runs", headers=admin["headers"])
    scan_run_id = created.json()["id"]
    # Same ASGITransport guarantee as test_full_scan_flow_completes_and_produces_report:
    # the scan has already finished by the time the POST above returns.

    cancel = await client.post(f"/scan-runs/{scan_run_id}/cancel", headers=admin["headers"])
    assert cancel.status_code == 409


async def test_delete_completed_scan_cascades_its_findings(client, fixture_site):
    host, port = fixture_site
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    await _authorize_and_target(client, admin["headers"], version_id, host, port)

    created = await client.post(f"/versions/{version_id}/scan-runs", headers=admin["headers"])
    scan_run_id = created.json()["id"]

    delete = await client.delete(f"/scan-runs/{scan_run_id}", headers=admin["headers"])
    assert delete.status_code == 204

    detail = await client.get(f"/scan-runs/{scan_run_id}", headers=admin["headers"])
    assert detail.status_code == 404

    remaining = await client.get(f"/versions/{version_id}/scan-runs", headers=admin["headers"])
    assert scan_run_id not in {s["id"] for s in remaining.json()}


async def test_delete_a_running_scan_is_blocked_until_cancelled(client, fixture_site, db_adapter):
    # ASGITransport always runs the scan to completion synchronously, so a
    # genuinely in-flight "running" row is simulated directly rather than
    # raced against — this is exercising delete_scan_run's own guard, not
    # the background execution itself.
    import uuid as uuid_module

    from app.models.scan import ScanRun
    from tests.conftest import session_scope

    host, port = fixture_site
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    await _authorize_and_target(client, admin["headers"], version_id, host, port)

    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(
            version_id=uuid_module.UUID(version_id),
            status="running",
            requested_by=uuid_module.uuid4(),
        )
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)
        scan_run_id = str(scan_run.id)

    delete = await client.delete(f"/scan-runs/{scan_run_id}", headers=admin["headers"])
    assert delete.status_code == 409

    cancel = await client.post(f"/scan-runs/{scan_run_id}/cancel", headers=admin["headers"])
    assert cancel.status_code == 200
    assert cancel.json()["status"] == "cancelled"

    delete_again = await client.delete(f"/scan-runs/{scan_run_id}", headers=admin["headers"])
    assert delete_again.status_code == 204
