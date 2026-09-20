"""Tests for the VGS report-builder API (app/api/routes/vgs_vulnerabilities.py)
and the ported DOCX generator (app/reporting/vgs_docx_report.py).

The routers aren't registered on the main app yet (that happens in a
central wiring pass after this and several other parallel feature slices
land), so this builds its own minimal FastAPI app mounting just these
routers — same dependency-override pattern tests/conftest.py's `client`
fixture uses against the real app (see tests/test_org_branding.py for
the identical established pattern this file mirrors).
"""

import io
import uuid

import pytest_asyncio
from docx import Document
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from PIL import Image

import app.api.routes.vgs_vulnerabilities as vgs_routes
from app.api.routes.vgs_vulnerabilities import draft_router, library_router
from app.auth.security import create_access_token, hash_password
from app.db.session import get_db_session
from app.integrations.portswigger.client import PortswigerFetchError, PortswigerTopic
from app.models.finding import Evidence, Finding
from app.models.organization import Organization, User
from app.models.project import Project, Version
from app.models.scan import AgentJob, ScanRun
from tests.conftest import db_adapter  # noqa: F401 — reused fixture
from tests.conftest import session_scope


def _make_app():
    app = FastAPI()
    app.include_router(library_router)
    app.include_router(draft_router)
    return app


@pytest_asyncio.fixture
async def vgs_client(db_adapter, monkeypatch):
    from app.db.session import get_adapter

    monkeypatch.setattr("app.db.session.get_adapter", lambda: db_adapter)
    get_adapter.cache_clear()

    app = _make_app()

    async def _override_get_db_session():
        async for session in db_adapter.get_session():
            yield session

    app.dependency_overrides[get_db_session] = _override_get_db_session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, db_adapter
    app.dependency_overrides.clear()


async def _create_org_admin(db_adapter, *, org_name="Acme"):
    async with session_scope(db_adapter) as session:
        org = Organization(name=f"{org_name}-{uuid.uuid4()}")
        session.add(org)
        await session.flush()
        user = User(
            org_id=org.id,
            email=f"admin-{uuid.uuid4()}@example.com",
            hashed_password=hash_password("correct-horse-battery-staple"),
            role="org_admin",
            is_active=True,
        )
        session.add(user)
        await session.flush()
        project = Project(org_id=org.id, name="Test Project", created_by=user.id)
        session.add(project)
        await session.flush()
        version = Version(project_id=project.id, name="v1", created_by=user.id)
        session.add(version)
        await session.commit()
        await session.refresh(user)
        await session.refresh(version)
        token = create_access_token(user.id)
        return org, user, version, {"Authorization": f"Bearer {token}"}


def _real_png_bytes() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (20, 10), color=(200, 0, 0)).save(buf, format="PNG")
    return buf.getvalue()


async def _make_finding(
    db_adapter,
    version_id,
    *,
    retest_status="open",
    with_screenshot=False,
    steps_to_reproduce=None,
    endpoint="http://site.test/",
) -> Finding:
    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=version_id, status="completed", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.flush()

        job = AgentJob(scan_run_id=scan_run.id, agent_type="header_config", status="completed")
        session.add(job)
        await session.flush()

        finding = Finding(
            scan_run_id=scan_run.id,
            agent_job_id=job.id,
            check_id="missing-hsts",
            title="Missing HSTS",
            severity="Low",
            owasp_2025_category="A02 Security Misconfiguration",
            cwe_id="CWE-693",
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            cvss_score=3.0,
            affected_endpoints=[endpoint],
            plain_language_summary="summary",
            technical_description="technical",
            remediation="remediate",
            retest_status=retest_status,
            steps_to_reproduce=steps_to_reproduce or [],
        )
        session.add(finding)
        await session.flush()

        if with_screenshot:
            session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw="GET / HTTP/1.1",
                    response_raw="HTTP/1.1 200 OK",
                    screenshot_refs=["vgs-evidence/fixture-key.png"],
                )
            )
        await session.commit()
        await session.refresh(finding)
        return finding


async def test_library_crud_and_org_scoping(vgs_client):
    client, db_adapter = vgs_client
    org_a, _user_a, _v_a, headers_a = await _create_org_admin(db_adapter, org_name="OrgA")
    _org_b, _user_b, _v_b, headers_b = await _create_org_admin(db_adapter, org_name="OrgB")

    created = await client.post(
        "/vgs-vulnerability-library",
        json={
            "title": "SQL Injection",
            "severity": "Critical",
            "cvss_score": "9.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "description": "desc",
            "recommendation": "rec",
            "reference": "ref",
        },
        headers=headers_a,
    )
    assert created.status_code == 201, created.text
    entry_id = created.json()["id"]
    assert created.json()["org_id"] == str(org_a.id)

    list_a = await client.get("/vgs-vulnerability-library", headers=headers_a)
    assert len(list_a.json()) == 1

    # Org B can't see Org A's library entry.
    list_b = await client.get("/vgs-vulnerability-library", headers=headers_b)
    assert list_b.json() == []

    updated = await client.patch(
        f"/vgs-vulnerability-library/{entry_id}",
        json={
            "title": "SQL Injection (updated)",
            "severity": "High",
            "cvss_score": "8.0",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "description": "desc2",
            "recommendation": "rec2",
            "reference": "ref2",
        },
        headers=headers_a,
    )
    assert updated.status_code == 200
    assert updated.json()["title"] == "SQL Injection (updated)"

    deleted = await client.delete(f"/vgs-vulnerability-library/{entry_id}", headers=headers_a)
    assert deleted.status_code == 204
    assert (await client.get("/vgs-vulnerability-library", headers=headers_a)).json() == []


async def test_report_draft_get_or_create_and_update(vgs_client):
    client, db_adapter = vgs_client
    _org, _user, version, headers = await _create_org_admin(db_adapter)

    draft = await client.get(f"/versions/{version.id}/vgs-report-draft", headers=headers)
    assert draft.status_code == 200
    assert draft.json()["app_title"] == ""

    updated = await client.patch(
        f"/versions/{version.id}/vgs-report-draft",
        json={"app_title": "My App", "analyst_name": "Alice", "requester_name": "Bob"},
        headers=headers,
    )
    assert updated.status_code == 200
    assert updated.json()["app_title"] == "My App"
    assert updated.json()["analyst_name"] == "Alice"

    # Get-again returns the same draft, not a new one.
    draft_again = await client.get(f"/versions/{version.id}/vgs-report-draft", headers=headers)
    assert draft_again.json()["id"] == updated.json()["id"]


async def test_add_from_library_and_ad_hoc_vulnerabilities_and_generate_docx(vgs_client):
    client, db_adapter = vgs_client
    _org, _user, version, headers = await _create_org_admin(db_adapter)

    library_entry = await client.post(
        "/vgs-vulnerability-library",
        json={
            "title": "Reflected XSS",
            "severity": "High",
            "cvss_score": "7.4",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "description": "XSS description",
            "recommendation": "Escape output",
            "reference": "https://owasp.org/xss",
        },
        headers=headers,
    )
    library_entry_id = library_entry.json()["id"]

    await client.patch(
        f"/versions/{version.id}/vgs-report-draft",
        json={"app_title": "Test App", "analyst_name": "Alice", "requester_name": "Bob"},
        headers=headers,
    )

    from_library = await client.post(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities",
        json={"library_entry_id": library_entry_id},
        headers=headers,
    )
    assert from_library.status_code == 201, from_library.text
    assert from_library.json()["title"] == "Reflected XSS"
    assert from_library.json()["library_entry_id"] == library_entry_id

    ad_hoc = await client.post(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities",
        json={
            "title": "Custom Finding",
            "severity": "Medium",
            "cvss_score": "5.3",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "description": "custom desc",
            "recommendation": "custom rec",
            "reference": "custom ref",
        },
        headers=headers,
    )
    assert ad_hoc.status_code == 201, ad_hoc.text
    ad_hoc_id = ad_hoc.json()["id"]

    # Ad-hoc creation without title/severity is rejected.
    rejected = await client.post(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities", json={}, headers=headers
    )
    assert rejected.status_code == 400

    listed = await client.get(f"/versions/{version.id}/vgs-report-draft/vulnerabilities", headers=headers)
    assert len(listed.json()) == 2

    # Real evidence step with a real uploaded PNG.
    files = {"screenshot": ("proof.png", _real_png_bytes(), "image/png")}
    step = await client.post(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities/{ad_hoc_id}/evidence-steps",
        data={"comment": "Observed the injected script execute."},
        files=files,
        headers=headers,
    )
    assert step.status_code == 201, step.text
    assert len(step.json()["screenshot_object_keys"]) == 1

    # Real DOCX generation, re-opened and checked structurally.
    report = await client.get(f"/versions/{version.id}/vgs-report-draft/report.docx", headers=headers)
    assert report.status_code == 200
    assert report.headers["content-type"] == (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )

    document = Document(io.BytesIO(report.content))
    heading_texts = [p.text for p in document.paragraphs if p.style.name.startswith("Heading 3")]
    # One heading per vulnerability ("1. Reflected XSS", "2. Custom Finding").
    assert any("Reflected XSS" in h for h in heading_texts)
    assert any("Custom Finding" in h for h in heading_texts)
    assert len(document.inline_shapes) >= 1  # pie chart + evidence screenshot present


async def test_available_findings_lists_real_scan_findings_excluding_fixed(vgs_client):
    client, db_adapter = vgs_client
    _org, _user, version, headers = await _create_org_admin(db_adapter)

    open_finding = await _make_finding(db_adapter, version.id, with_screenshot=True)
    await _make_finding(db_adapter, version.id, retest_status="fixed")
    await _make_finding(db_adapter, version.id, retest_status="false_positive_after_review")

    listed = await client.get(f"/versions/{version.id}/vgs-report-draft/available-findings", headers=headers)
    assert listed.status_code == 200, listed.text
    payload = listed.json()
    assert len(payload) == 1
    assert payload[0]["finding"]["id"] == str(open_finding.id)
    assert payload[0]["already_added"] is False


async def test_add_from_finding_copies_fields_and_evidence_and_flags_already_added(vgs_client):
    client, db_adapter = vgs_client
    _org, _user, version, headers = await _create_org_admin(db_adapter)

    finding = await _make_finding(db_adapter, version.id, with_screenshot=True)

    added = await client.post(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities/from-finding/{finding.id}",
        headers=headers,
    )
    assert added.status_code == 201, added.text
    body = added.json()
    assert body["title"] == "Missing HSTS"
    assert body["severity"] == "Low"
    assert body["source_finding_id"] == str(finding.id)
    assert body["library_entry_id"] is None

    steps = await client.get(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities/{body['id']}/evidence-steps",
        headers=headers,
    )
    assert steps.status_code == 200
    assert len(steps.json()) == 1
    assert steps.json()[0]["screenshot_object_keys"] == ["vgs-evidence/fixture-key.png"]

    # The available-findings list now flags it as already added.
    listed = await client.get(f"/versions/{version.id}/vgs-report-draft/available-findings", headers=headers)
    assert listed.json()[0]["already_added"] is True


async def test_add_from_finding_carries_steps_to_reproduce_verbatim_into_evidence(vgs_client):
    """§ item 4: a developer reading the VGS report must see the real
    steps_to_reproduce the scanner followed, not just a generic note."""
    client, db_adapter = vgs_client
    _org, _user, version, headers = await _create_org_admin(db_adapter)

    finding = await _make_finding(
        db_adapter,
        version.id,
        with_screenshot=True,
        steps_to_reproduce=[
            "1. Request http://site.test/ over HTTPS.",
            "2. Observe the response has no Strict-Transport-Security header.",
        ],
    )

    added = await client.post(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities/from-finding/{finding.id}",
        headers=headers,
    )
    assert added.status_code == 201, added.text
    vuln_id = added.json()["id"]

    steps = await client.get(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities/{vuln_id}/evidence-steps",
        headers=headers,
    )
    assert steps.status_code == 200
    comment = steps.json()[0]["comment"]
    assert "1. Request http://site.test/ over HTTPS." in comment
    assert "2. Observe the response has no Strict-Transport-Security header." in comment
    assert steps.json()[0]["screenshot_object_keys"] == ["vgs-evidence/fixture-key.png"]


async def test_auto_seed_creates_one_evidence_step_per_endpoint_up_to_the_detailed_cap(vgs_client):
    """§ item 5: a check confirmed on multiple endpoints should read as
    distinct, individually-reproducible steps in the report, not one
    undifferentiated blob covering only the first endpoint found."""
    client, db_adapter = vgs_client
    _org, _user, version, headers = await _create_org_admin(db_adapter)

    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=version.id, status="completed", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.flush()
        job = AgentJob(scan_run_id=scan_run.id, agent_type="header_config", status="completed")
        session.add(job)
        await session.flush()

        for i in range(3):
            endpoint = f"http://site.test/page{i}"
            finding = Finding(
                scan_run_id=scan_run.id,
                agent_job_id=job.id,
                check_id="missing-csp",
                title="Missing Content-Security-Policy",
                severity="Medium",
                owasp_2025_category="A02 Security Misconfiguration",
                cwe_id="CWE-693",
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                cvss_score=5.0,
                affected_endpoints=[endpoint],
                plain_language_summary="summary",
                technical_description="technical",
                remediation="remediate",
                retest_status="open",
                steps_to_reproduce=[f"1. Request {endpoint}.", "2. Observe no CSP header."],
            )
            session.add(finding)
        await session.commit()

    listed = await client.get(f"/versions/{version.id}/vgs-report-draft/vulnerabilities", headers=headers)
    assert listed.status_code == 200
    [vuln] = [v for v in listed.json() if v["title"] == "Missing Content-Security-Policy"]

    steps = await client.get(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities/{vuln['id']}/evidence-steps",
        headers=headers,
    )
    assert steps.status_code == 200
    bodies = steps.json()
    assert len(bodies) == 3
    endpoints_seen = {f"http://site.test/page{i}" for i in range(3)}
    assert all(any(ep in step["comment"] for ep in endpoints_seen) for step in bodies)


async def _make_findings_sharing_check_id(db_adapter, version_id, endpoints: list[str]) -> list[Finding]:
    """Simulates what a real scan actually produces: the same
    vulnerability check (check_id/title identical) confirmed across many
    crawled endpoints — one Finding row per endpoint, same as
    header_config.py/injection.py's real per-hit persistence."""
    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=version_id, status="completed", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.flush()
        job = AgentJob(scan_run_id=scan_run.id, agent_type="header_config", status="completed")
        session.add(job)
        await session.flush()

        findings = []
        for endpoint in endpoints:
            finding = Finding(
                scan_run_id=scan_run.id,
                agent_job_id=job.id,
                check_id="missing-csp",
                title="Missing Content-Security-Policy",
                severity="Medium",
                owasp_2025_category="A02 Security Misconfiguration",
                cwe_id="CWE-693",
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                cvss_score=5.0,
                affected_endpoints=[endpoint],
                plain_language_summary="Missing CSP header allows XSS to be more impactful.",
                technical_description="technical",
                remediation="Add a Content-Security-Policy header.",
                retest_status="open",
            )
            session.add(finding)
            findings.append(finding)
        await session.commit()
        for finding in findings:
            await session.refresh(finding)
        return findings


async def test_available_findings_and_auto_seed_group_by_check_id_not_one_row_per_endpoint(vgs_client):
    """Regression test for the user-reported '6400 vulns' report bloat:
    a single vulnerability class confirmed on many endpoints (the normal
    shape of a real scan — see header_config.py/injection.py, one Finding
    row per endpoint) must collapse into ONE picker entry / ONE
    auto-seeded report vulnerability, with every endpoint folded into
    affected_endpoints, not one row per endpoint."""
    client, db_adapter = vgs_client
    _org, _user, version, headers = await _create_org_admin(db_adapter)

    endpoints = [f"http://site.test/page{i}" for i in range(50)]
    instances = await _make_findings_sharing_check_id(db_adapter, version.id, endpoints)

    available = await client.get(f"/versions/{version.id}/vgs-report-draft/available-findings", headers=headers)
    assert available.status_code == 200, available.text
    payload = available.json()
    assert len(payload) == 1
    assert payload[0]["finding"]["title"] == "Missing Content-Security-Policy"
    assert sorted(payload[0]["finding"]["affected_endpoints"]) == sorted(endpoints)

    # Opening the picker auto-seeds ONE report vulnerability, not 50.
    seeded = await client.get(f"/versions/{version.id}/vgs-report-draft/vulnerabilities", headers=headers)
    assert seeded.status_code == 200
    body = seeded.json()
    assert len(body) == 1
    assert body[0]["title"] == "Missing Content-Security-Policy"
    assert body[0]["source_finding_id"] in [str(f.id) for f in instances]
    # The full endpoint list is preserved in the description, just not as
    # separate report-vulnerability rows.
    assert "Affected endpoints (50)" in body[0]["description"]

    # The picker now flags it as already added.
    available_again = await client.get(
        f"/versions/{version.id}/vgs-report-draft/available-findings", headers=headers
    )
    assert available_again.json()[0]["already_added"] is True


async def test_add_from_finding_rejects_a_finding_from_another_version(vgs_client):
    client, db_adapter = vgs_client
    _org, _user, version, headers = await _create_org_admin(db_adapter)
    _org2, _user2, other_version, _headers2 = await _create_org_admin(db_adapter, org_name="OrgB")

    finding = await _make_finding(db_adapter, other_version.id)

    added = await client.post(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities/from-finding/{finding.id}",
        headers=headers,
    )
    assert added.status_code == 404


async def test_vulnerability_picker_auto_seeds_open_findings_on_first_load(vgs_client):
    """Regression coverage for the user-reported gap: opening the picker
    for a version with real scan findings should pre-populate 'Selected
    for this report' automatically, without a manual Add click per
    finding. Also proves the seed runs exactly once — deleting the
    auto-added vulnerability and reloading must not resurrect it."""
    client, db_adapter = vgs_client
    _org, _user, version, headers = await _create_org_admin(db_adapter)

    open_finding = await _make_finding(db_adapter, version.id, with_screenshot=True)
    await _make_finding(db_adapter, version.id, retest_status="fixed")

    listed = await client.get(f"/versions/{version.id}/vgs-report-draft/vulnerabilities", headers=headers)
    assert listed.status_code == 200
    body = listed.json()
    assert len(body) == 1
    assert body[0]["source_finding_id"] == str(open_finding.id)
    assert body[0]["title"] == "Missing HSTS"

    # The auto-added evidence screenshot came along too.
    steps = await client.get(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities/{body[0]['id']}/evidence-steps",
        headers=headers,
    )
    assert steps.json()[0]["screenshot_object_keys"] == ["vgs-evidence/fixture-key.png"]

    deleted = await client.delete(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities/{body[0]['id']}", headers=headers
    )
    assert deleted.status_code == 204

    listed_again = await client.get(f"/versions/{version.id}/vgs-report-draft/vulnerabilities", headers=headers)
    assert listed_again.json() == []


async def test_auto_seed_reruns_on_every_load_without_resurrecting_deletions(vgs_client):
    """A later scan's newly-confirmed vulnerability class must appear in
    'Selected for this report' automatically on the next picker load,
    even though findings_auto_seeded was already set True by an earlier
    scan — while a vulnerability the analyst deliberately deleted (and
    whose underlying Finding was never rescanned) must stay deleted.
    This is the fix for the real gap found live: a scan run's newly
    confirmed check sat invisible in 'Selected for this report' until an
    analyst noticed it in the 'From scans' list and added it by hand."""
    client, db_adapter = vgs_client
    _org, _user, version, headers = await _create_org_admin(db_adapter)

    first_scan_finding = await _make_finding(db_adapter, version.id)

    # First load seeds the one finding from the first scan.
    listed = await client.get(f"/versions/{version.id}/vgs-report-draft/vulnerabilities", headers=headers)
    assert listed.status_code == 200
    body = listed.json()
    assert len(body) == 1
    assert body[0]["source_finding_id"] == str(first_scan_finding.id)

    # The analyst deliberately removes it.
    deleted = await client.delete(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities/{body[0]['id']}", headers=headers
    )
    assert deleted.status_code == 204

    # Reloading without any new scan must not resurrect it (the
    # already-covered regression from
    # test_vulnerability_picker_auto_seeds_open_findings_on_first_load).
    listed_again = await client.get(f"/versions/{version.id}/vgs-report-draft/vulnerabilities", headers=headers)
    assert listed_again.json() == []

    # A later scan confirms a brand new, never-before-seen check.
    second_scan_findings = await _make_findings_sharing_check_id(
        db_adapter, version.id, ["http://site.test/admin"]
    )

    # Reloading the picker now must auto-add the new check without a
    # manual Add — the deleted HSTS finding still must not come back.
    listed_after_new_scan = await client.get(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities", headers=headers
    )
    assert listed_after_new_scan.status_code == 200
    after_body = listed_after_new_scan.json()
    assert len(after_body) == 1
    assert after_body[0]["source_finding_id"] == str(second_scan_findings[0].id)
    assert after_body[0]["title"] == "Missing Content-Security-Policy"


async def test_delete_report_vulnerability_with_evidence_steps_succeeds(vgs_client):
    """Regression test: vgs_evidence_steps.report_vulnerability_id had no
    ON DELETE CASCADE, so deleting a selected vulnerability that had any
    evidence step attached (e.g. any finding-derived one, or one with a
    manually uploaded screenshot) used to fail with a
    ForeignKeyViolation — exactly the 'delete doesn't work in Selected
    for this report' bug the user reported."""
    client, db_adapter = vgs_client
    _org, _user, version, headers = await _create_org_admin(db_adapter)

    ad_hoc = await client.post(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities",
        json={"title": "XSS", "severity": "High"},
        headers=headers,
    )
    vuln_id = ad_hoc.json()["id"]

    files = {"screenshot": ("proof.png", _real_png_bytes(), "image/png")}
    step = await client.post(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities/{vuln_id}/evidence-steps",
        data={"comment": "step"},
        files=files,
        headers=headers,
    )
    assert step.status_code == 201

    deleted = await client.delete(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities/{vuln_id}", headers=headers
    )
    assert deleted.status_code == 204, deleted.text

    listed = await client.get(f"/versions/{version.id}/vgs-report-draft/vulnerabilities", headers=headers)
    assert listed.json() == []


async def test_add_screenshot_to_existing_evidence_step(vgs_client):
    """The original add_evidence_step endpoint only accepted a screenshot
    at step-creation time. This covers the new endpoint that lets an
    analyst attach a screenshot to a step at any later point, and that it
    appends rather than replaces when called more than once."""
    client, db_adapter = vgs_client
    _org, _user, version, headers = await _create_org_admin(db_adapter)

    ad_hoc = await client.post(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities",
        json={"title": "XSS", "severity": "High"},
        headers=headers,
    )
    vuln_id = ad_hoc.json()["id"]

    step = await client.post(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities/{vuln_id}/evidence-steps",
        data={"comment": "step"},
        headers=headers,
    )
    step_id = step.json()["id"]
    assert step.json()["screenshot_object_keys"] == []

    files1 = {"screenshot": ("proof1.png", _real_png_bytes(), "image/png")}
    added1 = await client.post(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities/{vuln_id}/evidence-steps/{step_id}/screenshots",
        files=files1,
        headers=headers,
    )
    assert added1.status_code == 201, added1.text
    assert len(added1.json()["screenshot_object_keys"]) == 1

    files2 = {"screenshot": ("proof2.png", _real_png_bytes(), "image/png")}
    added2 = await client.post(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities/{vuln_id}/evidence-steps/{step_id}/screenshots",
        files=files2,
        headers=headers,
    )
    assert added2.status_code == 201
    assert len(added2.json()["screenshot_object_keys"]) == 2

    listed = await client.get(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities/{vuln_id}/evidence-steps", headers=headers
    )
    assert len(listed.json()) == 1
    assert len(listed.json()[0]["screenshot_object_keys"]) == 2


async def test_load_from_portswigger_upserts_by_title(vgs_client, monkeypatch):
    client, db_adapter = vgs_client
    _org, _user, version, headers = await _create_org_admin(db_adapter)

    async def _fake_fetch_topics(*args, **kwargs):
        return [
            PortswigerTopic(title="SQL Injection", description="desc1", url="https://portswigger.net/x1"),
            PortswigerTopic(title="XSS", description="desc2", url="https://portswigger.net/x2"),
        ]

    monkeypatch.setattr(vgs_routes, "fetch_topics", _fake_fetch_topics)

    first = await client.post("/vgs-vulnerability-library/load-from-portswigger", headers=headers)
    assert first.status_code == 200, first.text
    assert first.json() == {"inserted": 2, "updated": 0, "skipped": 0}

    library = await client.get("/vgs-vulnerability-library", headers=headers)
    titles = {e["title"] for e in library.json()}
    assert titles == {"SQL Injection", "XSS"}
    entry = next(e for e in library.json() if e["title"] == "SQL Injection")
    assert entry["severity"] == "Medium"
    assert entry["reference"] == "https://portswigger.net/x1"

    # Running again with identical data is fully idempotent.
    second = await client.post("/vgs-vulnerability-library/load-from-portswigger", headers=headers)
    assert second.json() == {"inserted": 0, "updated": 0, "skipped": 2}

    # A changed description on a re-run updates the existing entry in place
    # rather than creating a duplicate.
    async def _fake_fetch_topics_updated(*args, **kwargs):
        return [
            PortswigerTopic(title="SQL Injection", description="new desc", url="https://portswigger.net/x1"),
        ]

    monkeypatch.setattr(vgs_routes, "fetch_topics", _fake_fetch_topics_updated)
    third = await client.post("/vgs-vulnerability-library/load-from-portswigger", headers=headers)
    assert third.json() == {"inserted": 0, "updated": 1, "skipped": 0}
    library_after = await client.get("/vgs-vulnerability-library", headers=headers)
    assert len(library_after.json()) == 2


async def test_load_from_portswigger_returns_502_on_total_failure(vgs_client, monkeypatch):
    client, db_adapter = vgs_client
    _org, _user, version, headers = await _create_org_admin(db_adapter)

    async def _fake_fetch_topics(*args, **kwargs):
        raise PortswigerFetchError("boom")

    monkeypatch.setattr(vgs_routes, "fetch_topics", _fake_fetch_topics)
    resp = await client.post("/vgs-vulnerability-library/load-from-portswigger", headers=headers)
    assert resp.status_code == 502
