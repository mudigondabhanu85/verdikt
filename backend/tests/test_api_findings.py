import uuid

from app.models.finding import Finding
from app.models.scan import AgentJob, ScanRun
from tests.conftest import create_project_and_version, register_org_admin, session_scope


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


async def test_org_admin_can_mark_finding_false_positive(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    finding_id = await _seed_finding(db_adapter, version_id)

    resp = await client.patch(
        f"/findings/{finding_id}", json={"retest_status": "false_positive_after_review"}, headers=admin["headers"]
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["retest_status"] == "false_positive_after_review"


async def test_org_admin_can_accept_risk_and_reopen(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    finding_id = await _seed_finding(db_adapter, version_id)

    accepted = await client.patch(
        f"/findings/{finding_id}", json={"retest_status": "risk_accepted"}, headers=admin["headers"]
    )
    assert accepted.status_code == 200
    assert accepted.json()["retest_status"] == "risk_accepted"

    reopened = await client.patch(f"/findings/{finding_id}", json={"retest_status": "open"}, headers=admin["headers"])
    assert reopened.status_code == 200
    assert reopened.json()["retest_status"] == "open"


async def test_invalid_retest_status_rejected(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    finding_id = await _seed_finding(db_adapter, version_id)

    resp = await client.patch(f"/findings/{finding_id}", json={"retest_status": "bogus"}, headers=admin["headers"])
    assert resp.status_code == 422


def test_analyst_can_update_status_but_not_delete_findings():
    # RBAC matrix check (app.auth.rbac_seed) rather than an HTTP round
    # trip — Phase 0 has no "invite teammate" flow to create a second
    # user with a real login (see create_user_with_role's own docstring:
    # it seeds a user directly into the DB with an unusable password
    # hash), so the matrix itself is the source of truth to assert
    # against here.
    from app.auth.rbac_seed import baseline_grants

    grants = {(role, resource, action) for role, resource, action in baseline_grants()}
    assert ("analyst", "finding", "update") in grants
    assert ("analyst", "finding", "delete") not in grants
    assert ("org_admin", "finding", "delete") in grants
    assert ("project_lead", "finding", "delete") in grants
    assert ("viewer", "finding", "update") not in grants


async def test_delete_finding_removes_it(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    finding_id = await _seed_finding(db_adapter, version_id)

    deleted = await client.delete(f"/findings/{finding_id}", headers=admin["headers"])
    assert deleted.status_code == 204

    async with session_scope(db_adapter) as session:
        assert await session.get(Finding, uuid.UUID(finding_id)) is None


async def test_update_status_rejects_other_orgs_finding(client, db_adapter):
    admin_a = await register_org_admin(client, org_name="Org A", email="admin-a@acme.io")
    admin_b = await register_org_admin(client, org_name="Org B", email="admin-b@acme.io")
    _, version_id = await create_project_and_version(client, admin_a["headers"])
    finding_id = await _seed_finding(db_adapter, version_id)

    resp = await client.patch(
        f"/findings/{finding_id}", json={"retest_status": "risk_accepted"}, headers=admin_b["headers"]
    )
    assert resp.status_code == 404
