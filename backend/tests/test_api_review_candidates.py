import uuid

from app.models.review_candidate import ReviewCandidate
from app.models.scan import AgentJob, ScanRun
from tests.conftest import create_project_and_version, register_org_admin, session_scope


async def _seed_review_candidate(db_adapter, version_id: str, *, check_type: str = "xss-reflected") -> str:
    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.UUID(version_id), status="completed", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        job = AgentJob(scan_run_id=scan_run.id, agent_type="xss", status="completed")
        session.add(job)
        await session.commit()
        await session.refresh(job)

        candidate = ReviewCandidate(
            scan_run_id=scan_run.id,
            agent_job_id=job.id,
            check_type=check_type,
            title="Possible Reflected Cross-Site Scripting (XSS)",
            severity_guess="High",
            affected_endpoint="http://site.test/search?q=x",
            request_raw="GET /search?q=%3Cvxss%3E HTTP/1.1",
            response_raw="HTTP/1.1 200 OK\n\n<p>Results for: <vxss>alert(1)</vxss></p>",
            llm_reasoning="Unescaped reflection directly in HTML body.",
            llm_confidence="high",
            status="pending",
        )
        session.add(candidate)
        await session.commit()
        await session.refresh(candidate)
        return str(scan_run.id), str(candidate.id)


async def test_list_review_candidates(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    scan_run_id, _candidate_id = await _seed_review_candidate(db_adapter, version_id)

    resp = await client.get(f"/scan-runs/{scan_run_id}/review-candidates", headers=admin["headers"])
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["check_type"] == "xss-reflected"
    assert body[0]["status"] == "pending"


async def test_promote_review_candidate_creates_analyst_confirmed_finding(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    _scan_run_id, candidate_id = await _seed_review_candidate(db_adapter, version_id)

    resp = await client.post(f"/review-candidates/{candidate_id}/promote", headers=admin["headers"])
    assert resp.status_code == 201
    finding = resp.json()
    assert finding["confirmation_status"] == "analyst_confirmed"
    assert finding["check_id"] == "xss-reflected"
    assert finding["severity"] == "High"
    assert finding["affected_endpoints"] == ["http://site.test/search?q=x"]
    assert "Unescaped reflection" in finding["technical_description"]

    # Promoting twice is rejected — already promoted.
    again = await client.post(f"/review-candidates/{candidate_id}/promote", headers=admin["headers"])
    assert again.status_code == 400


async def test_dismiss_review_candidate(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    scan_run_id, candidate_id = await _seed_review_candidate(db_adapter, version_id)

    resp = await client.post(f"/review-candidates/{candidate_id}/dismiss", headers=admin["headers"])
    assert resp.status_code == 200
    assert resp.json()["status"] == "dismissed"

    listed = await client.get(f"/scan-runs/{scan_run_id}/review-candidates", headers=admin["headers"])
    assert listed.json()[0]["status"] == "dismissed"

    again = await client.post(f"/review-candidates/{candidate_id}/dismiss", headers=admin["headers"])
    assert again.status_code == 400


async def test_review_candidates_scoped_to_org(client, db_adapter):
    org_a = await register_org_admin(client, org_name="Org A", email="a@org-a.io")
    org_b = await register_org_admin(client, org_name="Org B", email="b@org-b.io")
    _, version_id = await create_project_and_version(client, org_a["headers"])
    scan_run_id, candidate_id = await _seed_review_candidate(db_adapter, version_id)

    cross_org = await client.get(f"/scan-runs/{scan_run_id}/review-candidates", headers=org_b["headers"])
    assert cross_org.status_code == 404

    cross_org_promote = await client.post(f"/review-candidates/{candidate_id}/promote", headers=org_b["headers"])
    assert cross_org_promote.status_code == 404
