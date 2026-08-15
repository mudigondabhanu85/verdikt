import uuid

import httpx
from sqlalchemy import select

from app.agents.header_config import HeaderConfigAgent
from app.agents.http_client import ScopedHttpClient
from app.models.finding import Evidence, Finding
from app.models.project import ScopeEntry
from tests.conftest import session_scope

_flaky_call_count = {"count": 0}

HARDENED_HEADERS = {
    "content-type": "text/html",
    "strict-transport-security": "max-age=1",
    "content-security-policy": "frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "geolocation=()",
}


def _handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url == "https://site.test/vuln":
        return httpx.Response(
            200,
            headers={"content-type": "text/html", "set-cookie": "sid=abc123; Path=/"},
            text="<html><body>vulnerable page</body></html>",
        )
    if url == "https://site.test/flaky":
        _flaky_call_count["count"] += 1
        if _flaky_call_count["count"] == 1:
            return httpx.Response(200, headers={"content-type": "text/html"}, text="<html></html>")
        return httpx.Response(200, headers=HARDENED_HEADERS, text="<html></html>")
    return httpx.Response(404, text="not found")


async def test_confirmed_findings_are_persisted_with_evidence(db_adapter):
    async with session_scope(db_adapter) as session:
        scope_entries = [ScopeEntry(host="site.test", port=443, in_scope=True)]
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=scope_entries,
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )
        scan_run_id = uuid.uuid4()
        agent_job_id = uuid.uuid4()
        agent = HeaderConfigAgent(
            client, scan_run_id=scan_run_id, agent_job_id=agent_job_id, db_session=session
        )

        findings = await agent.run(["https://site.test/vuln"])

        check_ids = {f.check_id for f in findings}
        assert "missing-hsts" in check_ids
        assert "missing-csp" in check_ids
        assert "cookie-missing-secure" in check_ids
        assert "cookie-missing-httponly" in check_ids
        assert "cookie-missing-samesite" in check_ids

        for f in findings:
            assert f.confirmation_status == "ai_confirmed"
            assert f.scan_run_id == scan_run_id
            assert f.agent_job_id == agent_job_id
            assert f.affected_endpoints == ["https://site.test/vuln"]
            assert f.plain_language_summary
            assert f.technical_description
            assert f.remediation
            assert len(f.steps_to_reproduce) >= 1

        result = await session.execute(select(Evidence))
        evidences = result.scalars().all()
        assert len(evidences) == len(findings)
        for e in evidences:
            assert "GET" in e.request_raw
            assert "HTTP/1.1 200" in e.response_raw

        await client.aclose()


async def test_non_reproducing_hit_is_discarded_not_persisted(db_adapter):
    async with session_scope(db_adapter) as session:
        scope_entries = [ScopeEntry(host="site.test", port=443, in_scope=True)]
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=scope_entries,
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )
        agent = HeaderConfigAgent(
            client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
        )

        findings = await agent.run(["https://site.test/flaky"])
        assert findings == []

        result = await session.execute(select(Finding))
        assert result.scalars().all() == []

        await client.aclose()
