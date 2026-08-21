import uuid

import httpx

from app.agents.cors import CorsAgent
from app.agents.http_client import ScopedHttpClient
from app.models.project import ScopeEntry
from tests.conftest import session_scope


def _reflected_with_credentials_handler(request: httpx.Request) -> httpx.Response:
    origin = request.headers.get("origin", "")
    return httpx.Response(
        200,
        headers={
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
        },
        text="ok",
    )


def _wildcard_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, headers={"Access-Control-Allow-Origin": "*"}, text="ok")


def _allowlisted_handler(request: httpx.Request) -> httpx.Response:
    origin = request.headers.get("origin", "")
    if origin == "https://trusted-partner.example":
        return httpx.Response(200, headers={"Access-Control-Allow-Origin": origin}, text="ok")
    return httpx.Response(200, text="ok")  # no CORS headers for untrusted origins


async def _run_agent(db_adapter, handler, endpoints):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(handler),
        )
        agent = CorsAgent(
            client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
        )
        findings = await agent.run(endpoints)
        await client.aclose()
        return findings


async def test_reflected_origin_with_credentials_is_flagged_critical(db_adapter):
    findings = await _run_agent(
        db_adapter, _reflected_with_credentials_handler, ["http://site.test/api/data"]
    )
    check_ids = {f.check_id for f in findings}
    assert "cors-reflected-origin-with-credentials" in check_ids
    finding = next(f for f in findings if f.check_id == "cors-reflected-origin-with-credentials")
    assert finding.severity == "Critical"


async def test_wildcard_origin_is_flagged_low(db_adapter):
    findings = await _run_agent(db_adapter, _wildcard_handler, ["http://site.test/api/data"])
    check_ids = {f.check_id for f in findings}
    assert "cors-wildcard-origin" in check_ids
    finding = next(f for f in findings if f.check_id == "cors-wildcard-origin")
    assert finding.severity == "Low"


async def test_strict_allowlist_is_not_flagged(db_adapter):
    findings = await _run_agent(db_adapter, _allowlisted_handler, ["http://site.test/api/data"])
    assert findings == []
