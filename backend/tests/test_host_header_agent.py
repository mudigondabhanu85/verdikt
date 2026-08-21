import uuid

import httpx

from app.agents.host_header import HostHeaderAgent
from app.agents.http_client import ScopedHttpClient
from app.models.project import ScopeEntry
from tests.conftest import session_scope


def _vulnerable_handler(request: httpx.Request) -> httpx.Response:
    host = request.headers.get("host", "")
    if str(request.url.path) == "/reset-password":
        return httpx.Response(
            200, text=f"Click here to reset: http://{host}/reset?token=abc123"
        )
    return httpx.Response(200, text="ok")


def _safe_handler(request: httpx.Request) -> httpx.Response:
    if str(request.url.path) == "/reset-password":
        # Uses a fixed, server-configured hostname regardless of what
        # Host header the client sent.
        return httpx.Response(200, text="Click here to reset: http://app.example.com/reset?token=abc123")
    return httpx.Response(200, text="ok")


async def _run_agent(db_adapter, handler, endpoints):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(handler),
        )
        agent = HostHeaderAgent(
            client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
        )
        findings = await agent.run(endpoints)
        await client.aclose()
        return findings


async def test_host_header_injection_is_flagged_when_reflected(db_adapter):
    findings = await _run_agent(
        db_adapter, _vulnerable_handler, ["http://site.test/reset-password"]
    )
    check_ids = {f.check_id for f in findings}
    assert "host-header-injection" in check_ids
    finding = next(f for f in findings if f.check_id == "host-header-injection")
    assert finding.severity == "Medium"
    assert finding.cwe_id == "CWE-346"


async def test_fixed_hostname_is_not_flagged(db_adapter):
    findings = await _run_agent(db_adapter, _safe_handler, ["http://site.test/reset-password"])
    check_ids = {f.check_id for f in findings}
    assert "host-header-injection" not in check_ids


async def test_only_one_check_per_distinct_host(db_adapter):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return _vulnerable_handler(request)

    endpoints = [
        "http://site.test/reset-password",
        "http://site.test/other-page",
        "http://site.test/another-page",
    ]
    findings = await _run_agent(db_adapter, handler, endpoints)

    # One finding for the host overall, and at most 2 requests (probe +
    # re-execution) against it — not one pair per discovered endpoint.
    assert len({f.affected_endpoints[0] for f in findings}) <= 1
    assert calls["n"] == 2
