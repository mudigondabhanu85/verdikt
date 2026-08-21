import re
import uuid
from urllib.parse import parse_qs, urlsplit

import httpx
from sqlalchemy import select

from app.agents.http_client import ScopedHttpClient
from app.agents.injection import InjectionAgent
from app.agents.recon import DiscoveredParameter, FormField, FormInfo
from app.ai.budget import BudgetGuard
from app.models.finding import Finding
from app.models.project import ScopeEntry
from app.models.scan import ScanRun
from tests.conftest import session_scope
from tests.fakes import ScriptedAIProviderAdapter


def _handler(request: httpx.Request) -> httpx.Response:
    parsed = urlsplit(str(request.url))
    query = parse_qs(parsed.query)

    if parsed.path == "/product":
        value = query.get("id", [""])[0]
        if "'" in value:
            return httpx.Response(200, text="Error: You have an error in your SQL syntax near '''")
        # Deliberately does NOT echo the raw id value back — reflecting
        # arbitrary input would itself trip the command-injection marker
        # heuristic (a real false-positive risk the LLM triage step
        # exists to catch), which would muddy tests that want to isolate
        # the SQLi-error signal specifically.
        return httpx.Response(200, text="Product details page")

    if parsed.path == "/greet":
        value = query.get("name", [""])[0]
        if value in ("{{7*7}}", "${7*7}"):
            return httpx.Response(200, text="Hello, 49!")
        return httpx.Response(200, text=f"Hello, {value}!")

    if parsed.path == "/api/greet":
        # Same template-injection-vulnerable behavior as /greet, but as a
        # JSON API response — §10 smart scan should skip SSTI probing
        # here based on Content-Type alone, saving the probe entirely.
        # Deliberately does NOT echo arbitrary input back (same reasoning
        # as /product above) — only the exact SSTI trigger strings get a
        # distinguishable response, so no other probe type can misfire.
        value = query.get("name", [""])[0]
        if value in ("{{7*7}}", "${7*7}"):
            return httpx.Response(200, json={"greeting": "Hello, 49!"})
        return httpx.Response(200, json={"greeting": "Hello, there!"})

    if parsed.path == "/download":
        filename = query.get("file", [""])[0]
        if "etc/passwd" in filename or "etc%2fpasswd" in filename.lower():
            return httpx.Response(
                200,
                text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n",
            )
        return httpx.Response(200, text="File not found: report.pdf")

    if parsed.path == "/search-notes":
        value = query.get("q", [""])[0]
        if "return true" in value:
            return httpx.Response(200, text="Notes: " + "x" * 500)
        if "return false" in value:
            return httpx.Response(200, text="Notes: none")
        return httpx.Response(200, text="Notes: some default notes here")

    if parsed.path == "/ping" and request.method == "POST":
        body = request.content.decode()
        params = parse_qs(body)
        host = params.get("host", [""])[0]
        match = re.search(r"echo (\S+)", host)
        if match:
            return httpx.Response(200, text=f"PING {host}\n{match.group(1)}\n")
        return httpx.Response(200, text=f"PING {host}: unreachable")

    return httpx.Response(404)


async def _make_agent(session, provider):
    scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
    session.add(scan_run)
    await session.commit()
    await session.refresh(scan_run)

    client = ScopedHttpClient(
        version_id=uuid.uuid4(),
        scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
        db_session=session,
        transport=httpx.MockTransport(_handler),
    )
    guard = BudgetGuard(scan_run, session, provider)
    agent = InjectionAgent(
        client,
        scan_run_id=scan_run.id,
        agent_job_id=uuid.uuid4(),
        db_session=session,
        budget_guard=guard,
        ai_model="fake-model",
    )
    return agent, client, scan_run


async def test_injection_agent_confirms_real_vulnerabilities(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "looks vulnerable"}'
        )
        agent, client, _scan_run = await _make_agent(session, provider)

        parameters = [
            DiscoveredParameter(url="http://site.test/product?id=1", method="GET", name="id"),
            DiscoveredParameter(url="http://site.test/greet?name=x", method="GET", name="name"),
        ]
        forms = [
            FormInfo(
                action_url="http://site.test/ping",
                method="POST",
                fields=[FormField(name="host", type="text")],
            )
        ]

        findings = await agent.run(parameters, forms)

        check_ids = {f.check_id for f in findings}
        assert "sqli-error" in check_ids
        assert "ssti" in check_ids
        assert "command-injection" in check_ids
        for f in findings:
            assert f.confirmation_status == "ai_confirmed"
            assert f.severity == "Critical"

        result = await session.execute(select(Finding))
        assert len(result.scalars().all()) == len(findings)

        await client.aclose()


async def test_path_traversal_is_confirmed(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "clear /etc/passwd disclosure"}'
        )
        agent, client, _scan_run = await _make_agent(session, provider)

        parameters = [
            DiscoveredParameter(url="http://site.test/download?file=report.pdf", method="GET", name="file"),
        ]
        findings = await agent.run(parameters, [])

        check_ids = {f.check_id for f in findings}
        assert "path-traversal" in check_ids
        finding = next(f for f in findings if f.check_id == "path-traversal")
        assert finding.severity == "High"
        assert finding.confirmation_status == "ai_confirmed"

        await client.aclose()


async def test_nosql_injection_is_confirmed(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "boolean differential in $where context"}'
        )
        agent, client, _scan_run = await _make_agent(session, provider)

        parameters = [
            DiscoveredParameter(url="http://site.test/search-notes?q=x", method="GET", name="q"),
        ]
        findings = await agent.run(parameters, [])

        check_ids = {f.check_id for f in findings}
        assert "nosql-injection" in check_ids
        finding = next(f for f in findings if f.check_id == "nosql-injection")
        assert finding.severity == "High"
        assert finding.cwe_id == "CWE-943"

        await client.aclose()


async def test_ssti_probe_skipped_on_json_api_response(db_adapter):
    """§10 smart scan: /api/greet is just as template-injection-vulnerable
    as /greet (same reflected-49 behavior), but responds as
    application/json — the SSTI probe must not fire there at all, even
    though the LLM would happily confirm it if triage were ever reached.
    """
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "looks vulnerable"}'
        )
        agent, client, _scan_run = await _make_agent(session, provider)

        parameters = [
            DiscoveredParameter(url="http://site.test/api/greet?name=x", method="GET", name="name"),
        ]

        findings = await agent.run(parameters, [])

        assert findings == []
        assert provider.calls == []  # never even reached LLM triage

        await client.aclose()


async def test_injection_agent_finds_nothing_against_clean_target(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "would confirm if asked"}'
        )
        agent, client, _scan_run = await _make_agent(session, provider)

        # /safe doesn't exist in the handler at all -> always 404, never
        # matches any deterministic probe signal, so the LLM is never
        # even called for it.
        parameters = [DiscoveredParameter(url="http://site.test/safe?x=1", method="GET", name="x")]

        findings = await agent.run(parameters, [])
        assert findings == []
        assert len(provider.calls) == 0

        await client.aclose()


async def test_injection_agent_discards_when_triage_says_not_vulnerable(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": false, "confidence": "high", "reasoning": "coincidental error text"}'
        )
        agent, client, _scan_run = await _make_agent(session, provider)

        parameters = [DiscoveredParameter(url="http://site.test/product?id=1", method="GET", name="id")]
        findings = await agent.run(parameters, [])

        assert findings == []
        # Only the sqli-error probe should have triggered an LLM call (the
        # boolean probe produces no length divergence here, ssti/cmd-i
        # produce no marker match on this endpoint).
        assert len(provider.calls) == 1

        await client.aclose()


async def test_injection_agent_adversarial_validation_can_veto_triage(db_adapter):
    async with session_scope(db_adapter) as session:
        # Triage says vulnerable, validation disproves it.
        responses = iter(
            [
                '{"vulnerable": true, "confidence": "high", "reasoning": "initial triage says yes"}',
                '{"vulnerable": false, "confidence": "high", "reasoning": "actually just a generic error page"}',
            ]
        )
        provider = ScriptedAIProviderAdapter(respond_fn=lambda _msgs: next(responses))
        agent, client, _scan_run = await _make_agent(session, provider)

        parameters = [DiscoveredParameter(url="http://site.test/product?id=1", method="GET", name="id")]
        findings = await agent.run(parameters, [])

        assert findings == []
        assert len(provider.calls) == 2

        await client.aclose()
