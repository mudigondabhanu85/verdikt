import re
import uuid
from urllib.parse import parse_qs, urlsplit

import httpx
from sqlalchemy import select

from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
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

    if parsed.path == "/account":
        # A real, live-found bug: this endpoint's SQLi is only reachable
        # at all behind a login-gated cookie, matching a real target
        # (DVWA) whose vulnerable pages require an authenticated session
        # — every probe was silently unauthenticated before this fix, so
        # this class of finding was structurally unreachable regardless
        # of how vulnerable it actually was.
        if request.headers.get("cookie") != "PHPSESSID=valid-session":
            return httpx.Response(302, headers={"location": "/login"})
        value = query.get("id", [""])[0]
        if "'" in value:
            return httpx.Response(200, text="Error: You have an error in your SQL syntax near '''")
        return httpx.Response(200, text="Account details page")

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

    if parsed.path == "/legacy_item":
        # Only trips on a numeric-context payload with no quote at all
        # (e.g. "1 OR 1=1--") — the fixed battery's sqli-error payload
        # is a bare "'", which this endpoint's parser strips/ignores
        # silently, so only an AI-suggested, context-appropriate
        # payload can ever surface this signal.
        value = query.get("item_id", [""])[0]
        if "OR 1=1" in value.upper():
            return httpx.Response(200, text="Error: You have an error in your SQL syntax near '1=1--'")
        return httpx.Response(200, text="Item details page")

    if parsed.path == "/search-reviews":
        # Models a real, live-found gap: a naive `LIKE '%{q}%'`-wrapped
        # search parameter. A raw "'" genuinely breaks the query (a real
        # SQLite OperationalError, confirmed live) but the app's generic
        # exception handler returns a bland message with no recognizable
        # SQL wording — only an unhandled-5xx-vs-clean-baseline signal
        # can catch it, not a text-pattern match. Separately, the fixed
        # bare true/false payload pair (`...OR '1'='1`/`...OR '1'='2`,
        # with nothing neutralizing the template's trailing `%'`) always
        # produces the *same* no-match result regardless of which one is
        # sent — only a comment-terminated pair (`...OR '1'='1' -- `)
        # that comments out the trailing `%'` actually distinguishes
        # true from false.
        value = query.get("q", [""])[0]
        if value == "'":
            return httpx.Response(500, text="Internal Server Error")
        if value.endswith("-- ") and "OR '1'='1'" in value:
            return httpx.Response(200, text="Reviews: " + "x" * 500)
        return httpx.Response(200, text="Reviews: none matching")

    if parsed.path == "/browse-items":
        # Isolates the boolean-only fix from the error-based one above:
        # a raw "'" here produces an ordinary 200 (no error signal at
        # all, unlike /search-reviews), so this path can only ever be
        # caught by the comment-terminated boolean payload pair.
        value = query.get("q", [""])[0]
        if value.endswith("-- ") and "OR '1'='1'" in value:
            return httpx.Response(200, text="Items: " + "x" * 500)
        return httpx.Response(200, text="Items: none matching")

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


async def test_ai_suggested_payload_catches_what_the_fixed_battery_misses(db_adapter):
    """/legacy_item only trips its SQL-error signal on a numeric-context
    payload with no quote at all — the fixed battery's bare "'" never
    finds it. An AI-suggested payload tailored to the parameter's shape
    (informed by its name/sample value, see
    InjectionAgent._generate_ai_payloads) does.
    """
    async with session_scope(db_adapter) as session:
        def respond(msgs):
            if any("Suggest additional SQL-injection-error payload" in m.content for m in msgs):
                return '{"payloads": ["1 OR 1=1--"]}'
            return '{"vulnerable": true, "confidence": "high", "reasoning": "looks vulnerable"}'

        provider = ScriptedAIProviderAdapter(respond_fn=respond)
        agent, client, _scan_run = await _make_agent(session, provider)

        parameters = [
            DiscoveredParameter(
                url="http://site.test/legacy_item?item_id=42", method="GET", name="item_id"
            )
        ]
        findings = await agent.run(
            parameters, [], tech_stack_fingerprint={"backend_languages": ["PHP"]}
        )

        check_ids = {f.check_id for f in findings}
        assert "sqli-error" in check_ids
        finding = next(f for f in findings if f.affected_endpoints == ["http://site.test/legacy_item?item_id=42"])
        assert "AI-suggested" in finding.technical_description

        await client.aclose()


async def test_sqli_error_detected_via_status_code_when_message_is_generic(db_adapter):
    """Regression test for a real gap found live: a raw "'" genuinely
    breaks a naively-built SQL query (confirmed against a real SQLite
    OperationalError), but a framework's generic unhandled-exception
    handler returns a bland "Internal Server Error" body with no
    recognizable SQL wording — the text-pattern check alone never fires.
    The clean-baseline-to-unhandled-5xx signal must catch this too."""
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "looks vulnerable"}'
        )
        agent, client, _scan_run = await _make_agent(session, provider)

        parameters = [
            DiscoveredParameter(
                url="http://site.test/search-reviews?q=example", method="GET", name="q"
            )
        ]
        findings = await agent.run(parameters, [])

        check_ids = {f.check_id for f in findings}
        assert "sqli-error" in check_ids

        await client.aclose()


async def test_sqli_boolean_detected_behind_a_like_wrapped_search_parameter(db_adapter):
    """Regression test for a real gap found live: a parameter wrapped in
    a LIKE search (`LIKE '%{value}%'`, one of the most common shapes for
    a "search" feature) leaves trailing template text after the
    injection point that the original bare true/false payload pair
    never neutralizes — both payloads produce the identical no-match
    result, so the length-difference check never distinguishes them,
    missing a real, exploitable boolean-blind SQLi outright."""
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "looks vulnerable"}'
        )
        agent, client, _scan_run = await _make_agent(session, provider)

        parameters = [
            DiscoveredParameter(
                url="http://site.test/browse-items?q=example", method="GET", name="q"
            )
        ]
        findings = await agent.run(parameters, [])

        check_ids = {f.check_id for f in findings}
        assert "sqli-boolean" in check_ids

        await client.aclose()


async def test_second_order_sqli_detected_on_a_different_page_than_the_form(db_adapter):
    """Regression test for a real, live-found gap (§14, DVWA SQL
    Injection at "High" difficulty): a form that persists a value
    (into a session variable, here) without querying anything itself,
    where a COMPLETELY DIFFERENT page's query is what's actually
    injectable. Every other SQLi probe only ever compares the immediate
    response to the same request that carried the payload, so a
    same-page-only check would see this form as identical no matter what
    was submitted and never report it. Confirms _probe_sqli_second_order
    checks the containing directory's index instead and catches it.
    """
    server_state = {"id": ""}

    def handler(request: httpx.Request) -> httpx.Response:
        parsed = urlsplit(str(request.url))
        if parsed.path == "/vulnerable/set-id" and request.method == "POST":
            body = parse_qs(request.content.decode())
            server_state["id"] = body.get("id", [""])[0]
            return httpx.Response(200, text="Session ID set")
        if parsed.path == "/vulnerable/":
            # Simulates `SELECT ... WHERE user_id = '{id}'` with no
            # escaping at all — a true-condition payload matches every
            # row (long output), a false-condition one matches none.
            value = server_state["id"]
            if "OR '1'='1" in value:
                return httpx.Response(200, text="<html>" + "<p>User row</p>" * 40 + "</html>")
            return httpx.Response(200, text="<html>No results</html>")
        return httpx.Response(404)

    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(handler),
        )
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "looks vulnerable"}'
        )
        guard = BudgetGuard(scan_run, session, provider)
        agent = InjectionAgent(
            client, scan_run_id=scan_run.id, agent_job_id=uuid.uuid4(),
            db_session=session, budget_guard=guard, ai_model="fake-model",
        )

        forms = [
            FormInfo(
                action_url="http://site.test/vulnerable/set-id",
                method="POST",
                fields=[FormField(name="id", type="text")],
            )
        ]
        findings = await agent.run([], forms)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.check_id == "sqli-boolean"
        assert "http://site.test/vulnerable/" in finding.affected_endpoints
        assert "http://site.test/vulnerable/set-id" in finding.affected_endpoints

        await client.aclose()


async def test_no_parameters_never_calls_the_llm_for_payload_suggestions(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses('{"payloads": ["should never be seen"]}')
        agent, client, _scan_run = await _make_agent(session, provider)

        findings = await agent.run([], [])

        assert findings == []
        assert provider.calls == []

        await client.aclose()


async def test_login_gated_sqli_is_unreachable_without_a_session(db_adapter):
    """The real bug this fix closes: without a session, every probe hit
    the target completely unauthenticated. Proves the pre-fix behavior
    is now opt-in-visible rather than silent — no session passed means
    a login-gated vulnerable endpoint stays genuinely unreachable,
    matching a real unauthenticated attacker's own view of the app."""
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "looks vulnerable"}'
        )
        agent, client, _scan_run = await _make_agent(session, provider)

        parameters = [DiscoveredParameter(url="http://site.test/account?id=1", method="GET", name="id")]
        findings = await agent.run(parameters, [])

        assert findings == []
        await client.aclose()


async def test_login_gated_sqli_is_confirmed_with_a_session(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "looks vulnerable"}'
        )
        agent, client, _scan_run = await _make_agent(session, provider)

        parameters = [DiscoveredParameter(url="http://site.test/account?id=1", method="GET", name="id")]
        auth_session = AuthenticatedSession(
            credential_set_id=uuid.uuid4(), cookies={"PHPSESSID": "valid-session"}
        )
        sessions = {auth_session.credential_set_id: auth_session}
        findings = await agent.run(parameters, [], sessions)

        assert len(findings) == 1
        assert findings[0].check_id == "sqli-error"
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
        # The 1 call left is the AI-payload-suggestion call every run()
        # makes first — probe triage itself was never reached.
        assert len(provider.calls) == 1

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
        # The AI-payload-suggestion call still fires once per run() with
        # any parameters at all — it's the probe battery itself that
        # never gets an LLM call for this target (no deterministic
        # signal on /safe to triage).
        assert len(provider.calls) == 1

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
        # +1 for the AI-payload-suggestion call every run() makes first.
        # Beyond that, only the sqli-error probe should have triggered an
        # LLM call (the boolean probe produces no length divergence
        # here, ssti/cmd-i produce no marker match on this endpoint).
        assert len(provider.calls) == 2

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
        def respond(msgs):
            # The AI-payload-suggestion call (one per run(), before any
            # triage) shares this provider too — give it an empty
            # "payloads" response so it doesn't consume/advance the
            # triage/validation sequence below.
            if any("Suggest additional SQL-injection-error payload" in m.content for m in msgs):
                return '{"payloads": []}'
            return next(responses)

        provider = ScriptedAIProviderAdapter(respond_fn=respond)
        agent, client, _scan_run = await _make_agent(session, provider)

        parameters = [DiscoveredParameter(url="http://site.test/product?id=1", method="GET", name="id")]
        findings = await agent.run(parameters, [])

        assert findings == []
        # +1 for the AI-payload-suggestion call every run() now makes
        # first (see injection.py's InjectionAgent docstring).
        assert len(provider.calls) == 3

        await client.aclose()
