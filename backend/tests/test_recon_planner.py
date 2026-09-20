import uuid

import httpx

from app.agents.http_client import ScopedHttpClient
from app.agents.recon_planner import ReconPlannerAgent, run_planner_rounds
from app.ai.budget import BudgetGuard
from app.models.project import ScopeEntry
from app.models.scan import ScanRun
from app.models.target import Target
from tests.conftest import session_scope
from tests.fakes import ScriptedAIProviderAdapter


async def _make_agent(session, response_json: str, *, targets=None):
    scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
    session.add(scan_run)
    await session.commit()
    await session.refresh(scan_run)

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/admin/dashboard"):
            return httpx.Response(200, text="ok", request=request)
        return httpx.Response(404, text="not found", request=request)

    client = ScopedHttpClient(
        version_id=scan_run.version_id,
        scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
        db_session=session,
        transport=httpx.MockTransport(handler),
    )
    provider = ScriptedAIProviderAdapter.from_responses(response_json)
    guard = BudgetGuard(scan_run, session, provider, lock=client.session_lock)
    agent = ReconPlannerAgent(
        client,
        targets if targets is not None else [Target(host="site.test", port=80, base_url="http://site.test/")],
        budget_guard=guard,
        ai_model="fake-model",
    )
    return agent, scan_run, client


async def test_confirmed_suggestion_is_added_unconfirmed_is_dropped(db_adapter):
    response = '{"suggested_paths": ["/admin/dashboard", "/definitely-not-real"]}'
    async with session_scope(db_adapter) as session:
        agent, _scan_run, client = await _make_agent(session, response)

        confirmed = await agent.run(
            discovered_endpoints=["http://site.test/"],
            discovered_forms=[],
            tech_stack_fingerprint={"backend_languages": ["PHP"]},
        )

        assert confirmed == ["http://site.test/admin/dashboard"]
        await client.aclose()


async def test_logout_shaped_suggestion_is_never_fetched(db_adapter):
    """Real, live-found bug against DVWA: the model naturally suggests
    "/logout.php" as a plausible unlinked path for any login-based app.
    Unlike a link discovered mid-crawl (app.agents.recon._extract_links's
    own logout carve-out), an AI suggestion bypassed that filter entirely
    — _verify fetched it directly with the shared authenticated session,
    silently logging out every other concurrently-running detection
    agent for the rest of the scan. This asserts the fetch never happens
    at all (not just that the URL is later dropped from `confirmed`) —
    the handler raises if logout.php is ever requested.
    """
    response = '{"suggested_paths": ["/logout.php", "/admin/dashboard"]}'
    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        def handler(request: httpx.Request) -> httpx.Response:
            if "logout" in str(request.url):
                raise AssertionError(f"logout-shaped URL was fetched: {request.url}")
            if str(request.url).endswith("/admin/dashboard"):
                return httpx.Response(200, text="ok", request=request)
            return httpx.Response(404, text="not found", request=request)

        client = ScopedHttpClient(
            version_id=scan_run.version_id,
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(handler),
        )
        provider = ScriptedAIProviderAdapter.from_responses(response)
        guard = BudgetGuard(scan_run, session, provider, lock=client.session_lock)
        agent = ReconPlannerAgent(
            client,
            [Target(host="site.test", port=80, base_url="http://site.test/")],
            budget_guard=guard,
            ai_model="fake-model",
        )

        confirmed = await agent.run(
            discovered_endpoints=["http://site.test/"],
            discovered_forms=[],
            tech_stack_fingerprint=None,
        )

        assert confirmed == ["http://site.test/admin/dashboard"]
        await client.aclose()


async def test_already_discovered_path_is_not_resuggested(db_adapter):
    response = '{"suggested_paths": ["/admin/dashboard"]}'
    async with session_scope(db_adapter) as session:
        agent, _scan_run, client = await _make_agent(session, response)

        confirmed = await agent.run(
            discovered_endpoints=["http://site.test/", "http://site.test/admin/dashboard"],
            discovered_forms=[],
            tech_stack_fingerprint=None,
        )

        assert confirmed == []
        await client.aclose()


async def test_empty_site_map_never_calls_the_llm(db_adapter):
    async with session_scope(db_adapter) as session:
        agent, _scan_run, client = await _make_agent(session, '{"suggested_paths": []}')

        confirmed = await agent.run(
            discovered_endpoints=[], discovered_forms=[], tech_stack_fingerprint=None
        )

        assert confirmed == []
        await client.aclose()


async def test_malformed_response_yields_no_suggestions(db_adapter):
    async with session_scope(db_adapter) as session:
        agent, _scan_run, client = await _make_agent(session, "not json at all")

        confirmed = await agent.run(
            discovered_endpoints=["http://site.test/"],
            discovered_forms=[],
            tech_stack_fingerprint=None,
        )

        assert confirmed == []
        await client.aclose()


async def test_planner_rounds_crawl_from_a_confirmed_suggestion(db_adapter):
    """The actual coverage claim: a confirmed AI-suggested page isn't
    just added as a lone leaf — anything reachable *from* it (here,
    /admin/users, linked only from /admin's own page body) gets
    discovered too, because run_planner_rounds hands confirmed
    suggestions to a fresh ReconAgent as crawl seeds instead of only
    resolving them with a bare GET.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == "http://site.test/":
            return httpx.Response(200, headers={"content-type": "text/html"}, text="<html><body>Home</body></html>", request=request)
        if url == "http://site.test/admin":
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text='<html><body><a href="/admin/users">Users</a></body></html>',
                request=request,
            )
        if url == "http://site.test/admin/users":
            return httpx.Response(200, headers={"content-type": "text/html"}, text="<html><body>Users</body></html>", request=request)
        return httpx.Response(404, text="not found", request=request)

    def respond_fn(messages) -> str:
        prompt_text = " ".join(m.content for m in messages)
        if "/admin/users" in prompt_text:
            # Round 2: the site map already includes everything reachable
            # from round 1's suggestion — nothing further to propose.
            return '{"suggested_paths": []}'
        return '{"suggested_paths": ["/admin"]}'

    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        client = ScopedHttpClient(
            version_id=scan_run.version_id,
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(handler),
        )
        provider = ScriptedAIProviderAdapter(respond_fn=respond_fn)
        guard = BudgetGuard(scan_run, session, provider, lock=client.session_lock)
        targets = [Target(host="site.test", port=80, base_url="http://site.test/")]

        result = await run_planner_rounds(
            client,
            targets,
            budget_guard=guard,
            ai_model="fake-model",
            session=None,
            max_rounds=2,
            discovered_endpoints=["http://site.test/"],
            discovered_forms=[],
            discovered_parameters=[],
            discovered_responses={},
            discovered_websocket_endpoints=[],
            tech_stack_fingerprint=None,
        )
        await client.aclose()

        assert "http://site.test/admin" in result.discovered_endpoints
        # The real assertion: a page only linked *from* the AI-suggested
        # page, never suggested by the LLM itself and never linked from
        # anywhere the original crawl saw, still made it onto the map.
        assert "http://site.test/admin/users" in result.discovered_endpoints
        assert result.rounds_run == 2
        assert result.endpoints_suggested_and_confirmed == 1
        assert not result.budget_exceeded


async def test_planner_rounds_stop_early_when_nothing_confirmed(db_adapter):
    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="not found", request=request)

        client = ScopedHttpClient(
            version_id=scan_run.version_id,
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(handler),
        )
        provider = ScriptedAIProviderAdapter.from_responses('{"suggested_paths": ["/nope"]}')
        guard = BudgetGuard(scan_run, session, provider, lock=client.session_lock)
        targets = [Target(host="site.test", port=80, base_url="http://site.test/")]

        result = await run_planner_rounds(
            client,
            targets,
            budget_guard=guard,
            ai_model="fake-model",
            session=None,
            max_rounds=5,
            discovered_endpoints=["http://site.test/"],
            discovered_forms=[],
            discovered_parameters=[],
            discovered_responses={},
            discovered_websocket_endpoints=[],
            tech_stack_fingerprint=None,
        )
        await client.aclose()

        # A round that confirms nothing stops the loop immediately rather
        # than burning all 5 rounds' worth of LLM calls on a target with
        # nothing left to propose.
        assert result.rounds_run == 1
        assert result.endpoints_suggested_and_confirmed == 0
        assert result.discovered_endpoints == ["http://site.test/"]
