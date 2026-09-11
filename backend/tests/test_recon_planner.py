import uuid

import httpx

from app.agents.http_client import ScopedHttpClient
from app.agents.recon_planner import ReconPlannerAgent
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
