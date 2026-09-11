import asyncio
import uuid
from decimal import Decimal

from sqlalchemy import select

from app.agents.business_logic_planner import BusinessLogicPlannerAgent
from app.agents.recon import FormField, FormInfo
from app.ai.budget import BudgetGuard
from app.models.business_rule import BusinessRule
from app.models.scan import ScanRun
from tests.conftest import session_scope
from tests.fakes import ScriptedAIProviderAdapter


async def _make_agent(session, response_json: str):
    scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
    session.add(scan_run)
    await session.commit()
    await session.refresh(scan_run)

    provider = ScriptedAIProviderAdapter.from_responses(response_json)
    lock = asyncio.Lock()
    guard = BudgetGuard(scan_run, session, provider, lock=lock)
    agent = BusinessLogicPlannerAgent(
        version_id=scan_run.version_id,
        db_session=session,
        budget_guard=guard,
        ai_model="fake-model",
        session_lock=lock,
    )
    return agent, scan_run


async def test_valid_hypotheses_are_persisted_as_ai_generated_business_rules(db_adapter):
    response = """```json
{"hypotheses": [
  {"rule_type": "resource_isolation", "title": "User can view another user's order",
   "config": {"url": "https://site.test/orders/1", "method": "GET"}}
]}
```"""
    async with session_scope(db_adapter) as session:
        agent, scan_run = await _make_agent(session, response)

        rules = await agent.run(
            discovered_endpoints=["https://site.test/orders/1"],
            discovered_forms=[],
            discovered_parameters=[],
            tech_stack_fingerprint={"backend_languages": ["PHP"]},
        )

        assert len(rules) == 1
        assert rules[0].source == "ai_generated"
        assert rules[0].rule_type == "resource_isolation"
        assert rules[0].version_id == scan_run.version_id

        persisted = (
            await session.execute(select(BusinessRule).where(BusinessRule.version_id == scan_run.version_id))
        ).scalars().all()
        assert len(persisted) == 1
        assert persisted[0].source == "ai_generated"


async def test_malformed_hypothesis_is_discarded_not_repaired(db_adapter):
    response = """{"hypotheses": [
      {"rule_type": "resource_isolation", "title": "missing url", "config": {"method": "GET"}},
      {"rule_type": "not_a_real_type", "title": "bogus", "config": {}}
    ]}"""
    async with session_scope(db_adapter) as session:
        agent, _scan_run = await _make_agent(session, response)

        rules = await agent.run(
            discovered_endpoints=["https://site.test/"],
            discovered_forms=[],
            discovered_parameters=[],
            tech_stack_fingerprint=None,
        )

        assert rules == []


async def test_empty_site_map_never_calls_the_llm(db_adapter):
    async with session_scope(db_adapter) as session:
        agent, _scan_run = await _make_agent(session, '{"hypotheses": []}')

        rules = await agent.run(
            discovered_endpoints=[], discovered_forms=[], discovered_parameters=[], tech_stack_fingerprint=None
        )

        assert rules == []
        # Nothing charged — the pre-filter returned before any guarded_complete call.
        assert agent._budget_guard.spent == Decimal(0)


async def test_unparseable_llm_response_yields_no_rules(db_adapter):
    async with session_scope(db_adapter) as session:
        agent, _scan_run = await _make_agent(session, "not json at all")

        rules = await agent.run(
            discovered_endpoints=["https://site.test/"],
            discovered_forms=[FormInfo(action_url="https://site.test/login", method="POST", fields=[FormField(name="password", type="password")])],
            discovered_parameters=[],
            tech_stack_fingerprint=None,
        )

        assert rules == []
