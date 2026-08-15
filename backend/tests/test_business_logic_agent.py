import json
import uuid
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select

from app.agents.business_logic import BusinessLogicAgent
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.ai.budget import BudgetGuard
from app.models.business_rule import BusinessRule
from app.models.finding import Finding
from app.models.project import ScopeEntry
from app.models.scan import ScanRun
from tests.conftest import session_scope
from tests.fakes import ScriptedAIProviderAdapter


def _sessions_and_labels():
    user_id = uuid.uuid4()
    sessions = {user_id: AuthenticatedSession(credential_set_id=user_id, bearer_token="user-token")}
    labels = {user_id: "User A"}
    return sessions, labels


async def _make_agent(session, provider, handler, sessions=None, labels=None):
    scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
    session.add(scan_run)
    await session.commit()
    await session.refresh(scan_run)

    if sessions is None:
        sessions, labels = _sessions_and_labels()

    client = ScopedHttpClient(
        version_id=uuid.uuid4(),
        scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
        db_session=session,
        transport=httpx.MockTransport(handler),
    )
    guard = BudgetGuard(scan_run, session, provider)
    agent = BusinessLogicAgent(
        client,
        scan_run_id=scan_run.id,
        agent_job_id=uuid.uuid4(),
        db_session=session,
        budget_guard=guard,
        ai_model="fake-model",
        sessions=sessions,
        credential_labels=labels,
    )
    return agent, client


def _vulnerable_verdict() -> str:
    return '{"vulnerable": true, "confidence": "high", "reasoning": "matches the rule"}'


# ---------------------------------------------------------------- resource_isolation


def _handler_resource_isolation(vulnerable: bool):
    def handler(request: httpx.Request) -> httpx.Response:
        path = urlsplit(str(request.url)).path
        if not path.startswith("/rest/basket/"):
            return httpx.Response(404)
        basket_id = path.rsplit("/", 1)[-1]
        auth = request.headers.get("authorization", "")
        if "user-token" not in auth:
            return httpx.Response(401)
        if vulnerable or basket_id == "6":
            return httpx.Response(200, text=f"<html>Basket #{basket_id}: 3 items, $42.00</html>")
        return httpx.Response(403, text="forbidden")

    return handler


async def test_resource_isolation_vulnerable(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(_vulnerable_verdict())
        agent, client = await _make_agent(session, provider, _handler_resource_isolation(True))
        rule = BusinessRule(
            version_id=uuid.uuid4(),
            rule_type="resource_isolation",
            title="A user should never see another user's basket",
            config={"url": "http://site.test/rest/basket/6"},
        )

        findings = await agent.run([rule])
        assert len(findings) == 1
        assert findings[0].check_id == "business-logic-resource_isolation"
        assert "basket" in findings[0].title.lower()

        result = await session.execute(select(Finding))
        assert len(result.scalars().all()) == 1
        await client.aclose()


async def test_resource_isolation_safe(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(_vulnerable_verdict())
        agent, client = await _make_agent(session, provider, _handler_resource_isolation(False))
        rule = BusinessRule(
            version_id=uuid.uuid4(),
            rule_type="resource_isolation",
            title="A user should never see another user's basket",
            config={"url": "http://site.test/rest/basket/6"},
        )

        findings = await agent.run([rule])
        assert findings == []
        await client.aclose()


# ---------------------------------------------------------------- workflow_order


def _handler_workflow(vulnerable: bool):
    def handler(request: httpx.Request) -> httpx.Response:
        path = urlsplit(str(request.url)).path
        if path == "/checkout/complete":
            if vulnerable:
                return httpx.Response(200, text="Order completed")
            return httpx.Response(402, text="Payment required first")
        return httpx.Response(404)

    return handler


async def test_workflow_order_vulnerable(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(_vulnerable_verdict())
        agent, client = await _make_agent(session, provider, _handler_workflow(True))
        rule = BusinessRule(
            version_id=uuid.uuid4(),
            rule_type="workflow_order",
            title="Order can't complete before payment clears",
            config={
                "precondition": {"method": "POST", "url": "http://site.test/checkout/payment"},
                "guarded_action": {"method": "POST", "url": "http://site.test/checkout/complete"},
            },
        )

        findings = await agent.run([rule])
        assert len(findings) == 1
        assert findings[0].check_id == "business-logic-workflow_order"
        await client.aclose()


async def test_workflow_order_safe(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(_vulnerable_verdict())
        agent, client = await _make_agent(session, provider, _handler_workflow(False))
        rule = BusinessRule(
            version_id=uuid.uuid4(),
            rule_type="workflow_order",
            title="Order can't complete before payment clears",
            config={
                "precondition": {"method": "POST", "url": "http://site.test/checkout/payment"},
                "guarded_action": {"method": "POST", "url": "http://site.test/checkout/complete"},
            },
        )

        findings = await agent.run([rule])
        assert findings == []
        await client.aclose()


# ---------------------------------------------------------------- price_or_quantity_tampering


def _handler_price(vulnerable: bool):
    def handler(request: httpx.Request) -> httpx.Response:
        path = urlsplit(str(request.url)).path
        if path == "/api/basket-items" and request.method == "POST":
            body = json.loads(request.content.decode())
            price = float(body["price"])
            if price <= 0 and not vulnerable:
                return httpx.Response(400, text="Invalid price")
            return httpx.Response(200, text=json.dumps({"accepted_price": price}))
        return httpx.Response(404)

    return handler


async def test_price_tampering_vulnerable(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(_vulnerable_verdict())
        agent, client = await _make_agent(session, provider, _handler_price(True))
        rule = BusinessRule(
            version_id=uuid.uuid4(),
            rule_type="price_or_quantity_tampering",
            title="Basket item price should not be client-controlled",
            config={
                "method": "POST",
                "url": "http://site.test/api/basket-items",
                "body_template": '{"productId": 1, "price": {value}}',
                "baseline_value": "9.99",
                "tamper_values": ["-1"],
            },
        )

        findings = await agent.run([rule])
        assert len(findings) == 1
        assert findings[0].check_id == "business-logic-price_or_quantity_tampering"
        await client.aclose()


async def test_price_tampering_safe(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(_vulnerable_verdict())
        agent, client = await _make_agent(session, provider, _handler_price(False))
        rule = BusinessRule(
            version_id=uuid.uuid4(),
            rule_type="price_or_quantity_tampering",
            title="Basket item price should not be client-controlled",
            config={
                "method": "POST",
                "url": "http://site.test/api/basket-items",
                "body_template": '{"productId": 1, "price": {value}}',
                "baseline_value": "9.99",
                "tamper_values": ["-1"],
            },
        )

        findings = await agent.run([rule])
        assert findings == []
        await client.aclose()


# ---------------------------------------------------------------- race_condition_limited_use


def _handler_race(max_successes: int):
    state = {"used": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = urlsplit(str(request.url)).path
        if path == "/api/redeem-coupon":
            if state["used"] < max_successes:
                state["used"] += 1
                return httpx.Response(200, text="Coupon redeemed")
            return httpx.Response(409, text="Already used")
        return httpx.Response(404)

    return handler


async def test_race_condition_vulnerable(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(_vulnerable_verdict())
        agent, client = await _make_agent(session, provider, _handler_race(max_successes=999))
        rule = BusinessRule(
            version_id=uuid.uuid4(),
            rule_type="race_condition_limited_use",
            title="A coupon code should only be redeemable once",
            config={
                "method": "POST",
                "url": "http://site.test/api/redeem-coupon",
                "concurrency": 10,
                "max_allowed_successes": 1,
            },
        )

        findings = await agent.run([rule])
        assert len(findings) == 1
        assert findings[0].check_id == "business-logic-race_condition_limited_use"
        await client.aclose()


async def test_race_condition_safe(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(_vulnerable_verdict())
        agent, client = await _make_agent(session, provider, _handler_race(max_successes=1))
        rule = BusinessRule(
            version_id=uuid.uuid4(),
            rule_type="race_condition_limited_use",
            title="A coupon code should only be redeemable once",
            config={
                "method": "POST",
                "url": "http://site.test/api/redeem-coupon",
                "concurrency": 10,
                "max_allowed_successes": 1,
            },
        )

        findings = await agent.run([rule])
        assert findings == []
        await client.aclose()


async def test_unknown_rule_type_is_skipped_not_crashed(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(_vulnerable_verdict())
        agent, client = await _make_agent(session, provider, lambda r: httpx.Response(404))
        rule = BusinessRule(
            version_id=uuid.uuid4(),
            rule_type="some_future_rule_type",
            title="not yet supported",
            config={},
        )

        findings = await agent.run([rule])
        assert findings == []
        await client.aclose()


async def test_malformed_rule_config_is_skipped_not_crashed(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(_vulnerable_verdict())
        agent, client = await _make_agent(session, provider, lambda r: httpx.Response(404))
        rule = BusinessRule(
            version_id=uuid.uuid4(),
            rule_type="resource_isolation",
            title="missing required config key",
            config={},  # missing "url"
        )

        findings = await agent.run([rule])
        assert findings == []
        await client.aclose()
