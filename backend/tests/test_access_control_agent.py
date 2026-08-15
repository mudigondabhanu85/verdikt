import uuid
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select

from app.agents.access_control import AccessControlAgent
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.ai.budget import BudgetGuard
from app.models.finding import Finding
from app.models.project import ScopeEntry
from app.models.scan import ScanRun
from tests.conftest import session_scope
from tests.fakes import ScriptedAIProviderAdapter


def _identity_of(request: httpx.Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if "admin-token" in auth:
        return "admin"
    if "usera-token" in auth:
        return "usera"
    return None


def _handler(request: httpx.Request) -> httpx.Response:
    path = urlsplit(str(request.url)).path
    who = _identity_of(request)

    if path == "/admin/dashboard":
        # Vulnerable: identical full content regardless of who's asking.
        return httpx.Response(200, text="<html>Admin Dashboard: revenue, users, settings...</html>")

    if path == "/safe-admin/dashboard":
        if who is None:
            return httpx.Response(401, text="unauthorized")
        return httpx.Response(200, text="<html>Admin Dashboard: revenue, users, settings...</html>")

    if path.startswith("/orders/"):
        order_id = path.rsplit("/", 1)[-1]
        if who is None:
            return httpx.Response(401, text="unauthorized")
        # Vulnerable: any authenticated identity can fetch any order id.
        return httpx.Response(200, text=f"<html>Order #{order_id}: 3 items, $42.00, ships to...</html>")

    if path.startswith("/safe-orders/"):
        order_id = path.rsplit("/", 1)[-1]
        if who == "usera" and order_id == "100":
            return httpx.Response(200, text="<html>Order #100: 3 items, $42.00, ships to...</html>")
        return httpx.Response(403, text="forbidden")

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
    agent = AccessControlAgent(
        client,
        scan_run_id=scan_run.id,
        agent_job_id=uuid.uuid4(),
        db_session=session,
        budget_guard=guard,
        ai_model="fake-model",
    )
    return agent, client


def _sessions_and_labels():
    admin_id = uuid.uuid4()
    usera_id = uuid.uuid4()
    sessions = {
        admin_id: AuthenticatedSession(credential_set_id=admin_id, bearer_token="admin-token"),
        usera_id: AuthenticatedSession(credential_set_id=usera_id, bearer_token="usera-token"),
    }
    labels = {admin_id: "Admin", usera_id: "User A"}
    return sessions, labels


async def test_detects_vertical_privilege_escalation(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "unauthenticated gets full admin content"}'
        )
        agent, client = await _make_agent(session, provider)
        sessions, labels = _sessions_and_labels()

        findings = await agent.run(["http://site.test/admin/dashboard"], sessions, labels)

        assert len(findings) == 1
        assert findings[0].check_id == "access-control-vertical"
        assert findings[0].severity == "Critical"
        assert findings[0].confirmation_status == "ai_confirmed"

        result = await session.execute(select(Finding))
        assert len(result.scalars().all()) == 1

        await client.aclose()


async def test_safe_vertical_endpoint_is_not_flagged(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "would confirm if asked"}'
        )
        agent, client = await _make_agent(session, provider)
        sessions, labels = _sessions_and_labels()

        findings = await agent.run(["http://site.test/safe-admin/dashboard"], sessions, labels)

        assert findings == []
        assert len(provider.calls) == 0  # unauthenticated 401 -> no candidate, no LLM call

        await client.aclose()


async def test_detects_horizontal_idor(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "same user can fetch adjacent order ids"}'
        )
        agent, client = await _make_agent(session, provider)
        sessions, labels = _sessions_and_labels()

        findings = await agent.run(["http://site.test/orders/100"], sessions, labels)

        check_ids = {f.check_id for f in findings}
        assert "access-control-horizontal" in check_ids
        horizontal = next(f for f in findings if f.check_id == "access-control-horizontal")
        assert horizontal.severity == "High"

        await client.aclose()


async def test_safe_horizontal_endpoint_is_not_flagged(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "would confirm if asked"}'
        )
        agent, client = await _make_agent(session, provider)
        sessions, labels = _sessions_and_labels()

        findings = await agent.run(["http://site.test/safe-orders/100"], sessions, labels)

        assert findings == []

        await client.aclose()


async def test_adversarial_validation_can_veto_triage(db_adapter):
    async with session_scope(db_adapter) as session:
        responses = iter(
            [
                '{"vulnerable": true, "confidence": "high", "reasoning": "initial triage says yes"}',
                '{"vulnerable": false, "confidence": "high", "reasoning": "this admin page is intentionally public"}',
            ]
        )
        provider = ScriptedAIProviderAdapter(respond_fn=lambda _msgs: next(responses))
        agent, client = await _make_agent(session, provider)
        sessions, labels = _sessions_and_labels()

        findings = await agent.run(["http://site.test/admin/dashboard"], sessions, labels)

        assert findings == []
        assert len(provider.calls) == 2

        await client.aclose()
