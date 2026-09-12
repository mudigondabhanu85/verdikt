import uuid
from urllib.parse import parse_qs, urlsplit

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
    if "standarduser-role-token" in auth:
        return "standarduser"
    if "roleadmin-role-token" in auth:
        return "roleadmin"
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

    if path == "/role-admin/dashboard":
        # Vulnerable: identical full content regardless of caller's role.
        if who in ("standarduser", "roleadmin"):
            return httpx.Response(200, text="<html>Admin Dashboard: revenue, users, settings...</html>")
        return httpx.Response(401, text="unauthorized")

    if path == "/safe-role-admin/dashboard":
        if who == "roleadmin":
            return httpx.Response(200, text="<html>Admin Dashboard: revenue, users, settings...</html>")
        if who == "standarduser":
            return httpx.Response(403, text="forbidden")
        return httpx.Response(401, text="unauthorized")

    if path == "/loyalty/points":
        # Real, live-found gap: a lookup endpoint keyed by a query-string
        # identifier ("?email=") rather than a numeric path segment,
        # with no ownership check at all — vulnerable regardless of who
        # (or whether anyone) is asking.
        email = parse_qs(urlsplit(str(request.url)).query).get("email", [""])[0]
        return httpx.Response(200, text=f"<html>Points for {email}: 1250 pts, Orders: #1001</html>")

    if path == "/safe-loyalty/points":
        email = parse_qs(urlsplit(str(request.url)).query).get("email", [""])[0]
        if email == "known@example.com":
            return httpx.Response(200, text="<html>Points for known@example.com: 1250 pts</html>")
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


def _ranked_sessions_and_labels():
    standarduser_id = uuid.uuid4()
    roleadmin_id = uuid.uuid4()
    sessions = {
        standarduser_id: AuthenticatedSession(
            credential_set_id=standarduser_id, bearer_token="standarduser-role-token"
        ),
        roleadmin_id: AuthenticatedSession(credential_set_id=roleadmin_id, bearer_token="roleadmin-role-token"),
    }
    labels = {standarduser_id: "Standard User", roleadmin_id: "Role Admin"}
    ranks = {standarduser_id: 1, roleadmin_id: 10}
    return sessions, labels, ranks


async def test_detects_role_vs_role_vertical_escalation(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "standard user gets full admin content"}'
        )
        agent, client = await _make_agent(session, provider)
        sessions, labels, ranks = _ranked_sessions_and_labels()

        findings = await agent.run(["http://site.test/role-admin/dashboard"], sessions, labels, ranks)

        assert len(findings) == 1
        assert findings[0].check_id == "access-control-role_vertical"
        assert findings[0].severity == "Critical"
        assert findings[0].confirmation_status == "ai_confirmed"

        await client.aclose()


async def test_safe_role_vertical_endpoint_is_not_flagged(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "would confirm if asked"}'
        )
        agent, client = await _make_agent(session, provider)
        sessions, labels, ranks = _ranked_sessions_and_labels()

        findings = await agent.run(["http://site.test/safe-role-admin/dashboard"], sessions, labels, ranks)

        assert findings == []
        assert len(provider.calls) == 0  # 403 for the lower-ranked identity -> no candidate, no LLM call

        await client.aclose()


async def test_role_vertical_never_triggers_without_ranks(db_adapter):
    # Same vulnerable endpoint as test_detects_role_vs_role_vertical_escalation,
    # but no credential_ranks passed at all — without an explicit ranking
    # there's no ground truth for which identity is "supposed" to have
    # more access, so this check must not fire (the existing unranked
    # "vertical" check, unauth-vs-auth, still can't fire here either
    # since there's no unauthenticated identity in this fixture's set).
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "would confirm if asked"}'
        )
        agent, client = await _make_agent(session, provider)
        sessions, labels, _ranks = _ranked_sessions_and_labels()

        findings = await agent.run(["http://site.test/role-admin/dashboard"], sessions, labels)

        assert findings == []
        assert len(provider.calls) == 0

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


async def test_detects_horizontal_idor_via_query_param_unauthenticated(db_adapter):
    """Regression test for a real gap found live: find_numeric_id_segment
    returns None for a query-string identifier (no numeric path segment
    at all), so the old code returned None immediately — never testing
    the endpoint. Passing {} for both sessions and labels (matching the
    real bug: a version with zero credentials configured at all) proves
    this is caught for a fully anonymous caller too — the identities
    list always includes the unauthenticated baseline, but the old code
    explicitly filtered it out."""
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "any email works with no auth"}'
        )
        agent, client = await _make_agent(session, provider)

        findings = await agent.run(["http://site.test/loyalty/points?email=known@example.com"], {}, {})

        check_ids = {f.check_id for f in findings}
        assert "access-control-horizontal" in check_ids
        horizontal = next(f for f in findings if f.check_id == "access-control-horizontal")
        assert "unauthenticated" in horizontal.technical_description.lower()

        await client.aclose()


async def test_safe_horizontal_query_param_endpoint_is_not_flagged(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "would confirm if asked"}'
        )
        agent, client = await _make_agent(session, provider)

        findings = await agent.run(["http://site.test/safe-loyalty/points?email=known@example.com"], {}, {})

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
