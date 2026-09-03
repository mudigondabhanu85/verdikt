import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import httpx
from sqlalchemy import select

from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.agents.recon import DiscoveredParameter
from app.agents.xss import XSSAgent
from app.ai.budget import BudgetGuard
from app.models.finding import Finding
from app.models.project import ScopeEntry
from app.models.review_candidate import ReviewCandidate
from app.models.scan import ScanRun
from tests.conftest import session_scope
from tests.fakes import ScriptedAIProviderAdapter


def _handler(request: httpx.Request) -> httpx.Response:
    parsed = urlsplit(str(request.url))
    query = parse_qs(parsed.query)

    if parsed.path == "/search":
        term = query.get("q", [""])[0]
        # Reflects the query verbatim, unescaped — deliberately vulnerable.
        return httpx.Response(200, headers={"content-type": "text/html"}, text=f"<p>Results for: {term}</p>")

    if parsed.path == "/safe-search":
        import html

        term = query.get("q", [""])[0]
        return httpx.Response(
            200, headers={"content-type": "text/html"}, text=f"<p>Results for: {html.escape(term)}</p>"
        )

    if parsed.path == "/account-search":
        # A real, live-found bug: this endpoint's reflected XSS is only
        # reachable behind a login-gated cookie, matching a real target
        # (DVWA) whose vulnerable pages require an authenticated session
        # — every probe was silently unauthenticated before this fix.
        if request.headers.get("cookie") != "PHPSESSID=valid-session":
            return httpx.Response(302, headers={"location": "/login"})
        term = query.get("q", [""])[0]
        return httpx.Response(200, headers={"content-type": "text/html"}, text=f"<p>Results for: {term}</p>")

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
    agent = XSSAgent(
        client,
        scan_run_id=scan_run.id,
        agent_job_id=uuid.uuid4(),
        db_session=session,
        budget_guard=guard,
        ai_model="fake-model",
    )
    return agent, client


async def test_xss_agent_queues_review_candidate_not_finding(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "unescaped reflection in HTML body"}'
        )
        agent, client = await _make_agent(session, provider)

        parameters = [DiscoveredParameter(url="http://site.test/search?q=x", method="GET", name="q")]
        candidates = await agent.run(parameters, [])

        assert len(candidates) == 1
        candidate = candidates[0]
        assert candidate.check_type == "xss-reflected"
        assert candidate.status == "pending"
        assert candidate.affected_endpoint.startswith("http://site.test/search")
        assert "alert(1)" in candidate.request_raw or "vxss" in candidate.request_raw

        # Must not have created a Finding — browser proof is required first (§2 step 2).
        stored = await session.execute(select(ReviewCandidate))
        assert len(stored.scalars().all()) == 1

        await client.aclose()


async def test_login_gated_reflection_is_unreachable_without_a_session(db_adapter):
    """The real bug this fix closes: without a session, every probe hit
    the target completely unauthenticated."""
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "unescaped reflection"}'
        )
        agent, client = await _make_agent(session, provider)

        parameters = [DiscoveredParameter(url="http://site.test/account-search?q=x", method="GET", name="q")]
        candidates = await agent.run(parameters, [])

        assert candidates == []
        await client.aclose()


async def test_login_gated_reflection_is_found_with_a_session(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "unescaped reflection"}'
        )
        agent, client = await _make_agent(session, provider)

        parameters = [DiscoveredParameter(url="http://site.test/account-search?q=x", method="GET", name="q")]
        auth_session = AuthenticatedSession(
            credential_set_id=uuid.uuid4(), cookies={"PHPSESSID": "valid-session"}
        )
        sessions = {auth_session.credential_set_id: auth_session}
        candidates = await agent.run(parameters, [], sessions)

        assert len(candidates) == 1
        assert candidates[0].check_type == "xss-reflected"
        await client.aclose()


async def test_xss_agent_ignores_properly_escaped_reflection(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": true, "confidence": "high", "reasoning": "would confirm if asked"}'
        )
        agent, client = await _make_agent(session, provider)

        parameters = [DiscoveredParameter(url="http://site.test/safe-search?q=x", method="GET", name="q")]
        candidates = await agent.run(parameters, [])

        assert candidates == []
        assert len(provider.calls) == 0  # escaped reflection never even reaches the LLM

        await client.aclose()


class _RealReflectionFixtureHandler(BaseHTTPRequestHandler):
    """A real HTTP server (not httpx.MockTransport) so the real headless
    browser Playwright drives for §2 step 2 browser proof can actually
    reach it — MockTransport only intercepts the agent's own httpx calls,
    not a real browser's navigation.
    """

    def do_GET(self):  # noqa: N802
        parsed = urlsplit(self.path)
        term = parse_qs(parsed.query).get("q", [""])[0]
        if parsed.path == "/search":
            body = f"<p>Results for: {term}</p>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path == "/account-search":
            # A real, live-found bug: a fresh Playwright browser context
            # carries no cookies at all, so a login-gated page (matching
            # DVWA's real reflected-XSS page) always hit this redirect
            # and browser proof could never succeed — see
            # app.agents.xss_browser_proof.attempt_browser_proof.
            if self.headers.get("Cookie") != "PHPSESSID=valid-session":
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            body = f"<p>Results for: {term}</p>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):  # noqa: A002
        pass


async def test_xss_agent_auto_confirms_finding_with_real_browser_proof(db_adapter):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RealReflectionFixtureHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            provider = ScriptedAIProviderAdapter.from_responses(
                '{"vulnerable": true, "confidence": "high", "reasoning": "unescaped reflection in HTML body"}'
            )
            scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
            session.add(scan_run)
            await session.commit()
            await session.refresh(scan_run)

            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            guard = BudgetGuard(scan_run, session, provider)
            agent = XSSAgent(
                client,
                scan_run_id=scan_run.id,
                agent_job_id=uuid.uuid4(),
                db_session=session,
                budget_guard=guard,
                ai_model="fake-model",
            )

            parameters = [
                DiscoveredParameter(url=f"http://{host}:{port}/search?q=x", method="GET", name="q")
            ]
            candidates = await agent.run(parameters, [])

            # Real browser execution confirmed it — straight to a Finding,
            # no ReviewCandidate needed.
            assert candidates == []
            assert len(agent.findings) == 1
            finding = agent.findings[0]
            assert finding.confirmation_status == "ai_confirmed"
            assert finding.cwe_id == "CWE-79"

            stored_findings = (await session.execute(select(Finding))).scalars().all()
            assert len(stored_findings) == 1
            await session.refresh(stored_findings[0], attribute_names=["evidence"])
            assert stored_findings[0].evidence is not None
            assert len(stored_findings[0].evidence.screenshot_refs) == 1

            stored_candidates = (await session.execute(select(ReviewCandidate))).scalars().all()
            assert stored_candidates == []

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_browser_proof_reaches_login_gated_page_with_a_session(db_adapter):
    """The real bug this closes: attempt_browser_proof launched a fresh,
    cookie-less Playwright context, so a login-gated reflected-XSS page
    (matching DVWA's real /vulnerabilities/xss_r/ page) always hit the
    login redirect instead of the real vulnerable page and browser proof
    could never succeed — every such finding silently fell back to a
    ReviewCandidate (or nothing, before the AI-triage prompt fix) instead
    of an auto-confirmed Finding with a screenshot."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RealReflectionFixtureHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            provider = ScriptedAIProviderAdapter.from_responses(
                '{"vulnerable": true, "confidence": "high", "reasoning": "unescaped reflection in HTML body"}'
            )
            scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
            session.add(scan_run)
            await session.commit()
            await session.refresh(scan_run)

            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            guard = BudgetGuard(scan_run, session, provider)
            agent = XSSAgent(
                client,
                scan_run_id=scan_run.id,
                agent_job_id=uuid.uuid4(),
                db_session=session,
                budget_guard=guard,
                ai_model="fake-model",
            )

            parameters = [
                DiscoveredParameter(url=f"http://{host}:{port}/account-search?q=x", method="GET", name="q")
            ]
            auth_session = AuthenticatedSession(
                credential_set_id=uuid.uuid4(), cookies={"PHPSESSID": "valid-session"}
            )
            sessions = {auth_session.credential_set_id: auth_session}
            candidates = await agent.run(parameters, [], sessions)

            assert candidates == []
            assert len(agent.findings) == 1
            finding = agent.findings[0]
            assert finding.confirmation_status == "ai_confirmed"

            await session.refresh(finding, attribute_names=["evidence"])
            assert len(finding.evidence.screenshot_refs) == 1

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_xss_agent_discards_when_triage_says_not_exploitable(db_adapter):
    async with session_scope(db_adapter) as session:
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": false, "confidence": "medium", "reasoning": "reflection is inside an HTML comment"}'
        )
        agent, client = await _make_agent(session, provider)

        parameters = [DiscoveredParameter(url="http://site.test/search?q=x", method="GET", name="q")]
        candidates = await agent.run(parameters, [])

        assert candidates == []

        result = await session.execute(select(ReviewCandidate))
        assert result.scalars().all() == []

        await client.aclose()
