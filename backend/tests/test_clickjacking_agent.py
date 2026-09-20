import threading
import uuid
from http.server import ThreadingHTTPServer

import httpx
from sqlalchemy import select

from app.agents.clickjacking import ClickjackingAgent
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.models.finding import Finding
from app.models.project import ScopeEntry
from tests.conftest import session_scope
from tests.test_clickjacking_proof import _ClickjackingFixtureHandler


def _server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ClickjackingFixtureHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


async def test_clickjacking_agent_persists_confirmed_finding_with_screenshot(db_adapter):
    server, thread = _server()
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
                transport=httpx.MockTransport(lambda r: httpx.Response(404)),
            )
            agent = ClickjackingAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            findings = await agent.run([f"http://{host}:{port}/framable"])

            assert len(findings) == 1
            finding = findings[0]
            assert finding.check_id == "clickjacking-confirmed"
            assert finding.confirmation_status == "ai_confirmed"

            stored = (await session.execute(select(Finding))).scalars().all()
            assert len(stored) == 1
            await session.refresh(stored[0], attribute_names=["evidence"])
            assert len(stored[0].evidence.screenshot_refs) == 1

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_clickjacking_agent_finds_nothing_when_protected(db_adapter):
    server, thread = _server()
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
                transport=httpx.MockTransport(lambda r: httpx.Response(404)),
            )
            agent = ClickjackingAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            findings = await agent.run([f"http://{host}:{port}/blocked"])
            assert findings == []
            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_clickjacking_agent_tests_both_anonymous_and_authenticated(db_adapter):
    """§3 item 3: a session, when available, gets a genuinely separate
    check per host — not a replacement for the anonymous one. Confirms
    both fire for the same always-framable host, and that the
    authenticated finding's write-up says so.
    """
    server, thread = _server()
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
                transport=httpx.MockTransport(lambda r: httpx.Response(404)),
            )
            agent = ClickjackingAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            cred_id = uuid.uuid4()
            auth_session = AuthenticatedSession(credential_set_id=cred_id, cookies={"session": "valid"})
            findings = await agent.run(
                [f"http://{host}:{port}/framable"], sessions={cred_id: auth_session}
            )

            assert len(findings) == 2
            descriptions = [f.technical_description for f in findings]
            assert any("anonymous visitor" in d for d in descriptions)
            assert any("logged-in user" in d for d in descriptions)

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_clickjacking_agent_login_gated_page_needs_the_session(db_adapter):
    """The real, live-relevant gap this whole item exists to close: a
    login-gated page is only confirmed framable when tested with a
    session — without one, it's indistinguishable from "not vulnerable"
    (an empty shell, not blocked by any header).
    """
    server, thread = _server()
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
                transport=httpx.MockTransport(lambda r: httpx.Response(404)),
            )
            agent = ClickjackingAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            cred_id = uuid.uuid4()
            auth_session = AuthenticatedSession(credential_set_id=cred_id, cookies={"session": "valid"})

            without_session = await agent.run([f"http://{host}:{port}/dashboard"])
            assert without_session == []

            with_session = await agent.run(
                [f"http://{host}:{port}/dashboard"], sessions={cred_id: auth_session}
            )
            assert len(with_session) == 1
            assert "logged-in user" in with_session[0].technical_description

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_clickjacking_agent_dedupes_by_host(db_adapter):
    server, thread = _server()
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
                transport=httpx.MockTransport(lambda r: httpx.Response(404)),
            )
            agent = ClickjackingAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            endpoints = [
                f"http://{host}:{port}/framable",
                f"http://{host}:{port}/framable?x=1",
                f"http://{host}:{port}/blocked",
            ]
            findings = await agent.run(endpoints)
            assert len(findings) == 1
            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)
