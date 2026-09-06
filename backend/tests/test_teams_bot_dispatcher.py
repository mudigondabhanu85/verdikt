import asyncio
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sqlalchemy import select

from app.integrations.teams_bot.commands import NewProjectCommand, ScanCommand, StatusCommand
from app.integrations.teams_bot.dispatcher import TeamsCommandDispatcher
from app.models.organization import Organization, User
from app.models.project import AuthorizationRecord, Project, ScopeEntry, Version
from app.models.scan import ScanRun
from app.auth.security import hash_password
from tests.conftest import session_scope


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>hello</body></html>")

    def log_message(self, *args):  # noqa: D401 - silence test noise
        pass


async def _make_org_and_user(db_adapter) -> User:
    async with session_scope(db_adapter) as session:
        org = Organization(name=f"Teams Bot Org {uuid.uuid4()}")
        session.add(org)
        await session.flush()
        user = User(
            org_id=org.id,
            email=f"bot-actor-{uuid.uuid4()}@example.com",
            hashed_password=hash_password("irrelevant"),
            role="org_admin",
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


async def test_scan_command_creates_scan_run_for_existing_authorized_project(db_adapter, monkeypatch):
    monkeypatch.setattr("app.db.session.get_adapter", lambda: db_adapter)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address

    try:
        user = await _make_org_and_user(db_adapter)

        async with session_scope(db_adapter) as session:
            project = Project(org_id=user.org_id, name="Juice Shop", created_by=user.id)
            session.add(project)
            await session.flush()
            version = Version(project_id=project.id, name="v1", created_by=user.id)
            session.add(version)
            await session.flush()
            session.add(ScopeEntry(version_id=version.id, host=host, port=port, in_scope=True))
            session.add(
                AuthorizationRecord(
                    version_id=version.id,
                    approver_name="Test Approver",
                    attestation_text="authorized",
                    attested_by=user.id,
                    attested_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
                )
            )
            await session.commit()

        tasks_before = asyncio.all_tasks()

        async with session_scope(db_adapter) as session:
            fresh_user = await session.get(User, user.id)
            dispatcher = TeamsCommandDispatcher(session, acting_user=fresh_user)
            reply = await dispatcher.dispatch(ScanCommand(project_name="Juice Shop"))

        assert "Scan started for \"Juice Shop\"" in reply

        new_tasks = asyncio.all_tasks() - tasks_before
        for task in new_tasks:
            await task

        async with session_scope(db_adapter) as session:
            result = await session.execute(select(ScanRun).where(ScanRun.version_id == version.id))
            scan_run = result.scalar_one()
            assert scan_run.status == "completed"
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def test_scan_command_unknown_project_returns_helpful_reply(db_adapter, monkeypatch):
    monkeypatch.setattr("app.db.session.get_adapter", lambda: db_adapter)
    user = await _make_org_and_user(db_adapter)

    async with session_scope(db_adapter) as session:
        fresh_user = await session.get(User, user.id)
        dispatcher = TeamsCommandDispatcher(session, acting_user=fresh_user)
        reply = await dispatcher.dispatch(ScanCommand(project_name="Nonexistent App"))

    assert "No project named" in reply
    assert "Nonexistent App" in reply


async def test_status_command_reports_no_scans_yet(db_adapter, monkeypatch):
    monkeypatch.setattr("app.db.session.get_adapter", lambda: db_adapter)
    user = await _make_org_and_user(db_adapter)

    async with session_scope(db_adapter) as session:
        project = Project(org_id=user.org_id, name="Empty App", created_by=user.id)
        session.add(project)
        await session.commit()

    async with session_scope(db_adapter) as session:
        fresh_user = await session.get(User, user.id)
        dispatcher = TeamsCommandDispatcher(session, acting_user=fresh_user)
        reply = await dispatcher.dispatch(StatusCommand(project_name="Empty App"))

    assert "no scan runs yet" in reply


async def test_new_project_command_creates_bare_project_with_deep_link(db_adapter, monkeypatch):
    monkeypatch.setattr("app.db.session.get_adapter", lambda: db_adapter)
    user = await _make_org_and_user(db_adapter)

    async with session_scope(db_adapter) as session:
        fresh_user = await session.get(User, user.id)
        dispatcher = TeamsCommandDispatcher(session, acting_user=fresh_user)
        reply = await dispatcher.dispatch(NewProjectCommand(url="https://newapp.example.com"))

    assert "https://newapp.example.com" in reply
    assert "/projects/" in reply

    async with session_scope(db_adapter) as session:
        result = await session.execute(
            select(Project).where(Project.org_id == user.org_id, Project.name == "https://newapp.example.com")
        )
        assert result.scalar_one_or_none() is not None
