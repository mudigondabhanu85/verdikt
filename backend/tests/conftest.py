import os
import tempfile
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

os.environ.setdefault("VAULT_MASTER_KEY", "test-only-vault-key")
os.environ.setdefault("JWT_SECRET", "test-only-jwt-secret-at-least-32-bytes-long")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.auth.rbac_seed import baseline_grants
from app.auth.security import create_access_token, hash_password
from app.db.postgres_adapter import PostgresAdapter
from app.db.session import get_db_session, session_scope
from app.main import app
from app.models.organization import User
from app.models.rbac import RolePermission

__all__ = ["session_scope"]  # re-exported for tests importing it from here


@pytest_asyncio.fixture
async def db_adapter():
    """A fresh SQLite-backed DatabaseAdapter per test. The DB layer is
    dialect-agnostic (see app/db), so this exercises the same code paths
    Postgres would in real dev/prod — no external services required."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(path)
    adapter = PostgresAdapter(f"sqlite+aiosqlite:///{path}")
    await adapter.create_all()

    async with session_scope(adapter) as session:
        for role, resource, action in baseline_grants():
            session.add(RolePermission(role=role, resource=resource, action=action, allowed=True))
        await session.commit()

    yield adapter

    await adapter.dispose()
    Path(path).unlink(missing_ok=True)


@pytest_asyncio.fixture
async def client(db_adapter: PostgresAdapter, monkeypatch):
    async def _override_get_db_session():
        async for session in db_adapter.get_session():
            yield session

    app.dependency_overrides[get_db_session] = _override_get_db_session
    # BackgroundTasks (e.g. app.agents.runner.execute_scan_run) run outside
    # FastAPI's DI system, so dependency_overrides above doesn't reach them —
    # they look up the adapter via app.db.session.get_adapter() directly, so
    # patch that too or a scan-run background task would try to hit the real
    # (nonexistent, in this sandbox) production Postgres.
    monkeypatch.setattr("app.db.session.get_adapter", lambda: db_adapter)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


async def register_org_admin(client: AsyncClient, *, org_name="Acme Corp", email="admin@acme.io", password="correct-horse-battery-staple"):
    resp = await client.post(
        "/auth/register", json={"org_name": org_name, "email": email, "password": password}
    )
    assert resp.status_code == 201, resp.text
    token = resp.json()["access_token"]
    return {"token": token, "headers": {"Authorization": f"Bearer {token}"}, "email": email}


async def create_user_with_role(db_adapter: PostgresAdapter, *, org_id, role: str, email: str):
    """Directly inserts a user with an arbitrary role. Phase 0 has no
    "invite teammate" endpoint (bootstrap registration only creates
    org_admins), so RBAC tests for the other baseline roles seed the user
    straight into the DB."""
    if not isinstance(org_id, uuid.UUID):
        org_id = uuid.UUID(str(org_id))

    async with session_scope(db_adapter) as session:
        user = User(org_id=org_id, email=email, hashed_password=hash_password("irrelevant"), role=role)
        session.add(user)
        await session.commit()
        await session.refresh(user)
        user_id = user.id

    token = create_access_token(user_id)
    return {"token": token, "headers": {"Authorization": f"Bearer {token}"}, "user_id": user_id}


_LOGIN_FIXTURE_PAGE = b"""<html><body>
<form method="POST" action="/login">
  <input type="text" name="username" id="username">
  <input type="password" name="password" id="password">
  <button type="submit" id="submit-btn">Log in</button>
</form>
</body></html>"""


class _LoginFixtureHandler(BaseHTTPRequestHandler):
    """A tiny real HTTP server serving a classic server-rendered login
    form (Playwright needs a real URL to navigate to — it can't drive
    httpx.MockTransport). Accepts expected_user/expected_pass and sets a
    session cookie on success, used by the Phase 4 macro recorder/player
    tests to prove record -> store -> replay end-to-end against a real
    browser and a real server round-trip."""

    def do_GET(self):  # noqa: N802
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(_LOGIN_FIXTURE_PAGE)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):  # noqa: N802
        if self.path != "/login":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        params = parse_qs(body)
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]

        if username == "expected_user" and password == "expected_pass":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "session=abc123-real-session; Path=/")
            self.end_headers()
            self.wfile.write(b"<html><body>Welcome!</body></html>")
        else:
            self.send_response(401)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>Invalid credentials</body></html>")

    def log_message(self, format, *args):  # noqa: A002
        pass


@pytest.fixture
def fixture_login_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LoginFixtureHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        thread.join(timeout=2)


async def create_project_and_version(client: AsyncClient, headers: dict, *, project_name="Test Project", version_name="v1"):
    project = (await client.post("/projects", json={"name": project_name}, headers=headers)).json()
    version = (
        await client.post(
            f"/projects/{project['id']}/versions", json={"name": version_name}, headers=headers
        )
    ).json()
    return project["id"], version["id"]
