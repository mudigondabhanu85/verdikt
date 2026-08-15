import os
import tempfile
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

os.environ.setdefault("VAULT_MASTER_KEY", "test-only-vault-key")
os.environ.setdefault("JWT_SECRET", "test-only-jwt-secret-at-least-32-bytes-long")

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.auth.rbac_seed import baseline_grants
from app.auth.security import create_access_token, hash_password
from app.db.postgres_adapter import PostgresAdapter
from app.db.session import get_db_session
from app.main import app
from app.models.organization import User
from app.models.rbac import RolePermission


@asynccontextmanager
async def session_scope(adapter: PostgresAdapter):
    gen = adapter.get_session()
    session = await gen.__anext__()
    try:
        yield session
    finally:
        await gen.aclose()


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
async def client(db_adapter: PostgresAdapter):
    async def _override_get_db_session():
        async for session in db_adapter.get_session():
            yield session

    app.dependency_overrides[get_db_session] = _override_get_db_session
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


async def create_project_and_version(client: AsyncClient, headers: dict, *, project_name="Test Project", version_name="v1"):
    project = (await client.post("/projects", json={"name": project_name}, headers=headers)).json()
    version = (
        await client.post(
            f"/projects/{project['id']}/versions", json={"name": version_name}, headers=headers
        )
    ).json()
    return project["id"], version["id"]
