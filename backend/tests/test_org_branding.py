"""Tests for the org branding CRUD API (app/api/routes/org_branding.py).

The router isn't registered on the main app yet (that happens in a
central wiring pass after this and several other parallel feature slices
land), so this builds its own minimal FastAPI app mounting just this
router — same dependency-override pattern tests/conftest.py's `client`
fixture uses against the real app.
"""

import uuid

import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.routes.org_branding import router as org_branding_router
from app.auth.security import create_access_token, hash_password
from app.db.session import get_db_session
from app.models.organization import Organization, User
from tests.conftest import db_adapter  # noqa: F401 — reused fixture


def _make_app():
    app = FastAPI()
    app.include_router(org_branding_router)
    return app


@pytest_asyncio.fixture
async def branding_client(db_adapter, monkeypatch):
    from app.db.session import get_adapter

    monkeypatch.setattr("app.db.session.get_adapter", lambda: db_adapter)
    get_adapter.cache_clear()

    app = _make_app()

    async def _override_get_db_session():
        async for session in db_adapter.get_session():
            yield session

    app.dependency_overrides[get_db_session] = _override_get_db_session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, db_adapter
    app.dependency_overrides.clear()


async def _create_org_admin(db_adapter, *, org_name="Acme"):
    from tests.conftest import session_scope

    async with session_scope(db_adapter) as session:
        org = Organization(name=f"{org_name}-{uuid.uuid4()}")
        session.add(org)
        await session.flush()
        user = User(
            org_id=org.id,
            email=f"admin-{uuid.uuid4()}@example.com",
            hashed_password=hash_password("correct-horse-battery-staple"),
            role="org_admin",
            is_active=True,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        token = create_access_token(user.id)
        return org, user, {"Authorization": f"Bearer {token}"}


async def test_get_org_branding_creates_default_row(branding_client):
    client, db_adapter = branding_client
    org, user, headers = await _create_org_admin(db_adapter)

    resp = await client.get("/org-branding", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["org_id"] == str(org.id)
    assert body["logo_object_key"] is None
    assert body["company_name"] is None


async def test_update_org_branding_fields(branding_client):
    client, db_adapter = branding_client
    org, user, headers = await _create_org_admin(db_adapter)

    resp = await client.put(
        "/org-branding",
        json={"company_name": "Acme Corp", "primary_color_hex": "#1a56db"},
        headers=headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["company_name"] == "Acme Corp"
    assert body["primary_color_hex"] == "#1a56db"

    # Re-fetch to confirm persistence, not just an echoed response.
    resp2 = await client.get("/org-branding", headers=headers)
    assert resp2.json()["company_name"] == "Acme Corp"


async def test_upload_and_delete_logo(branding_client):
    client, db_adapter = branding_client
    org, user, headers = await _create_org_admin(db_adapter)

    files = {"logo": ("logo.png", b"\x89PNG\r\n\x1a\nfakepngbytes", "image/png")}
    resp = await client.post("/org-branding/logo", files=files, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["logo_object_key"] is not None

    resp2 = await client.delete("/org-branding/logo", headers=headers)
    assert resp2.status_code == 200
    assert resp2.json()["logo_object_key"] is None


async def test_org_branding_is_org_scoped(branding_client):
    client, db_adapter = branding_client
    org_a, user_a, headers_a = await _create_org_admin(db_adapter, org_name="Org A")
    org_b, user_b, headers_b = await _create_org_admin(db_adapter, org_name="Org B")

    await client.put("/org-branding", json={"company_name": "Org A Name"}, headers=headers_a)
    resp_b = await client.get("/org-branding", headers=headers_b)
    assert resp_b.json()["company_name"] is None


async def test_non_admin_role_cannot_update_branding(branding_client):
    from tests.conftest import session_scope

    client, db_adapter = branding_client
    org, admin_user, admin_headers = await _create_org_admin(db_adapter)

    async with session_scope(db_adapter) as session:
        viewer = User(
            org_id=org.id,
            email=f"viewer-{uuid.uuid4()}@example.com",
            hashed_password=hash_password("correct-horse-battery-staple"),
            role="viewer",
            is_active=True,
        )
        session.add(viewer)
        await session.commit()
        await session.refresh(viewer)
        viewer_token = create_access_token(viewer.id)

    resp = await client.put(
        "/org-branding",
        json={"company_name": "Should Fail"},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403
