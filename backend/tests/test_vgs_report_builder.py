"""Tests for the VGS report-builder API (app/api/routes/vgs_vulnerabilities.py)
and the ported DOCX generator (app/reporting/vgs_docx_report.py).

The routers aren't registered on the main app yet (that happens in a
central wiring pass after this and several other parallel feature slices
land), so this builds its own minimal FastAPI app mounting just these
routers — same dependency-override pattern tests/conftest.py's `client`
fixture uses against the real app (see tests/test_org_branding.py for
the identical established pattern this file mirrors).
"""

import io
import uuid

import pytest_asyncio
from docx import Document
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from PIL import Image

from app.api.routes.vgs_vulnerabilities import draft_router, library_router
from app.auth.security import create_access_token, hash_password
from app.db.session import get_db_session
from app.models.organization import Organization, User
from app.models.project import Project, Version
from tests.conftest import db_adapter  # noqa: F401 — reused fixture
from tests.conftest import session_scope


def _make_app():
    app = FastAPI()
    app.include_router(library_router)
    app.include_router(draft_router)
    return app


@pytest_asyncio.fixture
async def vgs_client(db_adapter, monkeypatch):
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
        await session.flush()
        project = Project(org_id=org.id, name="Test Project", created_by=user.id)
        session.add(project)
        await session.flush()
        version = Version(project_id=project.id, name="v1", created_by=user.id)
        session.add(version)
        await session.commit()
        await session.refresh(user)
        await session.refresh(version)
        token = create_access_token(user.id)
        return org, user, version, {"Authorization": f"Bearer {token}"}


def _real_png_bytes() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (20, 10), color=(200, 0, 0)).save(buf, format="PNG")
    return buf.getvalue()


async def test_library_crud_and_org_scoping(vgs_client):
    client, db_adapter = vgs_client
    org_a, _user_a, _v_a, headers_a = await _create_org_admin(db_adapter, org_name="OrgA")
    _org_b, _user_b, _v_b, headers_b = await _create_org_admin(db_adapter, org_name="OrgB")

    created = await client.post(
        "/vgs-vulnerability-library",
        json={
            "title": "SQL Injection",
            "severity": "Critical",
            "cvss_score": "9.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "description": "desc",
            "recommendation": "rec",
            "reference": "ref",
        },
        headers=headers_a,
    )
    assert created.status_code == 201, created.text
    entry_id = created.json()["id"]
    assert created.json()["org_id"] == str(org_a.id)

    list_a = await client.get("/vgs-vulnerability-library", headers=headers_a)
    assert len(list_a.json()) == 1

    # Org B can't see Org A's library entry.
    list_b = await client.get("/vgs-vulnerability-library", headers=headers_b)
    assert list_b.json() == []

    updated = await client.patch(
        f"/vgs-vulnerability-library/{entry_id}",
        json={
            "title": "SQL Injection (updated)",
            "severity": "High",
            "cvss_score": "8.0",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "description": "desc2",
            "recommendation": "rec2",
            "reference": "ref2",
        },
        headers=headers_a,
    )
    assert updated.status_code == 200
    assert updated.json()["title"] == "SQL Injection (updated)"

    deleted = await client.delete(f"/vgs-vulnerability-library/{entry_id}", headers=headers_a)
    assert deleted.status_code == 204
    assert (await client.get("/vgs-vulnerability-library", headers=headers_a)).json() == []


async def test_report_draft_get_or_create_and_update(vgs_client):
    client, db_adapter = vgs_client
    _org, _user, version, headers = await _create_org_admin(db_adapter)

    draft = await client.get(f"/versions/{version.id}/vgs-report-draft", headers=headers)
    assert draft.status_code == 200
    assert draft.json()["app_title"] == ""

    updated = await client.patch(
        f"/versions/{version.id}/vgs-report-draft",
        json={"app_title": "My App", "analyst_name": "Alice", "requester_name": "Bob"},
        headers=headers,
    )
    assert updated.status_code == 200
    assert updated.json()["app_title"] == "My App"
    assert updated.json()["analyst_name"] == "Alice"

    # Get-again returns the same draft, not a new one.
    draft_again = await client.get(f"/versions/{version.id}/vgs-report-draft", headers=headers)
    assert draft_again.json()["id"] == updated.json()["id"]


async def test_add_from_library_and_ad_hoc_vulnerabilities_and_generate_docx(vgs_client):
    client, db_adapter = vgs_client
    _org, _user, version, headers = await _create_org_admin(db_adapter)

    library_entry = await client.post(
        "/vgs-vulnerability-library",
        json={
            "title": "Reflected XSS",
            "severity": "High",
            "cvss_score": "7.4",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "description": "XSS description",
            "recommendation": "Escape output",
            "reference": "https://owasp.org/xss",
        },
        headers=headers,
    )
    library_entry_id = library_entry.json()["id"]

    await client.patch(
        f"/versions/{version.id}/vgs-report-draft",
        json={"app_title": "Test App", "analyst_name": "Alice", "requester_name": "Bob"},
        headers=headers,
    )

    from_library = await client.post(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities",
        json={"library_entry_id": library_entry_id},
        headers=headers,
    )
    assert from_library.status_code == 201, from_library.text
    assert from_library.json()["title"] == "Reflected XSS"
    assert from_library.json()["library_entry_id"] == library_entry_id

    ad_hoc = await client.post(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities",
        json={
            "title": "Custom Finding",
            "severity": "Medium",
            "cvss_score": "5.3",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "description": "custom desc",
            "recommendation": "custom rec",
            "reference": "custom ref",
        },
        headers=headers,
    )
    assert ad_hoc.status_code == 201, ad_hoc.text
    ad_hoc_id = ad_hoc.json()["id"]

    # Ad-hoc creation without title/severity is rejected.
    rejected = await client.post(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities", json={}, headers=headers
    )
    assert rejected.status_code == 400

    listed = await client.get(f"/versions/{version.id}/vgs-report-draft/vulnerabilities", headers=headers)
    assert len(listed.json()) == 2

    # Real evidence step with a real uploaded PNG.
    files = {"screenshot": ("proof.png", _real_png_bytes(), "image/png")}
    step = await client.post(
        f"/versions/{version.id}/vgs-report-draft/vulnerabilities/{ad_hoc_id}/evidence-steps",
        data={"comment": "Observed the injected script execute."},
        files=files,
        headers=headers,
    )
    assert step.status_code == 201, step.text
    assert len(step.json()["screenshot_object_keys"]) == 1

    # Real DOCX generation, re-opened and checked structurally.
    report = await client.get(f"/versions/{version.id}/vgs-report-draft/report.docx", headers=headers)
    assert report.status_code == 200
    assert report.headers["content-type"] == (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )

    document = Document(io.BytesIO(report.content))
    heading_texts = [p.text for p in document.paragraphs if p.style.name.startswith("Heading 3")]
    # One heading per vulnerability ("1. Reflected XSS", "2. Custom Finding").
    assert any("Reflected XSS" in h for h in heading_texts)
    assert any("Custom Finding" in h for h in heading_texts)
    assert len(document.inline_shapes) >= 1  # pie chart + evidence screenshot present
