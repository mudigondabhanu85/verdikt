"""Tests app.api.routes.saml against a locally-mounted FastAPI app rather
than the shared app.main.app instance — the saml router isn't registered
on app.main.app yet as of this test (a separate central-wiring pass
handles that), so this builds a minimal standalone app with just the
saml router included, sharing the same db_adapter/get_db_session
override pattern tests/conftest.py's `client` fixture uses for the real
app. User registration still goes through the real app.main.app (via
the standard `client` fixture) since /auth/register lives there — both
apps share the same underlying db_adapter, so a user created via one is
visible to the other.
"""

import xml.etree.ElementTree as ET

import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api.routes import saml as saml_routes
from app.db.session import get_db_session
from tests.conftest import register_org_admin


@pytest_asyncio.fixture
async def saml_client(db_adapter):
    app = FastAPI()
    app.include_router(saml_routes.router)

    async def _override_get_db_session():
        async for session in db_adapter.get_session():
            yield session

    app.dependency_overrides[get_db_session] = _override_get_db_session

    # A dotted host, not "http://test" (httpx's usual convention) —
    # OneLogin_Saml2_Settings' URL validator rejects single-label
    # domains by default (production always has a real dotted domain;
    # this is purely a test-harness detail, not a product constraint).
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://verdikt.test") as ac:
        yield ac
    app.dependency_overrides.clear()


async def test_saml_config_crud(client, saml_client):
    admin = await register_org_admin(client)

    created = await saml_client.post(
        "/saml-configs", json={"label": "Okta Prod"}, headers=admin["headers"]
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["label"] == "Okta Prod"
    assert body["has_idp_metadata"] is False

    listed = await saml_client.get("/saml-configs", headers=admin["headers"])
    assert len(listed.json()) == 1

    deleted = await saml_client.delete(f"/saml-configs/{body['id']}", headers=admin["headers"])
    assert deleted.status_code == 204

    listed_after = await saml_client.get("/saml-configs", headers=admin["headers"])
    assert listed_after.json() == []


async def test_metadata_download_returns_real_parseable_xml(client, saml_client):
    admin = await register_org_admin(client)

    created = await saml_client.post(
        "/saml-configs", json={"label": "Okta Prod"}, headers=admin["headers"]
    )
    config_id = created.json()["id"]

    resp = await saml_client.get(
        f"/saml-configs/{config_id}/metadata.xml", headers=admin["headers"]
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("application/xml")

    root = ET.fromstring(resp.text)  # raises if not well-formed
    assert root.tag == "{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor"
    assert f"/saml-configs/{config_id}/metadata.xml" in root.attrib["entityID"]


async def test_upload_idp_metadata_with_individual_fields(client, saml_client):
    admin = await register_org_admin(client)

    created = await saml_client.post(
        "/saml-configs", json={"label": "Okta Prod"}, headers=admin["headers"]
    )
    config_id = created.json()["id"]

    resp = await saml_client.post(
        f"/saml-configs/{config_id}/idp-metadata",
        json={
            "idp_sso_url": "https://acme.okta.com/app/verdikt/abc123/sso/saml",
            "idp_entity_id": "http://www.okta.com/abc123",
            "idp_x509_cert": "MIIC-fake-cert-data",
        },
        headers=admin["headers"],
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["idp_sso_url"] == "https://acme.okta.com/app/verdikt/abc123/sso/saml"
    assert body["has_idp_metadata"] is True


async def test_upload_idp_metadata_rejects_incomplete_payload(client, saml_client):
    admin = await register_org_admin(client)

    created = await saml_client.post(
        "/saml-configs", json={"label": "Okta Prod"}, headers=admin["headers"]
    )
    config_id = created.json()["id"]

    resp = await saml_client.post(
        f"/saml-configs/{config_id}/idp-metadata",
        json={"idp_sso_url": "https://acme.okta.com/sso"},  # missing entity_id + cert
        headers=admin["headers"],
    )
    assert resp.status_code == 422
