from tests.conftest import create_project_and_version, register_org_admin


async def test_new_version_is_not_authorized(client):
    admin = await register_org_admin(client)
    project_id, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.get(f"/versions/{version_id}", headers=admin["headers"])
    assert resp.status_code == 200
    assert resp.json()["is_authorized"] is False


async def test_scope_entries_crud(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    added = await client.post(
        f"/versions/{version_id}/scope-entries",
        json={"host": "app.example.test", "port": 443, "in_scope": True},
        headers=admin["headers"],
    )
    assert added.status_code == 201

    out_of_scope = await client.post(
        f"/versions/{version_id}/scope-entries",
        json={"host": "billing.example.test", "in_scope": False},
        headers=admin["headers"],
    )
    assert out_of_scope.status_code == 201

    listed = await client.get(f"/versions/{version_id}/scope-entries", headers=admin["headers"])
    hosts = {e["host"]: e["in_scope"] for e in listed.json()}
    assert hosts == {"app.example.test": True, "billing.example.test": False}


async def test_authorization_attestation_flips_is_authorized(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    granted = await client.post(
        f"/versions/{version_id}/authorization",
        data={"approver_name": "Jane CISO", "attestation_text": "Approved for pentest 2026-08-14"},
        headers=admin["headers"],
    )
    assert granted.status_code == 201
    assert granted.json()["approver_name"] == "Jane CISO"

    refetched = await client.get(f"/versions/{version_id}", headers=admin["headers"])
    assert refetched.json()["is_authorized"] is True


async def test_authorization_with_uploaded_letter(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/authorization",
        data={"approver_name": "Jane CISO"},
        files={"letter": ("authorization.pdf", b"%PDF-1.4 fake letter contents", "application/pdf")},
        headers=admin["headers"],
    )
    assert resp.status_code == 201
    assert resp.json()["letter_object_key"] == f"versions/{version_id}/authorization/authorization.pdf"
