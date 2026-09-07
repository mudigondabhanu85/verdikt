from tests.conftest import create_project_and_version, register_org_admin


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


async def test_scope_entry_update_and_delete(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    added = await client.post(
        f"/versions/{version_id}/scope-entries",
        json={"host": "app.example.test", "port": 443, "in_scope": True},
        headers=admin["headers"],
    )
    entry_id = added.json()["id"]

    updated = await client.patch(
        f"/versions/{version_id}/scope-entries/{entry_id}",
        json={"host": "app-fixed.example.test"},
        headers=admin["headers"],
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["host"] == "app-fixed.example.test"
    assert updated.json()["port"] == 443  # untouched field preserved

    deleted = await client.delete(
        f"/versions/{version_id}/scope-entries/{entry_id}", headers=admin["headers"]
    )
    assert deleted.status_code == 204

    listed = await client.get(f"/versions/{version_id}/scope-entries", headers=admin["headers"])
    assert listed.json() == []


async def test_scope_entry_update_and_delete_404_for_unknown_entry(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    missing_id = "00000000-0000-0000-0000-000000000000"
    updated = await client.patch(
        f"/versions/{version_id}/scope-entries/{missing_id}", json={"host": "x"}, headers=admin["headers"]
    )
    assert updated.status_code == 404
    deleted = await client.delete(
        f"/versions/{version_id}/scope-entries/{missing_id}", headers=admin["headers"]
    )
    assert deleted.status_code == 404
