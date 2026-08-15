from tests.conftest import create_project_and_version, register_org_admin


async def test_target_crud(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    added = await client.post(
        f"/versions/{version_id}/targets",
        json={"host": "app.example.test", "port": 443, "base_url": "https://app.example.test"},
        headers=admin["headers"],
    )
    assert added.status_code == 201
    target_id = added.json()["id"]

    listed = await client.get(f"/versions/{version_id}/targets", headers=admin["headers"])
    assert len(listed.json()) == 1

    deleted = await client.delete(f"/versions/{version_id}/targets/{target_id}", headers=admin["headers"])
    assert deleted.status_code == 204

    listed_after = await client.get(f"/versions/{version_id}/targets", headers=admin["headers"])
    assert len(listed_after.json()) == 0


async def test_credential_set_never_returns_plaintext_secret(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/credentials",
        json={
            "label": "Admin",
            "credential_type": "username_password",
            "username": "alice",
            "secret": "hunter2-super-secret",
        },
        headers=admin["headers"],
    )
    assert resp.status_code == 201
    body = resp.json()
    assert "hunter2-super-secret" not in resp.text
    assert body["masked_reference"].startswith("alice")

    listed = await client.get(f"/versions/{version_id}/credentials", headers=admin["headers"])
    assert "hunter2-super-secret" not in listed.text
    assert len(listed.json()) == 1

    deleted = await client.delete(
        f"/versions/{version_id}/credentials/{body['id']}", headers=admin["headers"]
    )
    assert deleted.status_code == 204
