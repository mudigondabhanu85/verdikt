from tests.conftest import create_project_and_version, register_org_admin


async def test_create_list_and_use_api_key(client):
    admin = await register_org_admin(client)

    created = await client.post("/api-keys", json={"label": "CI pipeline"}, headers=admin["headers"])
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["api_key"].startswith("vdk_")
    assert body["key_prefix"] == body["api_key"][:12]

    listed = await client.get("/api-keys", headers=admin["headers"])
    assert listed.status_code == 200
    listed_body = listed.json()
    assert len(listed_body) == 1
    # The raw key must never be echoed back anywhere except the creation response.
    assert body["api_key"] not in listed.text
    assert listed_body[0]["key_prefix"] == body["key_prefix"]
    assert listed_body[0]["revoked_at"] is None
    assert listed_body[0]["last_used_at"] is None

    # The key itself must work as a bearer credential against a real
    # protected, RBAC-gated endpoint (same role/permissions as the user).
    api_key_headers = {"Authorization": f"Bearer {body['api_key']}"}
    me = await client.get("/auth/me", headers=api_key_headers)
    assert me.status_code == 200
    assert me.json()["email"] == admin["email"]

    _, version_id = await create_project_and_version(client, api_key_headers)
    assert version_id

    # last_used_at should now be populated.
    listed_after_use = (await client.get("/api-keys", headers=admin["headers"])).json()
    assert listed_after_use[0]["last_used_at"] is not None


async def test_revoked_api_key_stops_working(client):
    admin = await register_org_admin(client)

    created = (
        await client.post("/api-keys", json={"label": "temp key"}, headers=admin["headers"])
    ).json()
    api_key_headers = {"Authorization": f"Bearer {created['api_key']}"}

    still_works = await client.get("/auth/me", headers=api_key_headers)
    assert still_works.status_code == 200

    revoked = await client.post(f"/api-keys/{created['id']}/revoke", headers=admin["headers"])
    assert revoked.status_code == 200
    assert revoked.json()["revoked_at"] is not None

    now_rejected = await client.get("/auth/me", headers=api_key_headers)
    assert now_rejected.status_code == 401


async def test_invalid_api_key_is_rejected(client):
    resp = await client.get("/auth/me", headers={"Authorization": "Bearer vdk_totally-made-up"})
    assert resp.status_code == 401


async def test_user_cannot_revoke_another_users_api_key(client, db_adapter):
    from tests.conftest import create_user_with_role

    admin = await register_org_admin(client)
    created = (
        await client.post("/api-keys", json={"label": "admin key"}, headers=admin["headers"])
    ).json()

    org_id = (await client.get("/organizations/me", headers=admin["headers"])).json()["id"]
    other = await create_user_with_role(db_adapter, org_id=org_id, role="analyst", email="analyst@example.io")

    resp = await client.post(f"/api-keys/{created['id']}/revoke", headers=other["headers"])
    assert resp.status_code == 403


async def test_org_admin_can_revoke_teammates_api_key(client, db_adapter):
    from tests.conftest import create_user_with_role

    admin = await register_org_admin(client)
    org_id = (await client.get("/organizations/me", headers=admin["headers"])).json()["id"]
    analyst = await create_user_with_role(
        db_adapter, org_id=org_id, role="analyst", email="analyst2@example.io"
    )

    created = (
        await client.post("/api-keys", json={"label": "analyst key"}, headers=analyst["headers"])
    ).json()

    resp = await client.post(f"/api-keys/{created['id']}/revoke", headers=admin["headers"])
    assert resp.status_code == 200
    assert resp.json()["revoked_at"] is not None
