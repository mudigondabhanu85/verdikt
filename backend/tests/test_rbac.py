from tests.conftest import create_user_with_role, register_org_admin


async def test_org_admin_can_create_project(client):
    admin = await register_org_admin(client)
    resp = await client.post("/projects", json={"name": "Web App Pentest"}, headers=admin["headers"])
    assert resp.status_code == 201


async def test_viewer_cannot_create_project_but_can_read(client, db_adapter):
    admin = await register_org_admin(client, email="admin2@acme.io")
    me = await client.get("/auth/me", headers=admin["headers"])
    org_id = me.json()["org_id"]

    viewer = await create_user_with_role(db_adapter, org_id=org_id, role="viewer", email="viewer@acme.io")

    denied = await client.post("/projects", json={"name": "X"}, headers=viewer["headers"])
    assert denied.status_code == 403

    allowed = await client.get("/projects", headers=viewer["headers"])
    assert allowed.status_code == 200


async def test_unknown_role_is_denied_everything(client, db_adapter):
    admin = await register_org_admin(client, email="admin3@acme.io")
    me = await client.get("/auth/me", headers=admin["headers"])
    org_id = me.json()["org_id"]

    ghost = await create_user_with_role(db_adapter, org_id=org_id, role="not_a_real_role", email="ghost@acme.io")
    resp = await client.get("/projects", headers=ghost["headers"])
    assert resp.status_code == 403
