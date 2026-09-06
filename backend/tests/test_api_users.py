from tests.conftest import create_user_with_role, register_org_admin


async def test_invite_creates_pending_user_and_token_can_accept_and_login(client):
    admin = await register_org_admin(client)

    invited = await client.post(
        "/users/invite",
        json={"email": "newhire@acme.io", "role": "analyst"},
        headers=admin["headers"],
    )
    assert invited.status_code == 201, invited.text
    body = invited.json()
    assert body["email"] == "newhire@acme.io"
    assert body["role"] == "analyst"
    invite_token = body["invite_token"]
    assert invite_token

    listed = await client.get("/users", headers=admin["headers"])
    assert listed.status_code == 200
    assert invite_token not in listed.text  # never re-displayed
    pending = next(u for u in listed.json() if u["email"] == "newhire@acme.io")
    assert pending["is_active"] is True
    assert pending["invite_accepted_at"] is None

    accepted = await client.post(
        "/users/accept-invite", json={"invite_token": invite_token, "password": "new-hire-password-123"}
    )
    assert accepted.status_code == 200, accepted.text
    assert "access_token" in accepted.json()

    logged_in = await client.post(
        "/auth/login", json={"email": "newhire@acme.io", "password": "new-hire-password-123"}
    )
    assert logged_in.status_code == 200

    reused = await client.post(
        "/users/accept-invite", json={"invite_token": invite_token, "password": "whatever"}
    )
    assert reused.status_code == 404


async def test_invite_rejects_duplicate_email(client):
    admin = await register_org_admin(client)
    await client.post("/users/invite", json={"email": "dup@acme.io", "role": "analyst"}, headers=admin["headers"])
    resp = await client.post("/users/invite", json={"email": "dup@acme.io", "role": "viewer"}, headers=admin["headers"])
    assert resp.status_code == 409


async def test_invite_rejects_unknown_role(client):
    admin = await register_org_admin(client)
    resp = await client.post(
        "/users/invite", json={"email": "x@acme.io", "role": "superuser"}, headers=admin["headers"]
    )
    assert resp.status_code == 400


async def test_deactivate_blocks_login_and_reactivate_restores_it(client, db_adapter):
    admin = await register_org_admin(client)
    org_id = (await client.get("/auth/me", headers=admin["headers"])).json()["org_id"]
    analyst = await create_user_with_role(db_adapter, org_id=org_id, role="analyst", email="a@acme.io")

    deactivated = await client.post(f"/users/{analyst['user_id']}/deactivate", headers=admin["headers"])
    assert deactivated.status_code == 204

    login_attempt = await client.post("/auth/login", json={"email": "a@acme.io", "password": "irrelevant"})
    assert login_attempt.status_code == 401

    reactivated = await client.post(f"/users/{analyst['user_id']}/reactivate", headers=admin["headers"])
    assert reactivated.status_code == 204

    users = await client.get("/users", headers=admin["headers"])
    matching = next(u for u in users.json() if str(u["id"]) == str(analyst["user_id"]))
    assert matching["is_active"] is True


async def test_cannot_deactivate_last_active_org_admin(client):
    admin = await register_org_admin(client)
    me = await client.get("/auth/me", headers=admin["headers"])
    admin_id = me.json()["id"]

    resp = await client.post(f"/users/{admin_id}/deactivate", headers=admin["headers"])
    assert resp.status_code == 400


async def test_deactivate_allowed_when_another_admin_remains(client, db_adapter):
    admin = await register_org_admin(client)
    org_id = (await client.get("/auth/me", headers=admin["headers"])).json()["org_id"]
    second_admin = await create_user_with_role(db_adapter, org_id=org_id, role="org_admin", email="second@acme.io")

    resp = await client.post(f"/users/{second_admin['user_id']}/deactivate", headers=admin["headers"])
    assert resp.status_code == 204


async def test_users_are_org_scoped(client, db_adapter):
    admin_a = await register_org_admin(client, org_name="Org A", email="admina@a.io")
    admin_b = await register_org_admin(client, org_name="Org B", email="adminb@b.io")
    org_b_id = (await client.get("/auth/me", headers=admin_b["headers"])).json()["org_id"]
    b_user = await create_user_with_role(db_adapter, org_id=org_b_id, role="analyst", email="banalyst@b.io")

    listed_by_a = await client.get("/users", headers=admin_a["headers"])
    assert "banalyst@b.io" not in listed_by_a.text

    cross_org_deactivate = await client.post(
        f"/users/{b_user['user_id']}/deactivate", headers=admin_a["headers"]
    )
    assert cross_org_deactivate.status_code == 404


async def test_invite_requires_user_create_permission(client, db_adapter):
    admin = await register_org_admin(client)
    org_id = (await client.get("/auth/me", headers=admin["headers"])).json()["org_id"]
    viewer = await create_user_with_role(db_adapter, org_id=org_id, role="viewer", email="viewer@acme.io")

    resp = await client.post(
        "/users/invite", json={"email": "blocked@acme.io", "role": "analyst"}, headers=viewer["headers"]
    )
    assert resp.status_code == 403
