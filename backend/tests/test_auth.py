from tests.conftest import register_org_admin


async def test_register_creates_org_admin_and_returns_token(client):
    session = await register_org_admin(client)

    resp = await client.get("/auth/me", headers=session["headers"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["email"] == session["email"]
    assert body["role"] == "org_admin"
    assert body["is_active"] is True


async def test_register_duplicate_email_rejected(client):
    await register_org_admin(client, email="dupe@acme.io")
    resp = await client.post(
        "/auth/register",
        json={"org_name": "Other Org", "email": "dupe@acme.io", "password": "whatever123"},
    )
    assert resp.status_code == 400


async def test_login_success(client):
    session = await register_org_admin(client, email="login@acme.io", password="s3cret-pass")
    resp = await client.post(
        "/auth/login", json={"email": "login@acme.io", "password": "s3cret-pass"}
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()


async def test_login_wrong_password_rejected(client):
    await register_org_admin(client, email="wrongpw@acme.io", password="s3cret-pass")
    resp = await client.post(
        "/auth/login", json={"email": "wrongpw@acme.io", "password": "not-it"}
    )
    assert resp.status_code == 401


async def test_me_requires_bearer_token(client):
    resp = await client.get("/auth/me")
    assert resp.status_code == 401


async def test_change_password_then_login_with_the_new_one(client):
    session = await register_org_admin(client, email="changer@acme.io", password="old-password-123")
    resp = await client.post(
        "/auth/change-password",
        json={"current_password": "old-password-123", "new_password": "new-password-456"},
        headers=session["headers"],
    )
    assert resp.status_code == 204

    old_login = await client.post(
        "/auth/login", json={"email": "changer@acme.io", "password": "old-password-123"}
    )
    assert old_login.status_code == 401

    new_login = await client.post(
        "/auth/login", json={"email": "changer@acme.io", "password": "new-password-456"}
    )
    assert new_login.status_code == 200


async def test_change_password_rejects_a_wrong_current_password(client):
    session = await register_org_admin(client, email="wrongcur@acme.io", password="real-password-123")
    resp = await client.post(
        "/auth/change-password",
        json={"current_password": "not-the-real-one", "new_password": "new-password-456"},
        headers=session["headers"],
    )
    assert resp.status_code == 401

    # The password on file must be unchanged after a rejected attempt.
    login = await client.post(
        "/auth/login", json={"email": "wrongcur@acme.io", "password": "real-password-123"}
    )
    assert login.status_code == 200


async def test_change_password_rejects_a_too_short_new_password(client):
    session = await register_org_admin(client, email="shortpw@acme.io", password="real-password-123")
    resp = await client.post(
        "/auth/change-password",
        json={"current_password": "real-password-123", "new_password": "short"},
        headers=session["headers"],
    )
    assert resp.status_code == 422


async def test_change_password_requires_a_bearer_token(client):
    resp = await client.post(
        "/auth/change-password",
        json={"current_password": "whatever", "new_password": "new-password-456"},
    )
    assert resp.status_code == 401
