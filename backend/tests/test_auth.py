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
