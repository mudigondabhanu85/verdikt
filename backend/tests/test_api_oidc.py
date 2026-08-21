import time
from urllib.parse import parse_qs, urlsplit

import pytest

from app.auth.security import decode_access_token
from tests.conftest import register_org_admin
from tests.oidc_fixture_idp import FixtureIdp


@pytest.fixture
def idp():
    fixture = FixtureIdp()
    yield fixture
    fixture.shutdown()


async def _register_oidc_config(client, headers, idp: FixtureIdp, **overrides) -> dict:
    body = {
        "label": "Test IdP",
        "issuer": idp.base_url,
        "client_id": "verdikt-client",
        "client_secret": "super-secret-client-value",
        "redirect_uri": "https://verdikt.example/auth/oidc/callback",
    }
    body.update(overrides)
    resp = await client.post("/oidc-provider-configs", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


async def test_oidc_provider_config_crud_never_returns_plaintext_secret(client, idp):
    admin = await register_org_admin(client)
    created = await _register_oidc_config(client, admin["headers"], idp)
    assert "super-secret-client-value" not in str(created)

    listed = await client.get("/oidc-provider-configs", headers=admin["headers"])
    assert "super-secret-client-value" not in listed.text
    assert len(listed.json()) == 1

    deleted = await client.delete(
        f"/oidc-provider-configs/{created['id']}", headers=admin["headers"]
    )
    assert deleted.status_code == 204


async def test_oidc_login_redirects_to_idp_authorize_endpoint(client, idp):
    admin = await register_org_admin(client)
    config = await _register_oidc_config(client, admin["headers"], idp)

    resp = await client.get(f"/auth/oidc/{config['id']}/login", follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith(f"{idp.base_url}/authorize?")
    query = parse_qs(urlsplit(location).query)
    assert query["client_id"] == ["verdikt-client"]
    assert query["response_type"] == ["code"]
    assert "state" in query


async def test_oidc_callback_provisions_new_user_and_issues_working_token(client, idp):
    admin = await register_org_admin(client)
    config = await _register_oidc_config(client, admin["headers"], idp, default_role="analyst")

    login_resp = await client.get(f"/auth/oidc/{config['id']}/login", follow_redirects=False)
    state = parse_qs(urlsplit(login_resp.headers["location"]).query)["state"][0]

    now = int(time.time())
    code = idp.issue_code(
        {
            "iss": idp.base_url,
            "aud": "verdikt-client",
            "sub": "sso-subject-alice",
            "email": "sso.alice@example.io",
            "iat": now,
            "exp": now + 300,
        }
    )

    callback = await client.get("/auth/oidc/callback", params={"code": code, "state": state})
    assert callback.status_code == 200, callback.text
    token = callback.json()["access_token"]

    # The issued token must actually work against a real authenticated endpoint.
    me = await client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["email"] == "sso.alice@example.io"
    assert me.json()["role"] == "analyst"

    decoded_user_id = decode_access_token(token)
    assert str(decoded_user_id) == me.json()["id"]


async def test_oidc_callback_second_login_reuses_same_user(client, idp):
    admin = await register_org_admin(client)
    config = await _register_oidc_config(client, admin["headers"], idp)

    async def _do_login() -> dict:
        login_resp = await client.get(f"/auth/oidc/{config['id']}/login", follow_redirects=False)
        state = parse_qs(urlsplit(login_resp.headers["location"]).query)["state"][0]
        now = int(time.time())
        code = idp.issue_code(
            {
                "iss": idp.base_url,
                "aud": "verdikt-client",
                "sub": "sso-subject-bob",
                "email": "sso.bob@example.io",
                "iat": now,
                "exp": now + 300,
            }
        )
        resp = await client.get("/auth/oidc/callback", params={"code": code, "state": state})
        assert resp.status_code == 200, resp.text
        return resp.json()

    first = await _do_login()
    second = await _do_login()

    first_user_id = decode_access_token(first["access_token"])
    second_user_id = decode_access_token(second["access_token"])
    assert first_user_id == second_user_id


async def test_oidc_callback_rejects_tampered_state(client, idp):
    admin = await register_org_admin(client)
    await _register_oidc_config(client, admin["headers"], idp)

    resp = await client.get(
        "/auth/oidc/callback", params={"code": "whatever", "state": "not-a-valid-state"}
    )
    assert resp.status_code == 400


async def test_oidc_callback_rejects_email_already_used_in_another_org(client, idp):
    admin_a = await register_org_admin(client, org_name="Org A", email="shared@example.io")
    admin_b = await register_org_admin(client, org_name="Org B", email="admin-b@example.io")
    config_b = await _register_oidc_config(client, admin_b["headers"], idp)

    login_resp = await client.get(f"/auth/oidc/{config_b['id']}/login", follow_redirects=False)
    state = parse_qs(urlsplit(login_resp.headers["location"]).query)["state"][0]

    now = int(time.time())
    code = idp.issue_code(
        {
            "iss": idp.base_url,
            "aud": "verdikt-client",
            "sub": "some-other-subject",
            "email": "shared@example.io",  # already registered under Org A
            "iat": now,
            "exp": now + 300,
        }
    )
    callback = await client.get("/auth/oidc/callback", params={"code": code, "state": state})
    assert callback.status_code == 401
    assert admin_a["email"] == "shared@example.io"
