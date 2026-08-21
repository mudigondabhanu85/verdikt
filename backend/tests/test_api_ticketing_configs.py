from tests.conftest import register_org_admin


async def test_ticketing_config_crud_never_returns_plaintext_token(client):
    admin = await register_org_admin(client)

    created = await client.post(
        "/ticketing-configs",
        json={
            "label": "Security Jira",
            "provider": "jira",
            "base_url": "https://acme.atlassian.net",
            "email": "analyst@acme.io",
            "api_token": "super-secret-token-value",
            "project_key": "SEC",
        },
        headers=admin["headers"],
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert "super-secret-token-value" not in created.text
    assert body["issue_type"] == "Task"
    assert body["project_key"] == "SEC"

    listed = await client.get("/ticketing-configs", headers=admin["headers"])
    assert "super-secret-token-value" not in listed.text
    assert len(listed.json()) == 1

    deleted = await client.delete(f"/ticketing-configs/{body['id']}", headers=admin["headers"])
    assert deleted.status_code == 204

    listed_after = await client.get("/ticketing-configs", headers=admin["headers"])
    assert listed_after.json() == []


async def test_unknown_provider_type_rejected(client):
    admin = await register_org_admin(client)
    resp = await client.post(
        "/ticketing-configs",
        json={
            "label": "x",
            "provider": "github-issues",
            "base_url": "https://example.test",
            "email": "a@b.io",
            "api_token": "tok",
            "project_key": "SEC",
        },
        headers=admin["headers"],
    )
    assert resp.status_code == 422
