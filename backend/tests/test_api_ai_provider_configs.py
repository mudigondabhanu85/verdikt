from tests.conftest import register_org_admin


async def test_ai_provider_config_crud_never_returns_plaintext_key(client):
    admin = await register_org_admin(client)

    created = await client.post(
        "/ai-provider-configs",
        json={
            "label": "In-house Llama",
            "provider": "custom",
            "model": "llama3.1:8b",
            "api_key": "sk-super-secret-value",
            "base_url": "http://localhost:11434/v1",
        },
        headers=admin["headers"],
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert "sk-super-secret-value" not in created.text
    assert body["masked_reference"].endswith("alue")
    assert body["provider"] == "custom"
    assert body["base_url"] == "http://localhost:11434/v1"

    listed = await client.get("/ai-provider-configs", headers=admin["headers"])
    assert listed.status_code == 200
    assert "sk-super-secret-value" not in listed.text
    assert len(listed.json()) == 1

    deleted = await client.delete(f"/ai-provider-configs/{body['id']}", headers=admin["headers"])
    assert deleted.status_code == 204

    listed_after = await client.get("/ai-provider-configs", headers=admin["headers"])
    assert len(listed_after.json()) == 0


async def test_custom_provider_requires_base_url(client):
    admin = await register_org_admin(client)

    resp = await client.post(
        "/ai-provider-configs",
        json={"label": "Missing base url", "provider": "custom", "model": "x", "api_key": "k"},
        headers=admin["headers"],
    )
    assert resp.status_code == 422


async def test_unknown_provider_type_rejected(client):
    admin = await register_org_admin(client)

    resp = await client.post(
        "/ai-provider-configs",
        json={"label": "Bogus", "provider": "cursor", "model": "x", "api_key": "k"},
        headers=admin["headers"],
    )
    assert resp.status_code == 422
