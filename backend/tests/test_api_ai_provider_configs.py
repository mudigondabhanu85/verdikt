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


async def _create_config(client, headers, label: str):
    created = await client.post(
        "/ai-provider-configs",
        json={
            "label": label,
            "provider": "custom",
            "model": "llama3.1:8b",
            "api_key": "sk-secret",
            "base_url": "http://localhost:11434/v1",
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text
    return created.json()


async def test_new_config_is_not_default_by_default(client):
    admin = await register_org_admin(client)
    config = await _create_config(client, admin["headers"], "In-house")
    assert config["is_default"] is False


async def test_set_default_marks_it_and_unmarks_the_previous_default(client):
    admin = await register_org_admin(client)
    first = await _create_config(client, admin["headers"], "First")
    second = await _create_config(client, admin["headers"], "Second")

    set_first = await client.post(f"/ai-provider-configs/{first['id']}/set-default", headers=admin["headers"])
    assert set_first.status_code == 200, set_first.text
    assert set_first.json()["is_default"] is True

    listed = await client.get("/ai-provider-configs", headers=admin["headers"])
    by_id = {c["id"]: c["is_default"] for c in listed.json()}
    assert by_id[first["id"]] is True
    assert by_id[second["id"]] is False

    # Switching the default unmarks the previous one — never two defaults at once.
    set_second = await client.post(f"/ai-provider-configs/{second['id']}/set-default", headers=admin["headers"])
    assert set_second.status_code == 200
    listed_again = await client.get("/ai-provider-configs", headers=admin["headers"])
    by_id_again = {c["id"]: c["is_default"] for c in listed_again.json()}
    assert by_id_again[first["id"]] is False
    assert by_id_again[second["id"]] is True


async def test_set_default_404_for_another_orgs_config(client):
    admin_a = await register_org_admin(client, org_name="Org A", email="a@example.com")
    admin_b = await register_org_admin(client, org_name="Org B", email="b@example.com")
    config_a = await _create_config(client, admin_a["headers"], "Org A's config")

    resp = await client.post(
        f"/ai-provider-configs/{config_a['id']}/set-default", headers=admin_b["headers"]
    )
    assert resp.status_code == 404
