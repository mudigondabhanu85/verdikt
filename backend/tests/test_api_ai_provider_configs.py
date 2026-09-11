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


async def test_spark_bearer_token_mode_falls_back_to_deployment_app_id(client):
    # Every Spark request needs an app_id (re-confirmed 2026-09 directly
    # against sparkapi.spglobal.com — a raw curl with no app_id path
    # segment got "app_id: <garbage> is not valid" instead of
    # succeeding), but it's a deployment-wide constant (SPARK_APP_ID)
    # this org falls back to automatically — see
    # app.ai.provider.build_adapter_from_config — same pattern as
    # base_url falling back to SPARK_BASE_URL. Not setting one here is
    # the common case, not an error.
    admin = await register_org_admin(client)

    created = await client.post(
        "/ai-provider-configs",
        json={
            "label": "Spark",
            "provider": "spark",
            "model": "gpt-4o-mini",
            "api_key": "test-bearer-token",
            "auth_type": "bearer_token",
        },
        headers=admin["headers"],
    )
    assert created.status_code == 201, created.text
    assert created.json()["app_id"] is None


async def test_spark_bearer_token_mode_can_override_app_id_per_org(client):
    admin = await register_org_admin(client)

    created = await client.post(
        "/ai-provider-configs",
        json={
            "label": "Spark",
            "provider": "spark",
            "model": "gpt-4o-mini",
            "api_key": "test-bearer-token",
            "auth_type": "bearer_token",
            "app_id": "SPGCKDPE99C",
        },
        headers=admin["headers"],
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["app_id"] == "SPGCKDPE99C"
    assert body["has_secondary_api_key"] is False


async def test_spark_api_key_mode_also_falls_back_to_deployment_app_id(client):
    # api_key mode has no different requirement here than bearer_token —
    # dast-automation's SparkConfig uses the identical deployment-wide
    # default_app_id for both, with no auth-mode branch at all.
    admin = await register_org_admin(client)

    created = await client.post(
        "/ai-provider-configs",
        json={
            "label": "Spark",
            "provider": "spark",
            "model": "gpt-4o-mini",
            "api_key": "primary-key",
            "auth_type": "api_key",
        },
        headers=admin["headers"],
    )
    assert created.status_code == 201, created.text
    assert created.json()["app_id"] is None


async def test_spark_api_key_mode_with_secondary_key(client):
    admin = await register_org_admin(client)

    created = await client.post(
        "/ai-provider-configs",
        json={
            "label": "Spark",
            "provider": "spark",
            "model": "gpt-4o-mini",
            "api_key": "primary-key",
            "auth_type": "api_key",
            "app_id": "SPGCKDPE99C",
            "secondary_api_key": "secondary-key",
        },
        headers=admin["headers"],
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["app_id"] == "SPGCKDPE99C"
    assert body["has_secondary_api_key"] is True
    assert "secondary-key" not in created.text
    assert "primary-key" not in created.text


async def test_unknown_provider_type_rejected(client):
    admin = await register_org_admin(client)

    resp = await client.post(
        "/ai-provider-configs",
        json={"label": "Bogus", "provider": "cursor", "model": "x", "api_key": "k"},
        headers=admin["headers"],
    )
    assert resp.status_code == 422


async def test_rotate_secret_preserves_default_and_updates_masked_reference(client):
    admin = await register_org_admin(client)

    created = await client.post(
        "/ai-provider-configs",
        json={
            "label": "Spark",
            "provider": "spark",
            "model": "gpt-4o-mini",
            "api_key": "old-bearer-token",
            "auth_type": "bearer_token",
            "app_id": "SPGCKDPE99C",
        },
        headers=admin["headers"],
    )
    assert created.status_code == 201, created.text
    config_id = created.json()["id"]

    default_resp = await client.post(
        f"/ai-provider-configs/{config_id}/set-default", headers=admin["headers"]
    )
    assert default_resp.status_code == 200
    assert default_resp.json()["is_default"] is True

    rotated = await client.post(
        f"/ai-provider-configs/{config_id}/rotate-secret",
        json={"api_key": "new-bearer-token"},
        headers=admin["headers"],
    )
    assert rotated.status_code == 200, rotated.text
    body = rotated.json()
    assert "old-bearer-token" not in rotated.text
    assert "new-bearer-token" not in rotated.text
    assert body["masked_reference"].endswith("oken")
    # label/provider/model/is_default all untouched by a secret-only rotation.
    assert body["is_default"] is True
    assert body["label"] == "Spark"
    assert body["provider"] == "spark"


async def test_rotate_secret_fixes_a_wrong_app_id(client):
    # Real incident this guards against: "openai" typed into App ID
    # instead of the actual Spark App ID (Spark's model names look like
    # OpenAI's, e.g. gpt-4o-mini, which is an easy mix-up) — should be
    # fixable without a full delete-and-recreate.
    admin = await register_org_admin(client)

    created = await client.post(
        "/ai-provider-configs",
        json={
            "label": "Spark",
            "provider": "spark",
            "model": "gpt-4o-mini",
            "api_key": "primary-key",
            "auth_type": "api_key",
            "app_id": "openai",
        },
        headers=admin["headers"],
    )
    assert created.status_code == 201, created.text
    config_id = created.json()["id"]
    assert created.json()["app_id"] == "openai"

    rotated = await client.post(
        f"/ai-provider-configs/{config_id}/rotate-secret",
        json={"app_id": "SPGCKDPE99C"},
        headers=admin["headers"],
    )
    assert rotated.status_code == 200, rotated.text
    body = rotated.json()
    assert body["app_id"] == "SPGCKDPE99C"
    # api_key-only fields untouched by an app_id-only rotation.
    assert body["masked_reference"].endswith("-key")


async def test_rotate_secret_rejects_other_orgs_config(client):
    admin_a = await register_org_admin(client, org_name="Org A", email="admin-a@acme.io")
    admin_b = await register_org_admin(client, org_name="Org B", email="admin-b@acme.io")

    config = await _create_config(client, admin_a["headers"], "Org A's config")

    resp = await client.post(
        f"/ai-provider-configs/{config['id']}/rotate-secret",
        json={"api_key": "hijacked-key"},
        headers=admin_b["headers"],
    )
    assert resp.status_code == 404


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
