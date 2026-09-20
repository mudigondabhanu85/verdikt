from tests.conftest import create_project_and_version, create_user_with_role, register_org_admin


async def test_create_chatbot_target(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/chatbot-targets",
        json={
            "label": "Support Bot",
            "endpoint_url": "http://site.test/chat",
            "http_method": "POST",
            "request_body_template": '{"message": "{message}", "session_id": "verdikt-probe"}',
            "content_type": "application/json",
            "response_text_path": "reply",
        },
        headers=admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["label"] == "Support Bot"
    assert body["endpoint_url"] == "http://site.test/chat"
    assert body["http_method"] == "POST"
    assert body["auth_header_name"] is None
    assert body["masked_reference"] is None


async def test_create_chatbot_target_rejects_missing_message_placeholder(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/chatbot-targets",
        json={
            "label": "Support Bot",
            "endpoint_url": "http://site.test/chat",
            "request_body_template": '{"text": "hello"}',  # no {message} placeholder
            "response_text_path": "reply",
        },
        headers=admin["headers"],
    )
    assert resp.status_code == 422


async def test_chatbot_target_with_auth_header_never_returns_plaintext_secret(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    created = await client.post(
        f"/versions/{version_id}/chatbot-targets",
        json={
            "label": "Internal Bot",
            "endpoint_url": "http://site.test/chat",
            "request_body_template": '{"message": "{message}"}',
            "response_text_path": "reply",
            "auth_header_name": "Authorization",
            "auth_header_value": "Bearer SUPER_SECRET_TOKEN",
        },
        headers=admin["headers"],
    )
    assert created.status_code == 201, created.text
    assert "SUPER_SECRET_TOKEN" not in created.text
    body = created.json()
    assert body["auth_header_name"] == "Authorization"
    assert body["masked_reference"] is not None

    listed = await client.get(f"/versions/{version_id}/chatbot-targets", headers=admin["headers"])
    assert "SUPER_SECRET_TOKEN" not in listed.text


async def test_list_and_delete_chatbot_targets(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    created = await client.post(
        f"/versions/{version_id}/chatbot-targets",
        json={
            "label": "Support Bot",
            "endpoint_url": "http://site.test/chat",
            "request_body_template": '{"message": "{message}"}',
            "response_text_path": "reply",
        },
        headers=admin["headers"],
    )
    assert created.status_code == 201
    target_id = created.json()["id"]

    listed = await client.get(f"/versions/{version_id}/chatbot-targets", headers=admin["headers"])
    assert listed.status_code == 200
    assert len(listed.json()) == 1

    deleted = await client.delete(
        f"/versions/{version_id}/chatbot-targets/{target_id}", headers=admin["headers"]
    )
    assert deleted.status_code == 204

    listed_after = await client.get(f"/versions/{version_id}/chatbot-targets", headers=admin["headers"])
    assert listed_after.json() == []


async def test_chatbot_targets_scoped_to_org(client):
    org_a = await register_org_admin(client, org_name="Org A", email="a@org-a.io")
    org_b = await register_org_admin(client, org_name="Org B", email="b@org-b.io")
    _, version_id = await create_project_and_version(client, org_a["headers"])

    created = await client.post(
        f"/versions/{version_id}/chatbot-targets",
        json={
            "label": "Support Bot",
            "endpoint_url": "http://site.test/chat",
            "request_body_template": '{"message": "{message}"}',
            "response_text_path": "reply",
        },
        headers=org_a["headers"],
    )
    assert created.status_code == 201

    cross_org = await client.get(f"/versions/{version_id}/chatbot-targets", headers=org_b["headers"])
    assert cross_org.status_code == 404


async def test_viewer_cannot_create_chatbot_target(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    org_id = (await client.get("/auth/me", headers=admin["headers"])).json()["org_id"]
    viewer = await create_user_with_role(db_adapter, org_id=org_id, role="viewer", email="viewer@acme.io")

    resp = await client.post(
        f"/versions/{version_id}/chatbot-targets",
        json={
            "label": "Support Bot",
            "endpoint_url": "http://site.test/chat",
            "request_body_template": '{"message": "{message}"}',
            "response_text_path": "reply",
        },
        headers=viewer["headers"],
    )
    assert resp.status_code == 403
