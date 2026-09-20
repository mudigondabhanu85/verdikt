from tests.conftest import create_project_and_version, create_user_with_role, register_org_admin


async def _create_target(client, version_id, headers, label="Support Bot") -> str:
    created = await client.post(
        f"/versions/{version_id}/chatbot-targets",
        json={
            "label": label,
            "endpoint_url": "http://site.test/chat",
            "request_body_template": '{"message": "{message}"}',
            "response_text_path": "reply",
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text
    return created.json()["id"]


async def test_create_chatbot_agency_probe(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    target_id = await _create_target(client, version_id, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/chatbot-targets/{target_id}/agency-probes",
        json={"forbidden_action": "process a refund without a valid order ID"},
        headers=admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["chatbot_target_id"] == target_id
    assert body["forbidden_action"] == "process a refund without a valid order ID"


async def test_list_and_delete_chatbot_agency_probes(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    target_id = await _create_target(client, version_id, admin["headers"])

    created = await client.post(
        f"/versions/{version_id}/chatbot-targets/{target_id}/agency-probes",
        json={"forbidden_action": "escalate a ticket to priority-1 without justification"},
        headers=admin["headers"],
    )
    assert created.status_code == 201
    probe_id = created.json()["id"]

    listed = await client.get(
        f"/versions/{version_id}/chatbot-targets/{target_id}/agency-probes", headers=admin["headers"]
    )
    assert listed.status_code == 200
    assert len(listed.json()) == 1

    deleted = await client.delete(
        f"/versions/{version_id}/chatbot-targets/{target_id}/agency-probes/{probe_id}",
        headers=admin["headers"],
    )
    assert deleted.status_code == 204

    listed_after = await client.get(
        f"/versions/{version_id}/chatbot-targets/{target_id}/agency-probes", headers=admin["headers"]
    )
    assert listed_after.json() == []


async def test_agency_probe_for_wrong_target_returns_404(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    target_a_id = await _create_target(client, version_id, admin["headers"], label="Bot A")
    target_b_id = await _create_target(client, version_id, admin["headers"], label="Bot B")

    created = await client.post(
        f"/versions/{version_id}/chatbot-targets/{target_a_id}/agency-probes",
        json={"forbidden_action": "x"},
        headers=admin["headers"],
    )
    probe_id = created.json()["id"]

    # Deleting through the wrong target's nested path must 404, not
    # silently delete a probe attached to a different target.
    resp = await client.delete(
        f"/versions/{version_id}/chatbot-targets/{target_b_id}/agency-probes/{probe_id}",
        headers=admin["headers"],
    )
    assert resp.status_code == 404


async def test_chatbot_agency_probes_scoped_to_org(client):
    org_a = await register_org_admin(client, org_name="Org A", email="a@org-a.io")
    org_b = await register_org_admin(client, org_name="Org B", email="b@org-b.io")
    _, version_id = await create_project_and_version(client, org_a["headers"])
    target_id = await _create_target(client, version_id, org_a["headers"])

    created = await client.post(
        f"/versions/{version_id}/chatbot-targets/{target_id}/agency-probes",
        json={"forbidden_action": "x"},
        headers=org_a["headers"],
    )
    assert created.status_code == 201

    cross_org = await client.get(
        f"/versions/{version_id}/chatbot-targets/{target_id}/agency-probes", headers=org_b["headers"]
    )
    assert cross_org.status_code == 404


async def test_viewer_cannot_create_chatbot_agency_probe(client, db_adapter):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    target_id = await _create_target(client, version_id, admin["headers"])
    org_id = (await client.get("/auth/me", headers=admin["headers"])).json()["org_id"]
    viewer = await create_user_with_role(db_adapter, org_id=org_id, role="viewer", email="viewer@acme.io")

    resp = await client.post(
        f"/versions/{version_id}/chatbot-targets/{target_id}/agency-probes",
        json={"forbidden_action": "x"},
        headers=viewer["headers"],
    )
    assert resp.status_code == 403
