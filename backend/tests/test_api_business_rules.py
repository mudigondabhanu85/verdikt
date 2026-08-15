from tests.conftest import create_project_and_version, register_org_admin


async def test_create_resource_isolation_rule(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/business-rules",
        json={
            "rule_type": "resource_isolation",
            "title": "A user should never see another user's basket",
            "config": {"url": "http://site.test/rest/basket/6"},
        },
        headers=admin["headers"],
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["rule_type"] == "resource_isolation"
    assert body["config"]["url"] == "http://site.test/rest/basket/6"
    assert body["config"]["method"] == "GET"  # default filled in by config schema


async def test_create_race_condition_rule_with_defaults(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/business-rules",
        json={
            "rule_type": "race_condition_limited_use",
            "title": "A coupon should only be redeemable once",
            "config": {"url": "http://site.test/api/redeem-coupon"},
        },
        headers=admin["headers"],
    )
    assert resp.status_code == 201
    config = resp.json()["config"]
    assert config["method"] == "POST"
    assert config["concurrency"] == 10
    assert config["max_allowed_successes"] == 1


async def test_create_rule_rejects_unknown_rule_type(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/business-rules",
        json={"rule_type": "not_a_real_type", "title": "x", "config": {}},
        headers=admin["headers"],
    )
    assert resp.status_code == 422


async def test_create_rule_rejects_config_missing_required_field(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/business-rules",
        json={
            "rule_type": "resource_isolation",
            "title": "x",
            "config": {},  # missing required "url"
        },
        headers=admin["headers"],
    )
    assert resp.status_code == 422


async def test_list_and_delete_business_rules(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    created = await client.post(
        f"/versions/{version_id}/business-rules",
        json={
            "rule_type": "workflow_order",
            "title": "Order can't complete before payment clears",
            "config": {
                "precondition": {"method": "POST", "url": "http://site.test/checkout/payment"},
                "guarded_action": {"method": "POST", "url": "http://site.test/checkout/complete"},
            },
        },
        headers=admin["headers"],
    )
    assert created.status_code == 201
    rule_id = created.json()["id"]

    listed = await client.get(f"/versions/{version_id}/business-rules", headers=admin["headers"])
    assert listed.status_code == 200
    assert len(listed.json()) == 1

    deleted = await client.delete(f"/versions/{version_id}/business-rules/{rule_id}", headers=admin["headers"])
    assert deleted.status_code == 204

    listed_after = await client.get(f"/versions/{version_id}/business-rules", headers=admin["headers"])
    assert listed_after.json() == []


async def test_business_rules_scoped_to_org(client):
    org_a = await register_org_admin(client, org_name="Org A", email="a@org-a.io")
    org_b = await register_org_admin(client, org_name="Org B", email="b@org-b.io")
    _, version_id = await create_project_and_version(client, org_a["headers"])

    created = await client.post(
        f"/versions/{version_id}/business-rules",
        json={
            "rule_type": "resource_isolation",
            "title": "x",
            "config": {"url": "http://site.test/rest/basket/6"},
        },
        headers=org_a["headers"],
    )
    assert created.status_code == 201

    cross_org = await client.get(f"/versions/{version_id}/business-rules", headers=org_b["headers"])
    assert cross_org.status_code == 404
