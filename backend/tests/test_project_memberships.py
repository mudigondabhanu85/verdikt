import uuid

from tests.conftest import create_project_and_version, create_user_with_role, register_org_admin


async def test_org_admin_sees_every_project_with_no_memberships_at_all(client):
    admin = await register_org_admin(client)
    await create_project_and_version(client, admin["headers"], project_name="P1")
    await create_project_and_version(client, admin["headers"], project_name="P2")

    listed = await client.get("/projects", headers=admin["headers"])
    names = {p["name"] for p in listed.json()}
    assert names == {"P1", "P2"}


async def test_restricted_role_with_no_memberships_sees_nothing(client, db_adapter):
    admin = await register_org_admin(client)
    org_id = (await client.get("/auth/me", headers=admin["headers"])).json()["org_id"]
    project_id, _ = await create_project_and_version(client, admin["headers"])
    lead = await create_user_with_role(db_adapter, org_id=org_id, role="project_lead", email="lead@acme.io")

    listed = await client.get("/projects", headers=lead["headers"])
    assert listed.json() == []

    direct = await client.get(f"/projects/{project_id}", headers=lead["headers"])
    assert direct.status_code == 404


async def test_restricted_role_sees_only_assigned_project(client, db_adapter):
    admin = await register_org_admin(client)
    org_id = (await client.get("/auth/me", headers=admin["headers"])).json()["org_id"]
    project_a, _ = await create_project_and_version(client, admin["headers"], project_name="A")
    project_b, _ = await create_project_and_version(client, admin["headers"], project_name="B")
    lead = await create_user_with_role(db_adapter, org_id=org_id, role="project_lead", email="lead2@acme.io")

    assign = await client.put(
        f"/users/{lead['user_id']}/project-memberships",
        json={"project_ids": [project_a]},
        headers=admin["headers"],
    )
    assert assign.status_code == 204

    listed = await client.get("/projects", headers=lead["headers"])
    assert [p["name"] for p in listed.json()] == ["A"]

    allowed = await client.get(f"/projects/{project_a}", headers=lead["headers"])
    assert allowed.status_code == 200

    blocked = await client.get(f"/projects/{project_b}", headers=lead["headers"])
    assert blocked.status_code == 404


async def test_restricted_role_blocked_from_version_and_scope_entries_of_unassigned_project(client, db_adapter):
    admin = await register_org_admin(client)
    org_id = (await client.get("/auth/me", headers=admin["headers"])).json()["org_id"]
    _, version_id = await create_project_and_version(client, admin["headers"])
    analyst = await create_user_with_role(db_adapter, org_id=org_id, role="analyst", email="an@acme.io")

    resp = await client.get(f"/versions/{version_id}/scope-entries", headers=analyst["headers"])
    assert resp.status_code == 404


async def test_replacing_memberships_removes_access_to_the_previously_assigned_project(client, db_adapter):
    admin = await register_org_admin(client)
    org_id = (await client.get("/auth/me", headers=admin["headers"])).json()["org_id"]
    project_a, _ = await create_project_and_version(client, admin["headers"], project_name="A")
    project_b, _ = await create_project_and_version(client, admin["headers"], project_name="B")
    lead = await create_user_with_role(db_adapter, org_id=org_id, role="project_lead", email="lead3@acme.io")

    await client.put(
        f"/users/{lead['user_id']}/project-memberships",
        json={"project_ids": [project_a]},
        headers=admin["headers"],
    )
    await client.put(
        f"/users/{lead['user_id']}/project-memberships",
        json={"project_ids": [project_b]},
        headers=admin["headers"],
    )

    assert (await client.get(f"/projects/{project_a}", headers=lead["headers"])).status_code == 404
    assert (await client.get(f"/projects/{project_b}", headers=lead["headers"])).status_code == 200


async def test_assigning_a_project_from_another_org_is_rejected(client, db_adapter):
    admin_a = await register_org_admin(client, org_name="Org A", email="admina2@a.io")
    admin_b = await register_org_admin(client, org_name="Org B", email="adminb2@b.io")
    org_a_id = (await client.get("/auth/me", headers=admin_a["headers"])).json()["org_id"]
    other_project_id, _ = await create_project_and_version(client, admin_b["headers"])
    lead = await create_user_with_role(db_adapter, org_id=org_a_id, role="project_lead", email="lead4@a.io")

    resp = await client.put(
        f"/users/{lead['user_id']}/project-memberships",
        json={"project_ids": [other_project_id]},
        headers=admin_a["headers"],
    )
    assert resp.status_code == 400


async def test_project_memberships_update_requires_user_update_permission(client, db_adapter):
    admin = await register_org_admin(client)
    org_id = (await client.get("/auth/me", headers=admin["headers"])).json()["org_id"]
    project_id, _ = await create_project_and_version(client, admin["headers"])
    viewer = await create_user_with_role(db_adapter, org_id=org_id, role="viewer", email="viewer2@acme.io")
    target = await create_user_with_role(db_adapter, org_id=org_id, role="analyst", email="target@acme.io")

    resp = await client.put(
        f"/users/{target['user_id']}/project-memberships",
        json={"project_ids": [project_id]},
        headers=viewer["headers"],
    )
    assert resp.status_code == 403


async def test_dashboard_totals_reflect_only_assigned_projects(client, db_adapter):
    admin = await register_org_admin(client)
    org_id = (await client.get("/auth/me", headers=admin["headers"])).json()["org_id"]
    project_a, _ = await create_project_and_version(client, admin["headers"], project_name="A")
    await create_project_and_version(client, admin["headers"], project_name="B")
    lead = await create_user_with_role(db_adapter, org_id=org_id, role="project_lead", email="lead5@acme.io")
    await client.put(
        f"/users/{lead['user_id']}/project-memberships",
        json={"project_ids": [project_a]},
        headers=admin["headers"],
    )

    dash = await client.get("/organizations/me/dashboard", headers=lead["headers"])
    assert dash.status_code == 200
    assert dash.json()["total_projects"] == 1


async def test_project_memberships_update_404s_for_unknown_user(client):
    admin = await register_org_admin(client)
    missing_id = uuid.uuid4()
    resp = await client.put(
        f"/users/{missing_id}/project-memberships",
        json={"project_ids": []},
        headers=admin["headers"],
    )
    assert resp.status_code == 404
