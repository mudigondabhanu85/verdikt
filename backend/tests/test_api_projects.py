from tests.conftest import register_org_admin


async def test_create_list_get_project(client):
    admin = await register_org_admin(client)

    created = await client.post("/projects", json={"name": "Web App Pentest"}, headers=admin["headers"])
    assert created.status_code == 201
    project = created.json()
    assert project["name"] == "Web App Pentest"

    listed = await client.get("/projects", headers=admin["headers"])
    assert listed.status_code == 200
    assert any(p["id"] == project["id"] for p in listed.json())

    fetched = await client.get(f"/projects/{project['id']}", headers=admin["headers"])
    assert fetched.status_code == 200
    assert fetched.json()["id"] == project["id"]


async def test_project_is_scoped_to_org(client):
    org_a = await register_org_admin(client, org_name="Org A", email="a@org-a.io")
    org_b = await register_org_admin(client, org_name="Org B", email="b@org-b.io")

    created = await client.post("/projects", json={"name": "Org A Project"}, headers=org_a["headers"])
    project_id = created.json()["id"]

    cross_org = await client.get(f"/projects/{project_id}", headers=org_b["headers"])
    assert cross_org.status_code == 404
