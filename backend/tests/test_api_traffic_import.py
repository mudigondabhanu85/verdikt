from pathlib import Path

from tests.conftest import create_project_and_version, register_org_admin

FIXTURE = Path(__file__).parent / "fixtures" / "sample.har"


async def test_import_har_persists_interactions(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    with open(FIXTURE, "rb") as f:
        resp = await client.post(
            f"/versions/{version_id}/traffic/import",
            files={"file": ("sample.har", f, "application/json")},
            headers=admin["headers"],
        )
    assert resp.status_code == 201
    body = resp.json()
    assert body["imported_count"] == 2
    assert len(body["interaction_ids"]) == 2

    listed = await client.get(f"/versions/{version_id}/traffic", headers=admin["headers"])
    assert listed.status_code == 200
    interactions = listed.json()
    assert len(interactions) == 2

    by_method = {i["request"]["method"]: i for i in interactions}
    get_one = by_method["GET"]
    assert get_one["request"]["query_params"] == {"lang": "en"}
    assert get_one["response"]["status"] == 200
    assert get_one["source"] == "har"

    post_one = by_method["POST"]
    assert "a@a.com" in post_one["request"]["body"]


async def test_rejects_non_har_upload(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/traffic/import",
        files={"file": ("notes.txt", b"not a har file", "text/plain")},
        headers=admin["headers"],
    )
    assert resp.status_code == 400


async def test_rejects_malformed_har(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/traffic/import",
        files={"file": ("broken.har", b"{not valid json", "application/json")},
        headers=admin["headers"],
    )
    assert resp.status_code == 400
