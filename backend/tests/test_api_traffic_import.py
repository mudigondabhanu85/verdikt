import json
from pathlib import Path

import zstandard

from tests.conftest import create_project_and_version, register_org_admin

FIXTURE = Path(__file__).parent / "fixtures" / "sample.har"

_SAMPLE_ZEST_SCRIPT = {
    "zestVersion": "0.8",
    "title": "Minimal script",
    "type": "StandAlone",
    "statements": [
        {
            "elementType": "ZestRequest",
            "url": "https://example.test/products",
            "method": "GET",
            "headers": "Accept: application/json\r\n",
            "data": None,
            "response": {
                "elementType": "ZestResponse",
                "statusCode": 200,
                "headers": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n",
                "body": '{"products": []}',
                "responseTimeInMs": 12,
            },
            "index": 1,
            "enabled": True,
        }
    ],
    "index": 0,
    "enabled": True,
}


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


async def test_import_zst_dispatches_to_zest_importer(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    compressed = zstandard.ZstdCompressor().compress(json.dumps(_SAMPLE_ZEST_SCRIPT).encode())

    resp = await client.post(
        f"/versions/{version_id}/traffic/import",
        files={"file": ("recording.zst", compressed, "application/octet-stream")},
        headers=admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["imported_count"] == 1

    listed = await client.get(f"/versions/{version_id}/traffic", headers=admin["headers"])
    interactions = listed.json()
    assert len(interactions) == 1
    assert interactions[0]["source"] == "zst_traffic"
    assert interactions[0]["request"]["url"] == "https://example.test/products"


async def test_import_burp_file_returns_501_not_a_crash(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/traffic/import",
        files={"file": ("project.burp", b"whatever bytes", "application/octet-stream")},
        headers=admin["headers"],
    )
    assert resp.status_code == 501
    assert "real .burp project export" in resp.text


async def test_import_webinspect_macro_returns_501_not_a_crash(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/traffic/import",
        files={"file": ("macro.webmacro", b"whatever bytes", "application/octet-stream")},
        headers=admin["headers"],
    )
    assert resp.status_code == 501
    assert "real WebInspect macro export" in resp.text


async def test_add_manual_traffic_persists_single_exchange(client):
    """Simulates what the Montoya Burp extension's "Send to Verdikt"
    context-menu action does — post one HTTP exchange directly."""
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/traffic/manual",
        json={
            "request": {
                "method": "GET",
                "url": "https://example.test/product?id=1",
                "headers": {"User-Agent": "Burp"},
                "query_params": {"id": "1"},
            },
            "response": {"status": 200, "headers": {"content-type": "text/html"}, "body": "<html></html>"},
        },
        headers=admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["source"] == "manual"
    assert body["request"]["url"] == "https://example.test/product?id=1"
    assert body["response"]["status"] == 200

    listed = await client.get(f"/versions/{version_id}/traffic", headers=admin["headers"])
    assert len(listed.json()) == 1
    assert listed.json()[0]["source"] == "manual"


async def test_add_manual_traffic_ignores_caller_supplied_source(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/traffic/manual",
        json={
            "request": {"method": "GET", "url": "https://example.test/"},
            "response": {"status": 200},
            "source": "agent",  # not a field on ManualTrafficCreate — should be ignored, not trusted
        },
        headers=admin["headers"],
    )
    assert resp.status_code == 201
    assert resp.json()["source"] == "manual"
