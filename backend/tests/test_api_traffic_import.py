import base64
import io
import json
from pathlib import Path

import pytest
import zstandard
from fastapi import HTTPException, UploadFile

from app.api.routes.traffic_import import _read_upload_capped, _strip_nul_bytes
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


async def test_import_openapi_json_is_sniffed_and_routed_correctly(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Sample", "version": "1.0"},
        "servers": [{"url": "https://api.example.test"}],
        "paths": {"/ping": {"get": {}}},
    }
    resp = await client.post(
        f"/versions/{version_id}/traffic/import",
        files={"file": ("api.json", json.dumps(spec).encode(), "application/json")},
        headers=admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["imported_count"] == 1

    listed = await client.get(f"/versions/{version_id}/traffic", headers=admin["headers"])
    assert listed.json()[0]["source"] == "openapi_import"


async def test_import_postman_json_is_sniffed_and_routed_correctly(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    collection = {
        "info": {"name": "Sample", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/"},
        "item": [{"name": "Ping", "request": {"method": "GET", "url": "https://api.example.test/ping"}}],
    }
    resp = await client.post(
        f"/versions/{version_id}/traffic/import",
        files={"file": ("collection.json", json.dumps(collection).encode(), "application/json")},
        headers=admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["imported_count"] == 1

    listed = await client.get(f"/versions/{version_id}/traffic", headers=admin["headers"])
    assert listed.json()[0]["source"] == "postman_import"


async def test_import_openapi_yaml_file(client):
    import yaml

    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Sample", "version": "1.0"},
        "paths": {"/ping": {"get": {}}},
    }
    resp = await client.post(
        f"/versions/{version_id}/traffic/import",
        files={"file": ("api.yaml", yaml.safe_dump(spec).encode(), "application/x-yaml")},
        headers=admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["imported_count"] == 1


async def test_read_upload_capped_rejects_oversized_file_without_buffering_it_all():
    # A tiny max_bytes keeps this fast — the real MAX_TRAFFIC_IMPORT_BYTES
    # cap (2GB) is exercised by this same code path, just with a smaller
    # threshold so the test doesn't need to actually push gigabytes.
    oversized = UploadFile(io.BytesIO(b"x" * 100), filename="huge.har")
    with pytest.raises(HTTPException) as exc_info:
        await _read_upload_capped(oversized, max_bytes=50)
    assert exc_info.value.status_code == 413


async def test_read_upload_capped_accepts_file_under_the_limit():
    small = UploadFile(io.BytesIO(b"x" * 50), filename="small.har")
    contents = await _read_upload_capped(small, max_bytes=100)
    assert contents == b"x" * 50


async def test_import_har_shaped_json_file_persists_interactions(client):
    # Same HAR content, just exported/saved with a ".json" extension —
    # HarImporter.parse does a plain json.load regardless of extension,
    # so ".json" is routed to it too (see traffic_import.py's _IMPORTERS).
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    with open(FIXTURE, "rb") as f:
        resp = await client.post(
            f"/versions/{version_id}/traffic/import",
            files={"file": ("sample.json", f, "application/json")},
            headers=admin["headers"],
        )
    assert resp.status_code == 201, resp.text
    assert resp.json()["imported_count"] == 2


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


def test_strip_nul_bytes_removes_embedded_nul():
    assert _strip_nul_bytes("before\x00after") == "beforeafter"


def test_strip_nul_bytes_passes_through_none_and_clean_text():
    assert _strip_nul_bytes(None) is None
    assert _strip_nul_bytes("clean text") == "clean text"


async def test_import_har_with_binary_asset_strips_nul_bytes_from_body(client):
    """A real bug found via §14 live validation against OWASP Juice
    Shop: a captured HAR entry for a binary asset (e.g. a PNG image)
    decodes to text containing literal NUL bytes, which Postgres text
    columns reject outright — and took down the *entire* batch insert,
    not just the one binary row, since HarImporter parses a whole HAR
    into one bulk TrafficInteraction insert. This uses a synthetic PNG
    header (which always starts with a NUL byte) as the base64-encoded
    response content, matching exactly what a real HAR capture of an
    image asset looks like.
    """
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00"
    har = {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "startedDateTime": "2026-08-21T12:00:00.000Z",
                    "time": 5,
                    "request": {
                        "method": "GET",
                        "url": "https://example.test/logo.png",
                        "headers": [],
                        "queryString": [],
                    },
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {
                            "mimeType": "image/png",
                            "encoding": "base64",
                            "text": base64.b64encode(png_bytes).decode(),
                        },
                    },
                }
            ],
        }
    }

    resp = await client.post(
        f"/versions/{version_id}/traffic/import",
        files={"file": ("binary.har", json.dumps(har).encode(), "application/json")},
        headers=admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["imported_count"] == 1

    listed = await client.get(f"/versions/{version_id}/traffic", headers=admin["headers"])
    interactions = listed.json()
    assert len(interactions) == 1
    assert "\x00" not in interactions[0]["response"]["body"]


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


async def test_import_burp_binary_project_save_returns_501_not_a_crash(client):
    # Burp's proprietary full-project binary save (Project > Save/Save
    # as) — undocumented, stays unsupported. Distinguished from the XML
    # "Save items" export (test_import_burp_save_items_xml below) by not
    # starting with an XML declaration.
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/traffic/import",
        files={"file": ("project.burp", b"whatever bytes", "application/octet-stream")},
        headers=admin["headers"],
    )
    assert resp.status_code == 501
    assert "proprietary full-project save" in resp.text


async def test_import_burp_save_items_xml_persists_interactions(client):
    # Burp's "Save selected items"/"Save all items" XML export (Proxy >
    # HTTP history, right-click -> Save selected items) — real,
    # documented format BurpFileImporter actually parses.
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    burp_xml = b"""<?xml version="1.0"?>
<items burpVersion="2026.7.3" exportTime="Tue Sep 08 15:58:02 EDT 2026">
  <item>
    <time>Tue Mar 31 16:23:42 EDT 2026</time>
    <url><![CDATA[https://example.test/api/products?id=1]]></url>
    <host ip="1.2.3.4">example.test</host>
    <port>443</port>
    <protocol>https</protocol>
    <method><![CDATA[GET]]></method>
    <path><![CDATA[/api/products?id=1]]></path>
    <extension>null</extension>
    <request base64="true">R0VUIC9hcGkvcHJvZHVjdHM/aWQ9MSBIVFRQLzEuMQ0KSG9zdDogZXhhbXBsZS50ZXN0DQoNCg==</request>
    <status>200</status>
    <responselength>42</responselength>
    <mimetype>json</mimetype>
    <response base64="true">SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24NCg0Ke30=</response>
    <comment></comment>
  </item>
</items>
"""
    resp = await client.post(
        f"/versions/{version_id}/traffic/import",
        files={"file": ("export.burp", burp_xml, "application/xml")},
        headers=admin["headers"],
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["imported_count"] == 1

    listed = await client.get(f"/versions/{version_id}/traffic", headers=admin["headers"])
    interaction = listed.json()[0]
    assert interaction["source"] == "burp_file"
    assert interaction["request"]["method"] == "GET"
    assert interaction["request"]["url"] == "https://example.test/api/products?id=1"
    assert interaction["request"]["headers"]["Host"] == "example.test"
    assert interaction["response"]["status"] == 200


async def test_import_extensionless_file_routes_to_burp_importer(client):
    # Burp's own "Save selected items" export has no extension at all —
    # confirm it's routed to BurpFileImporter (501, not the generic
    # "unsupported file type ''" 400) rather than rejected outright.
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    resp = await client.post(
        f"/versions/{version_id}/traffic/import",
        files={"file": ("2026-02-02-MarketScan-Account-Manager", b"whatever bytes", "application/octet-stream")},
        headers=admin["headers"],
    )
    assert resp.status_code == 501
    assert "proprietary full-project save" in resp.text


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


async def test_delete_traffic_interaction_removes_just_that_row(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    first = await client.post(
        f"/versions/{version_id}/traffic/manual",
        json={
            "request": {"method": "GET", "url": "https://example.test/a"},
            "response": {"status": 200},
        },
        headers=admin["headers"],
    )
    second = await client.post(
        f"/versions/{version_id}/traffic/manual",
        json={
            "request": {"method": "GET", "url": "https://example.test/b"},
            "response": {"status": 200},
        },
        headers=admin["headers"],
    )
    first_id = first.json()["id"]

    deleted = await client.delete(f"/versions/{version_id}/traffic/{first_id}", headers=admin["headers"])
    assert deleted.status_code == 204

    listed = (await client.get(f"/versions/{version_id}/traffic", headers=admin["headers"])).json()
    assert len(listed) == 1
    assert listed[0]["id"] == second.json()["id"]

    again = await client.delete(f"/versions/{version_id}/traffic/{first_id}", headers=admin["headers"])
    assert again.status_code == 404


async def test_clear_all_traffic_deletes_everything_for_the_version(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    for i in range(3):
        await client.post(
            f"/versions/{version_id}/traffic/manual",
            json={
                "request": {"method": "GET", "url": f"https://example.test/{i}"},
                "response": {"status": 200},
            },
            headers=admin["headers"],
        )

    cleared = await client.delete(f"/versions/{version_id}/traffic", headers=admin["headers"])
    assert cleared.status_code == 204

    listed = (await client.get(f"/versions/{version_id}/traffic", headers=admin["headers"])).json()
    assert listed == []


async def test_clear_traffic_by_source_only_deletes_that_source(client):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])

    await client.post(
        f"/versions/{version_id}/traffic/manual",
        json={"request": {"method": "GET", "url": "https://example.test/manual"}, "response": {"status": 200}},
        headers=admin["headers"],
    )

    cleared = await client.delete(f"/versions/{version_id}/traffic?source=har", headers=admin["headers"])
    assert cleared.status_code == 204

    # The manual entry survives — only "har"-sourced rows were targeted,
    # and there were none.
    listed = (await client.get(f"/versions/{version_id}/traffic", headers=admin["headers"])).json()
    assert len(listed) == 1
    assert listed[0]["source"] == "manual"
