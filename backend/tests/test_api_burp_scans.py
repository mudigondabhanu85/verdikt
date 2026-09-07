import httpx

from tests.conftest import create_project_and_version, register_org_admin

_SAMPLE_ISSUE = {
    "type_index": 1049088,
    "name": "SQL injection",
    "severity": "high",
    "host": "https://example.test",
    "path": "/product",
    "issue_background": "<p>SQL injection background.</p>",
    "issue_detail": "<p>The id parameter is vulnerable.</p>",
    "remediation_detail": "<p>Use parameterized queries.</p>",
    "vulnerability_classifications": "<p>CWE-89</p>",
    "evidence": [],
}


def _burp_handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url == "https://burp.local:1337/v0.1/scan" and request.method == "POST":
        return httpx.Response(201, headers={"location": "/v0.1/scan/42"})
    if url == "https://burp.local:1337/v0.1/scan/42" and request.method == "GET":
        return httpx.Response(
            200,
            json={
                "scan_status": "succeeded",
                "issue_events": [{"type": "issue_found", "issue": _SAMPLE_ISSUE}],
            },
        )
    return httpx.Response(404)


async def _authorize_version(client, headers, version_id):
    await client.post(
        f"/versions/{version_id}/scope-entries",
        json={"host": "example.test", "port": 443, "in_scope": True},
        headers=headers,
    )


async def test_burp_scan_trigger_and_import_creates_findings(client, monkeypatch):
    admin = await register_org_admin(client)
    _, version_id = await create_project_and_version(client, admin["headers"])
    await _authorize_version(client, admin["headers"], version_id)

    # Patch BurpRestClient construction inside the route module so every
    # instance it creates talks to our MockTransport instead of a real
    # network socket — Burp Community Edition (installed in this sandbox)
    # has no REST API to hit for a genuine live test.
    import app.api.routes.burp as burp_routes
    from app.integrations.burp.rest_client import BurpRestClient

    def _patched_client(base_url, api_key=None):
        return BurpRestClient(base_url, api_key, transport=httpx.MockTransport(_burp_handler))

    monkeypatch.setattr(burp_routes, "BurpRestClient", _patched_client)

    created = await client.post(
        f"/versions/{version_id}/burp/scans",
        json={"burp_base_url": "https://burp.local:1337", "urls": ["https://example.test/"]},
        headers=admin["headers"],
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["task_id"] == "42"
    scan_run_id = body["scan_run_id"]

    imported = await client.post(
        f"/versions/{version_id}/burp/scans/{body['task_id']}/import",
        json={
            "burp_base_url": "https://burp.local:1337",
            "scan_run_id": scan_run_id,
            "poll_interval": 0,
        },
        headers=admin["headers"],
    )
    assert imported.status_code == 200, imported.text
    imported_body = imported.json()
    assert imported_body["scan_status"] == "succeeded"
    assert imported_body["imported_count"] == 1

    findings = await client.get(f"/scan-runs/{scan_run_id}/findings", headers=admin["headers"])
    assert findings.status_code == 200
    findings_body = findings.json()
    assert len(findings_body) == 1
    assert findings_body[0]["severity"] == "High"
    assert findings_body[0]["confirmation_status"] == "analyst_confirmed"
    assert findings_body[0]["cwe_id"] == "CWE-89"


async def test_burp_import_rejects_scan_run_from_another_version(client, monkeypatch):
    import app.api.routes.burp as burp_routes
    from app.integrations.burp.rest_client import BurpRestClient

    def _patched_client(base_url, api_key=None):
        return BurpRestClient(base_url, api_key, transport=httpx.MockTransport(_burp_handler))

    monkeypatch.setattr(burp_routes, "BurpRestClient", _patched_client)

    admin = await register_org_admin(client)
    _, version_id_a = await create_project_and_version(client, admin["headers"], project_name="A")
    _, version_id_b = await create_project_and_version(client, admin["headers"], project_name="B")
    await _authorize_version(client, admin["headers"], version_id_a)

    created = await client.post(
        f"/versions/{version_id_a}/burp/scans",
        json={"burp_base_url": "https://burp.local:1337", "urls": ["https://example.test/"]},
        headers=admin["headers"],
    )
    scan_run_id = created.json()["scan_run_id"]

    imported = await client.post(
        f"/versions/{version_id_b}/burp/scans/42/import",
        json={
            "burp_base_url": "https://burp.local:1337",
            "scan_run_id": scan_run_id,
            "poll_interval": 0,
        },
        headers=admin["headers"],
    )
    assert imported.status_code == 404
