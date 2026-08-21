import base64
import json

import httpx
import pytest

from app.integrations.burp.mapping import map_issue_to_finding
from app.integrations.burp.rest_client import BurpRestClient, BurpScanError

_SAMPLE_ISSUE = {
    "serial_number": "123456",
    "type_index": 1049088,
    "name": "SQL injection",
    "severity": "high",
    "confidence": "certain",
    "host": "https://example.test",
    "path": "/product",
    "location": "/product",
    "issue_background": "<p>SQL injection vulnerabilities arise when...</p>",
    "remediation_background": "<p>The most effective way to prevent SQL injection...</p>",
    "issue_detail": "<p>The value of the id request parameter is copied into an SQL statement.</p>",
    "remediation_detail": "<p>Use parameterized queries.</p>",
    "references": "<p>https://portswigger.net/kb/issues/00100200_sql-injection</p>",
    "vulnerability_classifications": "<p>This issue is categorized as CWE-89.</p>",
    "evidence": [
        {
            "request_response": {
                "request": base64.b64encode(b"GET /product?id=1 HTTP/1.1\r\nHost: example.test\r\n\r\n").decode(),
                "response": base64.b64encode(b"HTTP/1.1 500 Internal Server Error\r\n\r\nSQL syntax error").decode(),
            }
        }
    ],
}


def _handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)

    if url == "https://burp.local:1337/v0.1/scan" and request.method == "POST":
        body = json.loads(request.content.decode())
        assert body["urls"] == ["https://example.test/"]
        return httpx.Response(201, headers={"location": "/v0.1/scan/7"})

    if url == "https://burp.local:1337/v0.1/scan/7" and request.method == "GET":
        return httpx.Response(
            200,
            json={
                "scan_status": "succeeded",
                "scan_metrics": {"crawl_and_audit_time": 4213},
                "issue_events": [
                    {"type": "issue_found", "issue": _SAMPLE_ISSUE},
                    {"type": "scan_metrics_updated"},
                ],
            },
        )

    if url == "https://burp.local:1337/my-api-key/v0.1/scan/9" and request.method == "GET":
        return httpx.Response(200, json={"scan_status": "running", "issue_events": []})

    return httpx.Response(404)


async def test_start_scan_parses_task_id_from_location_header():
    client = BurpRestClient(
        "https://burp.local:1337", transport=httpx.MockTransport(_handler)
    )
    task_id = await client.start_scan(["https://example.test/"])
    assert task_id == "7"


async def test_get_scan_status_returns_raw_documented_body():
    client = BurpRestClient(
        "https://burp.local:1337", transport=httpx.MockTransport(_handler)
    )
    status = await client.get_scan_status("7")
    assert status["scan_status"] == "succeeded"
    issues = BurpRestClient.extract_issues(status)
    assert len(issues) == 1
    assert issues[0]["name"] == "SQL injection"


async def test_api_key_is_inserted_as_path_segment():
    client = BurpRestClient(
        "https://burp.local:1337",
        api_key="my-api-key",
        transport=httpx.MockTransport(_handler),
    )
    status = await client.get_scan_status("9")
    assert status["scan_status"] == "running"


async def test_wait_for_completion_polls_until_terminal_status():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        status = "running" if calls["n"] < 3 else "succeeded"
        return httpx.Response(200, json={"scan_status": status, "issue_events": []})

    client = BurpRestClient("https://burp.local:1337", transport=httpx.MockTransport(handler))
    result = await client.wait_for_completion("7", poll_interval=0, timeout=5)
    assert result["scan_status"] == "succeeded"
    assert calls["n"] == 3


async def test_scan_creation_failure_raises_burp_scan_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad scope")

    client = BurpRestClient("https://burp.local:1337", transport=httpx.MockTransport(handler))
    with pytest.raises(BurpScanError):
        await client.start_scan(["https://example.test/"])


async def test_unreachable_burp_instance_raises_burp_scan_error_not_uncaught():
    """A real E2E run against a genuinely unreachable Burp URL found that
    a connection-level failure (refused, DNS, timeout) previously
    propagated straight past this client as a raw httpx.RequestError —
    the API route only excepts BurpScanError, so callers got an
    unhandled 500 instead of the documented, clean 502 response."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused", request=request)

    client = BurpRestClient("https://burp.local:1337", transport=httpx.MockTransport(handler))
    with pytest.raises(BurpScanError, match="Could not reach Burp"):
        await client.start_scan(["https://example.test/"])
    with pytest.raises(BurpScanError, match="Could not reach Burp"):
        await client.get_scan_status("7")


def test_map_issue_to_finding_extracts_severity_cwe_and_evidence():
    import uuid

    scan_run_id = uuid.uuid4()
    agent_job_id = uuid.uuid4()

    finding, evidence = map_issue_to_finding(
        _SAMPLE_ISSUE, scan_run_id=scan_run_id, agent_job_id=agent_job_id
    )

    assert finding.severity == "High"
    assert finding.cwe_id == "CWE-89"
    assert finding.confirmation_status == "analyst_confirmed"
    assert finding.title == "SQL injection"
    assert "example.test/product" in finding.affected_endpoints[0]
    assert "SQL statement" in finding.technical_description
    assert "parameterized queries" in finding.remediation.lower()

    assert evidence is not None
    assert "GET /product?id=1" in evidence.request_raw
    assert "SQL syntax error" in evidence.response_raw


def test_map_issue_to_finding_handles_missing_optional_fields():
    import uuid

    minimal_issue = {"name": "Some issue", "severity": "information"}
    finding, evidence = map_issue_to_finding(
        minimal_issue, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4()
    )

    assert finding.severity == "Low"
    assert finding.cwe_id == "CWE-0"
    assert finding.affected_endpoints == []
    assert evidence is None
