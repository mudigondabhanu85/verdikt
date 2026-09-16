import uuid
from urllib.parse import parse_qs

import httpx

from app.agents.csv_injection import CsvInjectionAgent
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.agents.recon import FormField, FormInfo
from app.models.project import ScopeEntry
from tests.conftest import session_scope


def _comment_form() -> FormInfo:
    return FormInfo(
        action_url="http://site.test/comments",
        method="POST",
        fields=[FormField(name="comment", type="text")],
    )


def _make_handler(*, sanitizes: bool, export_available: bool):
    stored: dict[str, str] = {"comment": ""}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path

        if path == "/comments" and request.method == "POST":
            body = parse_qs(request.content.decode())
            value = body.get("comment", [""])[0]
            if sanitizes and value.startswith("="):
                value = "'" + value  # standard OWASP mitigation
            stored["comment"] = value
            return httpx.Response(200, text="Comment posted", request=request)

        if path == "/profile" and request.method == "GET":
            return httpx.Response(
                200, text=f"<html><body>Latest comment: {stored['comment']}</body></html>", request=request
            )

        if path == "/export/csv" and request.method == "GET":
            if not export_available:
                return httpx.Response(404, request=request)
            return httpx.Response(200, text=f"id,comment\n1,{stored['comment']}\n", request=request)

        return httpx.Response(404, request=request)

    return handler


async def _run_agent(db_adapter, handler, endpoints):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(handler),
        )
        agent = CsvInjectionAgent(
            client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
        )
        cred_id = uuid.uuid4()
        sessions = {cred_id: AuthenticatedSession(credential_set_id=cred_id, cookies={"sid": "abc"})}
        findings = await agent.run([_comment_form()], endpoints, sessions)
        await client.aclose()
        return findings


async def test_unsanitized_value_round_trips_and_export_found(db_adapter):
    handler = _make_handler(sanitizes=False, export_available=True)

    findings = await _run_agent(db_adapter, handler, ["http://site.test/profile"])

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "csv-formula-injection"
    assert any("export/csv" in step for step in finding.steps_to_reproduce)


async def test_unsanitized_value_round_trips_without_export_endpoint(db_adapter):
    handler = _make_handler(sanitizes=False, export_available=False)

    findings = await _run_agent(db_adapter, handler, ["http://site.test/profile"])

    assert len(findings) == 1
    finding = findings[0]
    # Honest about the missing full end-to-end proof rather than
    # claiming a download that was never actually confirmed.
    assert any("No conventional export endpoint" in step for step in finding.steps_to_reproduce)


async def test_leading_quote_mitigation_prevents_false_positive(db_adapter):
    handler = _make_handler(sanitizes=True, export_available=True)

    findings = await _run_agent(db_adapter, handler, ["http://site.test/profile"])

    assert findings == []


async def test_marker_absent_entirely_yields_no_finding(db_adapter):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/comments" and request.method == "POST":
            return httpx.Response(200, text="posted, but nothing is ever displayed back", request=request)
        return httpx.Response(404, request=request)

    findings = await _run_agent(db_adapter, handler, ["http://site.test/profile"])

    assert findings == []
