import uuid
from urllib.parse import parse_qs

import httpx
from sqlalchemy import select

from app.agents.csrf import CsrfAgent
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.agents.recon import FormField, FormInfo
from app.models.finding import Evidence
from app.models.project import ScopeEntry
from tests.conftest import session_scope


def _vulnerable_handler(request: httpx.Request) -> httpx.Response:
    if str(request.url.path) == "/change-email" and request.method == "POST":
        body = parse_qs(request.content.decode())
        if "email" in body:
            return httpx.Response(200, text="Email updated")
    return httpx.Response(404)


def _protected_handler(request: httpx.Request) -> httpx.Response:
    if str(request.url.path) == "/change-email" and request.method == "POST":
        origin = request.headers.get("origin", "")
        if origin != "http://site.test":
            return httpx.Response(403, text="Forbidden: origin mismatch")
        body = parse_qs(request.content.decode())
        if "email" in body:
            return httpx.Response(200, text="Email updated")
    return httpx.Response(404)


def _token_protected_handler(request: httpx.Request) -> httpx.Response:
    if str(request.url.path) == "/change-email" and request.method == "POST":
        body = parse_qs(request.content.decode())
        if body.get("csrf_token", [""])[0] != "the-real-token":
            return httpx.Response(403, text="Forbidden: bad CSRF token")
        return httpx.Response(200, text="Email updated")
    return httpx.Response(404)


def _form_without_token() -> FormInfo:
    return FormInfo(
        action_url="http://site.test/change-email",
        method="POST",
        fields=[FormField(name="email", type="text")],
    )


def _form_with_token() -> FormInfo:
    return FormInfo(
        action_url="http://site.test/change-email",
        method="POST",
        fields=[
            FormField(name="email", type="text"),
            FormField(name="csrf_token", type="hidden"),
        ],
    )


async def _run_agent(db_adapter, handler, forms, sessions):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(handler),
        )
        agent = CsrfAgent(
            client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
        )
        findings = await agent.run(forms, sessions)
        await client.aclose()
        return findings


async def test_form_without_token_and_no_origin_check_is_flagged(db_adapter):
    cred_id = uuid.uuid4()
    sessions = {cred_id: AuthenticatedSession(credential_set_id=cred_id, cookies={"sid": "abc"})}

    findings = await _run_agent(db_adapter, _vulnerable_handler, [_form_without_token()], sessions)

    check_ids = {f.check_id for f in findings}
    assert "csrf-missing-protection" in check_ids
    finding = next(f for f in findings if f.check_id == "csrf-missing-protection")
    assert finding.severity == "High"


async def test_origin_validation_prevents_flag(db_adapter):
    cred_id = uuid.uuid4()
    sessions = {cred_id: AuthenticatedSession(credential_set_id=cred_id, cookies={"sid": "abc"})}

    findings = await _run_agent(db_adapter, _protected_handler, [_form_without_token()], sessions)

    assert findings == []


async def test_form_with_csrf_token_field_is_skipped_entirely(db_adapter):
    cred_id = uuid.uuid4()
    sessions = {cred_id: AuthenticatedSession(credential_set_id=cred_id, cookies={"sid": "abc"})}

    findings = await _run_agent(db_adapter, _token_protected_handler, [_form_with_token()], sessions)

    assert findings == []


async def test_bearer_token_only_session_is_never_flagged(db_adapter):
    cred_id = uuid.uuid4()
    sessions = {cred_id: AuthenticatedSession(credential_set_id=cred_id, bearer_token="jwt.abc.def")}

    findings = await _run_agent(db_adapter, _vulnerable_handler, [_form_without_token()], sessions)

    assert findings == []


async def test_evidence_records_the_forged_origin_as_the_payload(db_adapter):
    """The exact substring that proves this finding (see
    Evidence.payload) — every report surface highlights it wherever the
    raw request/response is shown, so it needs to be the real forged
    Origin value, not left null.
    """
    cred_id = uuid.uuid4()
    sessions = {cred_id: AuthenticatedSession(credential_set_id=cred_id, cookies={"sid": "abc"})}
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(_vulnerable_handler),
        )
        agent = CsrfAgent(client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session)
        findings = await agent.run([_form_without_token()], sessions)
        assert len(findings) == 1
        evidence = (
            await session.execute(select(Evidence).where(Evidence.finding_id == findings[0].id))
        ).scalar_one()
        assert evidence.payload == "https://verdikt-csrf-test.invalid"
        await client.aclose()
