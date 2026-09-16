import uuid

import httpx

from app.agents.http_client import ScopedHttpClient
from app.agents.recon import FormField, FormInfo
from app.agents.session_invalidation import SessionInvalidationAgent
from app.models.credential import CredentialSet
from app.models.project import ScopeEntry
from app.models.target import Target
from app.vault.credential_vault import encrypt_credential
from tests.conftest import session_scope

_ANONYMOUS_HOME = "<html><body>Please log in</body></html>"
_AUTHENTICATED_HOME = "<html><body>Welcome back, admin! Here is your real dashboard content.</body></html>"


def _credential() -> CredentialSet:
    return CredentialSet(
        id=uuid.uuid4(),
        version_id=uuid.uuid4(),
        label="admin",
        credential_type="username_password",
        encrypted_secret=encrypt_credential("admin", "hunter2"),
        masked_reference="admin (****)",
        login_endpoint="http://site.test/login",
    )


def _make_handler(*, invalidates_on_logout: bool):
    valid_sessions: set[str] = set()

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        cookie = request.headers.get("cookie", "")

        if path == "/login" and request.method == "POST":
            token = f"sid-{uuid.uuid4().hex[:8]}"
            valid_sessions.add(token)
            return httpx.Response(200, headers={"set-cookie": f"session={token}"}, request=request)

        if path == "/" and request.method == "GET":
            authed = any(f"session={tok}" in cookie for tok in valid_sessions)
            if authed:
                return httpx.Response(200, text=_AUTHENTICATED_HOME, request=request)
            return httpx.Response(200, text=_ANONYMOUS_HOME, request=request)

        if path == "/logout" and request.method == "GET":
            if invalidates_on_logout:
                for tok in list(valid_sessions):
                    if f"session={tok}" in cookie:
                        valid_sessions.discard(tok)
            return httpx.Response(200, text="Logged out", request=request)

        return httpx.Response(404, request=request)

    return handler


async def _run_agent(db_adapter, handler, *, credential=None):
    credential = credential or _credential()
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=credential.version_id,
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(handler),
        )
        anonymous_baseline = await client.get("http://site.test/")
        agent = SessionInvalidationAgent(
            client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
        )
        findings = await agent.run(
            [credential],
            forms=[],
            logout_urls=["http://site.test/logout"],
            targets=[Target(host="site.test", port=80, base_url="http://site.test/")],
            anonymous_responses={"http://site.test/": anonymous_baseline},
        )
        await client.aclose()
        return findings


async def test_session_survives_logout_is_flagged(db_adapter):
    handler = _make_handler(invalidates_on_logout=False)

    findings = await _run_agent(db_adapter, handler)

    assert len(findings) == 1
    assert findings[0].check_id == "session-not-invalidated-on-logout"


async def test_session_correctly_invalidated_yields_no_finding(db_adapter):
    handler = _make_handler(invalidates_on_logout=True)

    findings = await _run_agent(db_adapter, handler)

    assert findings == []


async def test_no_logout_url_discovered_skips_entirely(db_adapter):
    credential = _credential()
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=credential.version_id,
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(_make_handler(invalidates_on_logout=False)),
        )
        anonymous_baseline = await client.get("http://site.test/")
        agent = SessionInvalidationAgent(
            client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
        )
        findings = await agent.run(
            [credential],
            forms=[],
            logout_urls=[],  # nothing captured by recon this run
            targets=[Target(host="site.test", port=80, base_url="http://site.test/")],
            anonymous_responses={"http://site.test/": anonymous_baseline},
        )
        await client.aclose()

    assert findings == []


async def test_api_token_credential_is_skipped(db_adapter):
    credential = CredentialSet(
        id=uuid.uuid4(),
        version_id=uuid.uuid4(),
        label="api",
        credential_type="api_token",
        encrypted_secret=encrypt_credential("api", "some-token"),
        masked_reference="api (****)",
    )

    findings = await _run_agent(db_adapter, _make_handler(invalidates_on_logout=False), credential=credential)

    assert findings == []
