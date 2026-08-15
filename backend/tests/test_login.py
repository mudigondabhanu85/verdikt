import uuid

import httpx

from app.agents.http_client import ScopedHttpClient
from app.agents.login import SessionManager
from app.agents.macro import MacroRecorder
from app.agents.recon import FormField, FormInfo
from app.models.credential import CredentialSet
from app.models.login_macro import LoginMacro
from app.models.project import ScopeEntry
from app.vault.credential_vault import encrypt_credential
from tests.conftest import session_scope


def _handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url == "https://site.test/rest/user/login" and request.method == "POST":
        body = request.content.decode()
        if '"admin@site.test"' in body and '"correct-pw"' in body:
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={"authentication": {"token": "jwt-abc-123"}},
            )
        return httpx.Response(401, json={"error": "invalid credentials"})

    if url == "https://site.test/do-login" and request.method == "POST":
        body = request.content.decode()
        if "username=formuser" in body and "password=formpass" in body:
            return httpx.Response(
                200, headers={"set-cookie": "sid=abc123; Path=/"}, text="Welcome"
            )
        return httpx.Response(200, text="Login failed")

    return httpx.Response(404)


def _credential_set(**overrides) -> CredentialSet:
    encrypted = encrypt_credential(
        overrides.pop("username", "admin@site.test"), overrides.pop("secret", "correct-pw")
    )
    defaults = dict(
        id=uuid.uuid4(),
        version_id=uuid.uuid4(),
        label="Admin",
        credential_type="username_password",
        encrypted_secret=encrypted,
        masked_reference="admin (****pw)",
    )
    defaults.update(overrides)
    return CredentialSet(**defaults)


async def test_explicit_login_config_extracts_bearer_token(db_adapter):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=443, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )
        credential = _credential_set(
            login_endpoint="https://site.test/rest/user/login",
            login_method="POST",
            login_body_template='{"email": "{username}", "password": "{password}"}',
            login_content_type="application/json",
            token_response_path="authentication.token",
        )

        manager = SessionManager(client)
        auth_session = await manager.login(credential, forms=[])

        assert auth_session is not None
        assert auth_session.bearer_token == "jwt-abc-123"
        assert auth_session.credential_set_id == credential.id

        await client.aclose()


async def test_explicit_login_wrong_credentials_returns_none(db_adapter):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=443, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )
        credential = _credential_set(
            username="admin@site.test",
            secret="wrong-password",
            login_endpoint="https://site.test/rest/user/login",
            login_content_type="application/json",
            token_response_path="authentication.token",
        )

        manager = SessionManager(client)
        auth_session = await manager.login(credential, forms=[])
        assert auth_session is None

        await client.aclose()


async def test_form_auto_discovery_login_extracts_cookie(db_adapter):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=443, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )
        credential = _credential_set(username="formuser", secret="formpass")
        form = FormInfo(
            action_url="https://site.test/do-login",
            method="POST",
            fields=[
                FormField(name="username", type="text"),
                FormField(name="password", type="password"),
                FormField(name="csrf", type="hidden"),
            ],
        )

        manager = SessionManager(client)
        auth_session = await manager.login(credential, forms=[form])

        assert auth_session is not None
        assert auth_session.cookies == {"sid": "abc123"}
        assert auth_session.bearer_token is None

        await client.aclose()


async def _drive_fixture_login(page, *, username="whatever-typed", password="whatever-typed"):
    await page.fill("#username", username)
    await page.fill("#password", password)
    await page.click("#submit-btn")
    await page.wait_for_load_state("networkidle")


async def test_macro_replay_fallback_used_when_no_config_or_form(db_adapter, fixture_login_server):
    host, port = fixture_login_server
    start_url = f"http://{host}:{port}/"

    recorder = MacroRecorder()
    steps = await recorder.record(start_url, headless=True, drive=_drive_fixture_login)

    credential = _credential_set(username="expected_user", secret="expected_pass")

    async with session_scope(db_adapter) as session:
        session.add(
            LoginMacro(
                version_id=credential.version_id,
                credential_set_id=credential.id,
                steps=[s.to_dict() for s in steps],
            )
        )
        await session.commit()

        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=443, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )

        # No login_endpoint on this credential and no forms available —
        # explicit config and form auto-discovery both decline, so only
        # the macro-replay fallback can produce a session.
        manager = SessionManager(client, db_session=session)
        auth_session = await manager.login(credential, forms=[])

        assert auth_session is not None
        assert auth_session.credential_set_id == credential.id
        assert auth_session.cookies == {"session": "abc123-real-session"}

        await client.aclose()


async def test_macro_replay_fallback_not_tried_without_db_session(db_adapter, fixture_login_server):
    host, port = fixture_login_server
    start_url = f"http://{host}:{port}/"

    recorder = MacroRecorder()
    steps = await recorder.record(start_url, headless=True, drive=_drive_fixture_login)

    credential = _credential_set(username="expected_user", secret="expected_pass")

    async with session_scope(db_adapter) as session:
        session.add(
            LoginMacro(
                version_id=credential.version_id,
                credential_set_id=credential.id,
                steps=[s.to_dict() for s in steps],
            )
        )
        await session.commit()

        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=443, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )

        manager = SessionManager(client)  # no db_session -> macro fallback skipped
        auth_session = await manager.login(credential, forms=[])
        assert auth_session is None

        await client.aclose()


async def test_no_login_path_available_returns_none(db_adapter):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=443, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )
        credential = _credential_set()  # no login_endpoint, no forms available

        manager = SessionManager(client)
        auth_session = await manager.login(credential, forms=[])
        assert auth_session is None

        await client.aclose()
