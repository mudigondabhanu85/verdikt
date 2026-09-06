import secrets
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

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


async def test_extra_cookies_are_merged_into_the_authenticated_session(db_adapter):
    """A real, concrete need found live: some targets gate behavior
    behind a stateless preference/feature-flag cookie the login response
    itself never sets (e.g. DVWA's `security` cookie choosing low/
    medium/high/impossible difficulty per-request, independent of
    session/auth state). extra_cookies lets a CredentialSet carry a
    fixed cookie alongside whatever the real login response sets."""
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=443, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )
        credential = _credential_set(
            username="formuser", secret="formpass", extra_cookies={"security": "low"}
        )
        form = FormInfo(
            action_url="https://site.test/do-login",
            method="POST",
            fields=[
                FormField(name="username", type="text"),
                FormField(name="password", type="password"),
            ],
        )

        manager = SessionManager(client)
        auth_session = await manager.login(credential, forms=[form])

        assert auth_session is not None
        # Both the extra static cookie and the real login-derived one
        # are present — extra_cookies augments, it doesn't replace.
        assert auth_session.cookies == {"security": "low", "sid": "abc123"}

        await client.aclose()


async def test_extra_cookies_win_over_a_login_derived_cookie_of_the_same_name(db_adapter):
    """A real bug found live against DVWA: its login response itself
    resets a `security` cookie to its own default on every login — if
    the login-derived value won, extra_cookies could never actually pin
    anything the target's own login response also happens to set,
    defeating the entire point of the field."""
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=443, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )
        credential = _credential_set(username="formuser", secret="formpass", extra_cookies={"sid": "forced-value"})
        form = FormInfo(
            action_url="https://site.test/do-login",
            method="POST",
            fields=[
                FormField(name="username", type="text"),
                FormField(name="password", type="password"),
            ],
        )

        manager = SessionManager(client)
        auth_session = await manager.login(credential, forms=[form])

        assert auth_session is not None
        assert auth_session.cookies == {"sid": "forced-value"}

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


async def test_sso_redirect_form_is_not_auto_posted_to(db_adapter):
    """A real bug class this closes: blindly POSTing credentials into an
    unfamiliar third-party IdP login page (§5) — the agent must
    recognize an Okta-hosted form and refuse to auto-post to it. Proven
    by pointing the form's action at a URL this fixture's handler would
    fail on if a credential-bearing POST ever actually reached it."""
    async with session_scope(db_adapter) as session:

        def _handler_that_fails_on_sso_post(request: httpx.Request) -> httpx.Response:
            if "oktapreview" in str(request.url) or "okta.com" in str(request.url):
                raise AssertionError(
                    "SessionManager POSTed credentials into an Okta-hosted login "
                    "page instead of recognizing it as SSO and refusing to auto-post"
                )
            return _handler(request)

        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[
                ScopeEntry(host="site.test", port=443, in_scope=True),
                ScopeEntry(host="acme.okta.com", port=443, in_scope=True),
            ],
            db_session=session,
            transport=httpx.MockTransport(_handler_that_fails_on_sso_post),
        )
        credential = _credential_set(username="formuser", secret="formpass")
        form = FormInfo(
            action_url="https://acme.okta.com/app/site/abc123/sso/saml",
            method="POST",
            fields=[
                FormField(name="username", type="text"),
                FormField(name="password", type="password"),
            ],
        )

        # No db_session on this manager -> macro fallback also declines,
        # so the only way this returns non-None is if the SSO form got
        # auto-posted to (which _handler_that_fails_on_sso_post would
        # have raised on) — a None result here is the expected safe
        # failure, not a bug.
        manager = SessionManager(client)
        auth_session = await manager.login(credential, forms=[form])
        assert auth_session is None

        await client.aclose()


async def test_sso_redirect_form_falls_back_to_macro_replay(db_adapter, fixture_login_server):
    """When an SSO-redirect form is detected AND a recorded macro exists
    for the credential set, login should still succeed — via the macro,
    never via posting into the IdP form."""
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

        def _handler_that_fails_on_sso_post(request: httpx.Request) -> httpx.Response:
            if "okta.com" in str(request.url):
                raise AssertionError("credentials were POSTed into the Okta form")
            return _handler(request)

        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=443, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(_handler_that_fails_on_sso_post),
        )
        form = FormInfo(
            action_url="https://acme.okta.com/app/site/abc123/sso/saml",
            method="POST",
            fields=[
                FormField(name="username", type="text"),
                FormField(name="password", type="password"),
            ],
        )

        manager = SessionManager(client, db_session=session)
        auth_session = await manager.login(credential, forms=[form])

        assert auth_session is not None
        assert auth_session.credential_set_id == credential.id
        assert auth_session.cookies == {"session": "abc123-real-session"}

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


class _CsrfGatedLoginHandler(BaseHTTPRequestHandler):
    """A real HTTP server (not httpx.MockTransport) modeling DVWA's real
    login.php exactly, since a stateless mock can't express either real
    bug found live against it: (1) it mints a fresh, session-bound CSRF
    token on every GET and genuinely rejects a login whose submitted
    token doesn't match the token tied to the session cookie the POST
    rides on — sending it blank (the old behavior) always fails; (2) it
    only attempts a login at all when its submit button's own named
    field ("Login") is present in the POST body — omitting it (also the
    old behavior, since only type=="hidden" fields were ever filled in)
    means the handler never even runs the credential check.
    """

    _tokens_by_session: dict[str, str] = {}

    def do_GET(self):  # noqa: N802
        if self.path != "/login.php":
            self.send_response(404)
            self.end_headers()
            return
        session_id = secrets.token_hex(8)
        token = secrets.token_hex(8)
        self._tokens_by_session[session_id] = token
        body = (
            "<form action='/login.php' method='post'>"
            "<input name='username'><input name='password' type='password'>"
            f"<input type='hidden' name='csrf_token' value='{token}'>"
            "<input type='submit' name='Login' value='Login'>"
            "</form>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", f"PHPSESSID={session_id}; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        fields = parse_qs(self.rfile.read(length).decode())
        cookie_header = self.headers.get("Cookie", "")
        session_id = cookie_header.removeprefix("PHPSESSID=") if "PHPSESSID=" in cookie_header else None
        expected_token = self._tokens_by_session.get(session_id or "")

        authenticated = (
            "Login" in fields  # the submit button's own field must be present
            and fields.get("csrf_token", [None])[0] == expected_token
            and expected_token is not None
            and fields.get("username", [None])[0] == "admin"
            and fields.get("password", [None])[0] == "password"
        )
        if authenticated:
            self.send_response(302)
            self.send_header("Location", "/index.php")
            self.send_header("Set-Cookie", f"PHPSESSID={session_id}; Path=/; authenticated=1")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<title>Login :: still on the login page</title>")

    def log_message(self, format, *args):  # noqa: A002
        pass


async def test_form_login_sends_live_csrf_token_and_submit_field(db_adapter):
    """The two real bugs this closes, found live against DVWA: a form
    auto-login that sends every hidden field blank (including a live
    CSRF token) and drops the submit button's own field entirely both
    fail against a real CSRF-gated, submit-gated login form like this
    one — the old code returned None here 100% of the time."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CsrfGatedLoginHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            credential = _credential_set(username="admin", secret="password")
            form = FormInfo(
                action_url=f"http://{host}:{port}/login.php",
                method="POST",
                fields=[
                    FormField(name="username", type="text"),
                    FormField(name="password", type="password"),
                    FormField(name="csrf_token", type="hidden"),
                    FormField(name="Login", type="submit"),
                ],
            )

            manager = SessionManager(client)
            auth_session = await manager.login(credential, forms=[form])

            assert auth_session is not None
            assert auth_session.cookies.get("PHPSESSID") is not None

            await client.aclose()
    finally:
        server.shutdown()
        thread.join(timeout=2)
