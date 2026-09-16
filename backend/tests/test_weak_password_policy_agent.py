import json
import logging
import uuid
from urllib.parse import parse_qs

import httpx

from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.agents.recon import FormField, FormInfo
from app.agents.weak_password_policy import WeakPasswordPolicyAgent
from app.models.credential import CredentialSet
from app.models.project import ScopeEntry
from app.vault.credential_vault import encrypt_credential
from tests.conftest import session_scope

_ORIGINAL_PASSWORD = "correct-horse-battery-staple"


def _change_password_form() -> FormInfo:
    return FormInfo(
        action_url="http://site.test/change-password",
        method="POST",
        fields=[
            FormField(name="current_password", type="password"),
            FormField(name="new_password", type="password"),
            FormField(name="confirm_password", type="password"),
        ],
    )


def _login_form_only() -> FormInfo:
    return FormInfo(
        action_url="http://site.test/login-form",
        method="POST",
        fields=[FormField(name="password", type="password")],
    )


def _credential() -> CredentialSet:
    return CredentialSet(
        id=uuid.uuid4(),
        version_id=uuid.uuid4(),
        label="admin",
        credential_type="username_password",
        encrypted_secret=encrypt_credential("admin", _ORIGINAL_PASSWORD),
        masked_reference="admin (****)",
        login_endpoint="http://site.test/login",
    )


def _api_token_credential() -> CredentialSet:
    return CredentialSet(
        id=uuid.uuid4(),
        version_id=uuid.uuid4(),
        label="api",
        credential_type="api_token",
        encrypted_secret=encrypt_credential("api-token", "some-token-value"),
        masked_reference="api (****)",
    )


def _make_handler(state: dict, *, accepts_weak_password: bool, revert_allowed: bool = True):
    """A fake app tracking one real mutable "current password" — the
    only way this test can tell whether the agent's confirmation
    (re-login) and revert steps are doing real work, not just trusting a
    response body.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path

        if path == "/change-password" and request.method == "GET":
            return httpx.Response(200, text="<html><body>change password</body></html>", request=request)

        if path == "/change-password" and request.method == "POST":
            body = parse_qs(request.content.decode())
            current = body.get("current_password", [""])[0]
            new = body.get("new_password", [""])[0]
            if current != state["password"]:
                return httpx.Response(200, text="Error: current password incorrect", request=request)
            if not accepts_weak_password and len(new) < 8:
                return httpx.Response(200, text="Error: password too short", request=request)
            if not revert_allowed and new == _ORIGINAL_PASSWORD:
                # Simulates a broken revert attempt (e.g. a server-side
                # policy silently rejecting the revert) without touching
                # state — proves the finally-block's own re-login check
                # (not just the HTTP status) is what detects this.
                return httpx.Response(200, text="Error: could not update", request=request)
            state["password"] = new
            return httpx.Response(200, text="Password changed successfully", request=request)

        if path == "/login" and request.method == "POST":
            payload = json.loads(request.content.decode())
            if payload.get("password") == state["password"]:
                return httpx.Response(200, headers={"set-cookie": "sid=fresh-session"}, request=request)
            return httpx.Response(401, text="Invalid credentials", request=request)

        return httpx.Response(404, request=request)

    return handler


async def _run_agent(db_adapter, handler, forms, credential, sessions=None):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=credential.version_id,
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(handler),
        )
        agent = WeakPasswordPolicyAgent(
            client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
        )
        auth_sessions = sessions or {
            credential.id: AuthenticatedSession(credential_set_id=credential.id, cookies={"sid": "initial"})
        }
        findings = await agent.run(forms, auth_sessions, [credential])
        await client.aclose()
        return findings


async def test_weak_password_accepted_and_confirmed_via_relogin(db_adapter):
    credential = _credential()
    state = {"password": _ORIGINAL_PASSWORD}

    findings = await _run_agent(
        db_adapter, _make_handler(state, accepts_weak_password=True), [_change_password_form()], credential
    )

    assert len(findings) == 1
    assert findings[0].check_id == "weak-password-policy-accepted"
    # The revert must have run regardless of the finding, restoring the
    # account to a state where the *original* password logs in again.
    assert state["password"] == _ORIGINAL_PASSWORD


async def test_password_policy_enforced_yields_no_finding(db_adapter):
    credential = _credential()
    state = {"password": _ORIGINAL_PASSWORD}

    findings = await _run_agent(
        db_adapter, _make_handler(state, accepts_weak_password=False), [_change_password_form()], credential
    )

    assert findings == []
    assert state["password"] == _ORIGINAL_PASSWORD


async def test_login_form_with_single_password_field_is_never_treated_as_change_form(db_adapter):
    credential = _credential()
    state = {"password": _ORIGINAL_PASSWORD}

    findings = await _run_agent(
        db_adapter, _make_handler(state, accepts_weak_password=True), [_login_form_only()], credential
    )

    assert findings == []
    assert state["password"] == _ORIGINAL_PASSWORD  # never even attempted


async def test_api_token_credential_is_skipped(db_adapter):
    credential = _api_token_credential()
    state = {"password": _ORIGINAL_PASSWORD}
    sessions = {credential.id: AuthenticatedSession(credential_set_id=credential.id, bearer_token="jwt.abc")}

    findings = await _run_agent(
        db_adapter, _make_handler(state, accepts_weak_password=True), [_change_password_form()], credential, sessions
    )

    assert findings == []


async def test_revert_failure_logs_critical_and_never_raises(db_adapter, caplog):
    credential = _credential()
    state = {"password": _ORIGINAL_PASSWORD}

    with caplog.at_level(logging.CRITICAL, logger="app.agents.weak_password_policy"):
        findings = await _run_agent(
            db_adapter,
            _make_handler(state, accepts_weak_password=True, revert_allowed=False),
            [_change_password_form()],
            credential,
        )

    # The finding itself is still reported — the vulnerability is real —
    # but the broken revert must be surfaced loudly, not swallowed.
    assert len(findings) == 1
    assert any(record.levelno == logging.CRITICAL for record in caplog.records)
    assert "FAILED TO REVERT" in caplog.text
    # The account is genuinely left on the weak password in this
    # scenario — that's the whole point of the CRITICAL log existing.
    assert state["password"] == "x"
