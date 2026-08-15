import base64
import json
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import jwt as pyjwt
from sqlalchemy import select

from app.agents.auth_agent import AuthAgent, decode_jwt_unverified, entropy_issue, find_logout_url
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.models.finding import Finding
from app.models.project import ScopeEntry
from tests.conftest import session_scope


def _unsigned_jwt(payload: dict) -> str:
    def b64(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    header = {"alg": "none", "typ": "JWT"}
    return f"{b64(header)}.{b64(payload)}."


def test_decode_jwt_unverified_rejects_non_jwt_strings():
    assert decode_jwt_unverified("not-a-jwt") is None
    assert decode_jwt_unverified("abc.def.ghi.jkl") is None


def test_decode_jwt_unverified_parses_real_jwt():
    token = pyjwt.encode({"sub": "user1", "exp": datetime.now(timezone.utc) + timedelta(hours=1)}, "a-32-byte-plus-test-signing-secret-key", algorithm="HS256")
    decoded = decode_jwt_unverified(token)
    assert decoded is not None
    header, payload = decoded
    assert header["alg"] == "HS256"
    assert payload["sub"] == "user1"


def test_entropy_issue_flags_short_and_numeric_tokens():
    assert entropy_issue("short") == "shorter than 16 characters"
    assert entropy_issue("12345678901234567890") == "purely numeric"
    assert entropy_issue("a-reasonably-long-random-looking-token-abc123") is None


def test_find_logout_url():
    endpoints = ["http://x/", "http://x/account", "http://x/rest/user/logout"]
    assert find_logout_url(endpoints) == "http://x/rest/user/logout"
    assert find_logout_url(["http://x/", "http://x/about"]) is None


def _handler_vulnerable_logout(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url == "http://site.test/logout":
        return httpx.Response(200, text="logged out")
    if url == "http://site.test/account":
        # Always succeeds regardless of logout — the vulnerability.
        return httpx.Response(200, text="account details")
    return httpx.Response(404)


def _make_safe_logout_handler():
    # ScopedHttpClient deliberately never re-reads Set-Cookie into future
    # requests (it's per-request/per-identity by design, see
    # app/agents/http_client.py) — it always re-sends whatever cookie
    # value the AuthenticatedSession was given. So a realistic "safe"
    # fixture needs its own server-side state tracking that the session
    # was logged out, exactly like a real app invalidating server-side.
    state = {"logged_out": False}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == "http://site.test/logout":
            state["logged_out"] = True
            return httpx.Response(200, text="logged out")
        if url == "http://site.test/account":
            if state["logged_out"]:
                return httpx.Response(401, text="unauthorized")
            return httpx.Response(200, text="account details")
        return httpx.Response(404)

    return handler


async def _run_auth_agent(db_adapter, handler, sessions):
    # Deliberately does not return the session — it belongs to the
    # session_scope() context manager below and is closed the moment this
    # function returns. Callers that need to verify persistence should
    # open their own fresh session_scope(db_adapter) block.
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(handler),
        )
        agent = AuthAgent(client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session)
        findings = await agent.run(sessions, ["http://site.test/logout", "http://site.test/account"])
        await client.aclose()
        return findings


async def test_logout_does_not_invalidate_session_is_flagged(db_adapter):
    cred_id = uuid.uuid4()
    sessions = {cred_id: AuthenticatedSession(credential_set_id=cred_id, cookies={"sid": "valid-session-token"})}

    findings = await _run_auth_agent(db_adapter, _handler_vulnerable_logout, sessions)

    check_ids = {f.check_id for f in findings}
    assert "session-not-invalidated-on-logout" in check_ids
    assert all(f.id is not None for f in findings)  # persisted (session.flush() assigned an id)

    async with session_scope(db_adapter) as session:
        result = await session.execute(select(Finding))
        assert len(result.scalars().all()) == len(findings)


async def test_logout_properly_invalidates_session_is_not_flagged(db_adapter):
    cred_id = uuid.uuid4()
    sessions = {cred_id: AuthenticatedSession(credential_set_id=cred_id, cookies={"sid": "valid-session-token"})}

    findings = await _run_auth_agent(db_adapter, _make_safe_logout_handler(), sessions)

    check_ids = {f.check_id for f in findings}
    assert "session-not-invalidated-on-logout" not in check_ids


async def test_jwt_alg_none_is_flagged(db_adapter):
    token = _unsigned_jwt({"sub": "user1", "exp": 9999999999})
    cred_id = uuid.uuid4()
    sessions = {cred_id: AuthenticatedSession(credential_set_id=cred_id, bearer_token=token)}

    findings = await _run_auth_agent(db_adapter, _make_safe_logout_handler(), sessions)

    check_ids = {f.check_id for f in findings}
    assert "jwt-alg-none" in check_ids


async def test_jwt_missing_expiration_is_flagged(db_adapter):
    token = pyjwt.encode({"sub": "user1"}, "a-32-byte-plus-test-signing-secret-key", algorithm="HS256")
    cred_id = uuid.uuid4()
    sessions = {cred_id: AuthenticatedSession(credential_set_id=cred_id, bearer_token=token)}

    findings = await _run_auth_agent(db_adapter, _make_safe_logout_handler(), sessions)

    check_ids = {f.check_id for f in findings}
    assert "jwt-missing-expiration" in check_ids


async def test_healthy_jwt_is_not_flagged(db_adapter):
    token = pyjwt.encode(
        {"sub": "user1", "exp": datetime.now(timezone.utc) + timedelta(hours=1)}, "a-32-byte-plus-test-signing-secret-key", algorithm="HS256"
    )
    cred_id = uuid.uuid4()
    sessions = {cred_id: AuthenticatedSession(credential_set_id=cred_id, bearer_token=token)}

    findings = await _run_auth_agent(db_adapter, _make_safe_logout_handler(), sessions)

    check_ids = {f.check_id for f in findings}
    assert "jwt-alg-none" not in check_ids
    assert "jwt-missing-expiration" not in check_ids


async def test_weak_cookie_entropy_is_flagged(db_adapter):
    cred_id = uuid.uuid4()
    sessions = {cred_id: AuthenticatedSession(credential_set_id=cred_id, cookies={"sid": "12345"})}

    findings = await _run_auth_agent(db_adapter, _make_safe_logout_handler(), sessions)

    check_ids = {f.check_id for f in findings}
    assert "weak-session-token-entropy" in check_ids
