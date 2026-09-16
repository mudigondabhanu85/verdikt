import base64
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from app.agents.auth_agent import AuthAgent, decode_jwt_unverified, entropy_issue
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
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


async def test_jwt_signed_with_weak_secret_is_flagged(db_adapter):
    token = pyjwt.encode({"sub": "user1", "exp": 9999999999}, "secret", algorithm="HS256")
    cred_id = uuid.uuid4()
    sessions = {cred_id: AuthenticatedSession(credential_set_id=cred_id, bearer_token=token)}

    findings = await _run_auth_agent(db_adapter, _make_safe_logout_handler(), sessions)

    check_ids = {f.check_id for f in findings}
    assert "jwt-weak-signing-secret" in check_ids
    weak_finding = next(f for f in findings if f.check_id == "jwt-weak-signing-secret")
    assert weak_finding.severity == "Critical"


async def test_jwt_signed_with_strong_secret_is_not_flagged_as_weak(db_adapter):
    token = pyjwt.encode(
        {"sub": "user1", "exp": 9999999999}, "a-32-byte-plus-test-signing-secret-key", algorithm="HS256"
    )
    cred_id = uuid.uuid4()
    sessions = {cred_id: AuthenticatedSession(credential_set_id=cred_id, bearer_token=token)}

    findings = await _run_auth_agent(db_adapter, _make_safe_logout_handler(), sessions)

    check_ids = {f.check_id for f in findings}
    assert "jwt-weak-signing-secret" not in check_ids


def _rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
    )
    return private_key, private_pem


def _jwks_body(public_key) -> str:
    jwk = json.loads(pyjwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": "test-key-1", "alg": "RS256", "use": "sig"})
    return json.dumps({"keys": [jwk]})


async def _run_auth_agent_with_endpoints(db_adapter, handler, sessions, endpoints):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(handler),
        )
        agent = AuthAgent(client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session)
        findings = await agent.run(sessions, endpoints)
        await client.aclose()
        return findings


async def test_jwt_alg_confusion_accepted_by_vulnerable_server_is_flagged(db_adapter):
    private_key, private_pem = _rsa_keypair()
    public_key = private_key.public_key()
    real_token = pyjwt.encode({"sub": "user1", "exp": 9999999999}, private_pem, algorithm="RS256")
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
    )

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == "http://site.test/.well-known/jwks.json":
            return httpx.Response(200, text=_jwks_body(public_key))
        if url == "http://site.test/account":
            auth = request.headers.get("authorization", "")
            token = auth.removeprefix("Bearer ")
            header = pyjwt.get_unverified_header(token)
            # The vulnerable behavior under test: the server trusts
            # whatever alg the token's own header claims, rather than
            # pinning RS256, so it verifies an HS256-signed forgery using
            # the public key as the HMAC secret — verified here via raw
            # HMAC (not pyjwt.decode(), which added its own guard against
            # exactly this misuse; this fixture simulates a server/library
            # that predates or lacks that guard, which is the real-world
            # vulnerable condition this check exists to catch).
            if header.get("alg") != "HS256":
                return httpx.Response(401, text="unauthorized")
            signing_input, _, signature_b64 = token.rpartition(".")
            expected_sig = hmac.new(public_pem, signing_input.encode(), hashlib.sha256).digest()
            actual_sig = base64.urlsafe_b64decode(signature_b64 + "==")
            if not hmac.compare_digest(expected_sig, actual_sig):
                return httpx.Response(401, text="unauthorized")
            return httpx.Response(200, text="account details")
        return httpx.Response(404)

    cred_id = uuid.uuid4()
    sessions = {cred_id: AuthenticatedSession(credential_set_id=cred_id, bearer_token=real_token)}
    endpoints = ["http://site.test/.well-known/jwks.json", "http://site.test/account"]

    findings = await _run_auth_agent_with_endpoints(db_adapter, handler, sessions, endpoints)

    check_ids = {f.check_id for f in findings}
    assert "jwt-alg-confusion" in check_ids
    finding = next(f for f in findings if f.check_id == "jwt-alg-confusion")
    assert finding.severity == "Critical"


async def test_jwt_alg_confusion_rejected_by_safe_server_is_not_flagged(db_adapter):
    private_key, private_pem = _rsa_keypair()
    public_key = private_key.public_key()
    real_token = pyjwt.encode({"sub": "user1", "exp": 9999999999}, private_pem, algorithm="RS256")
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
    )

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == "http://site.test/.well-known/jwks.json":
            return httpx.Response(200, text=_jwks_body(public_key))
        if url == "http://site.test/account":
            auth = request.headers.get("authorization", "")
            token = auth.removeprefix("Bearer ")
            try:
                # The safe behavior: algorithm is pinned to RS256
                # explicitly, so the HS256 forgery is rejected outright.
                pyjwt.decode(token, public_pem, algorithms=["RS256"])
            except pyjwt.InvalidTokenError:
                return httpx.Response(401, text="unauthorized")
            return httpx.Response(200, text="account details")
        return httpx.Response(404)

    cred_id = uuid.uuid4()
    sessions = {cred_id: AuthenticatedSession(credential_set_id=cred_id, bearer_token=real_token)}
    endpoints = ["http://site.test/.well-known/jwks.json", "http://site.test/account"]

    findings = await _run_auth_agent_with_endpoints(db_adapter, handler, sessions, endpoints)

    check_ids = {f.check_id for f in findings}
    assert "jwt-alg-confusion" not in check_ids
