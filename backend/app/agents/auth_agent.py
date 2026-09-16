import base64
import hashlib
import hmac
import json
import re
import uuid

import httpx
import jwt
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.evidence_screenshot import capture_and_store_evidence_screenshot
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient, ScopeViolationError
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.finding import Evidence, Finding

_CATALOG_FILE = "auth_catalog.yaml"
_MIN_TOKEN_LENGTH = 16
_NUMERIC_RE = re.compile(r"^\d+$")

# A small, well-known wordlist of default/example JWT secrets that show
# up in tutorials and unchanged boilerplate — not a general password
# cracker (§1.2 safe-by-default: this is a handful of offline signature
# verifications against a token we already hold, not a brute-force
# attack against the live server).
_WEAK_JWT_SECRETS = [
    "secret",
    "your-256-bit-secret",
    "changeme",
    "change-me",
    "password",
    "jwt_secret",
    "jwtsecret",
    "your-secret-key",
    "supersecret",
    "secretkey",
    "mysecret",
    "123456",
    "qwerty",
]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def forge_hs256_token(payload: dict, secret: bytes) -> str:
    """Manually constructs an HS256 JWT rather than going through
    jwt.encode() — PyJWT (correctly, for legitimate use) refuses to sign
    with a PEM-formatted key, but that refusal is exactly the mistake
    the algorithm-confusion attack this simulates exploits: a vulnerable
    server's *verification* code trusts the token's own "alg" header and
    ends up treating an RSA public key as a raw HMAC secret. Mirrors what
    real tooling (e.g. jwt_tool) does for this specific test.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(payload).encode())}"
    signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url(signature)}"


def find_jwks_url(endpoints: list[str]) -> str | None:
    for url in endpoints:
        lowered = url.lower()
        if "jwks" in lowered or ".well-known/jwks.json" in lowered:
            return url
    return None


def extract_rsa_public_pem(jwks_body: str) -> bytes | None:
    """Parses a JWKS document and returns the first RSA public key found,
    PEM-encoded — used to test JWT algorithm confusion (RS256 -> HS256),
    not to forge anything against key material that isn't already
    published by the server itself.
    """
    try:
        doc = json.loads(jwks_body)
        for jwk in doc.get("keys", []):
            if jwk.get("kty") != "RSA":
                continue
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
            return public_key.public_bytes(
                encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
            )
    except (json.JSONDecodeError, KeyError, ValueError, TypeError):
        return None
    return None


def decode_jwt_unverified(token: str) -> tuple[dict, dict] | None:
    """Decodes a JWT's header+payload WITHOUT verifying the signature —
    we're inspecting what the server issued, not attempting to forge
    anything. Returns None if the token doesn't parse as a JWT at all."""
    if token.count(".") != 2:
        return None
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
    except (jwt.InvalidTokenError, jwt.DecodeError, ValueError):
        return None
    return header, payload


def entropy_issue(token: str) -> str | None:
    """Returns a human-readable reason if the token looks low-entropy,
    else None. Deliberately conservative — only flags clear cases."""
    if len(token) < _MIN_TOKEN_LENGTH:
        return "shorter than 16 characters"
    if _NUMERIC_RE.match(token):
        return "purely numeric"
    return None


class AuthAgent:
    """Deterministic authentication checks (§3, A07) — no LLM needed.
    Safe-by-default (§1.2): no brute-force/lockout testing, everything
    here is a handful of read-only or single-state-change requests.
    """

    def __init__(
        self,
        client: ScopedHttpClient,
        *,
        scan_run_id: uuid.UUID,
        agent_job_id: uuid.UUID,
        db_session,
    ):
        self._client = client
        self._scan_run_id = scan_run_id
        self._agent_job_id = agent_job_id
        self._session = db_session

    async def run(
        self,
        sessions: dict[uuid.UUID, AuthenticatedSession],
        endpoints: list[str],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for credential_set_id, auth_session in sessions.items():
            if auth_session.bearer_token:
                jwt_findings = await self._check_jwt(auth_session)
                findings.extend(jwt_findings)
                entropy_finding = await self._check_token_entropy(
                    auth_session.bearer_token, "bearer token"
                )
                if entropy_finding is not None:
                    findings.append(entropy_finding)

                weak_secret_finding = await self._check_jwt_weak_secret(auth_session)
                if weak_secret_finding is not None:
                    findings.append(weak_secret_finding)

                alg_confusion_finding = await self._check_jwt_alg_confusion(auth_session, endpoints)
                if alg_confusion_finding is not None:
                    findings.append(alg_confusion_finding)

            for cookie_name, cookie_value in auth_session.cookies.items():
                entropy_finding = await self._check_token_entropy(
                    cookie_value, f"cookie '{cookie_name}'"
                )
                if entropy_finding is not None:
                    findings.append(entropy_finding)

        return findings

    async def _check_jwt(self, auth_session: AuthenticatedSession) -> list[Finding]:
        decoded = decode_jwt_unverified(auth_session.bearer_token)
        if decoded is None:
            return []
        header, payload = decoded

        findings = []
        if str(header.get("alg", "")).lower() == "none":
            findings.append(await self._persist_static(
                "jwt-alg-none", url="(issued session token)", request_raw=auth_session.bearer_token,
                response_raw=f"header={header}\npayload={payload}",
            ))
        if "exp" not in payload:
            findings.append(await self._persist_static(
                "jwt-missing-expiration", url="(issued session token)",
                request_raw=auth_session.bearer_token, response_raw=f"header={header}\npayload={payload}",
            ))
        return findings

    async def _check_jwt_weak_secret(self, auth_session: AuthenticatedSession) -> Finding | None:
        """Zero extra HTTP requests — purely an offline signature
        verification of the token we already hold against a small
        well-known wordlist (§1.2: not a live brute-force attack)."""
        decoded = decode_jwt_unverified(auth_session.bearer_token)
        if decoded is None:
            return None
        header, _payload = decoded
        alg = str(header.get("alg", "")).upper()
        if alg not in ("HS256", "HS384", "HS512"):
            return None

        matched_secret = None
        for candidate in _WEAK_JWT_SECRETS:
            try:
                jwt.decode(auth_session.bearer_token, candidate, algorithms=[header["alg"]])
                matched_secret = candidate
                break
            except jwt.InvalidTokenError:
                continue
        if matched_secret is None:
            return None

        check_def = get_check("jwt-weak-signing-secret", filename=_CATALOG_FILE)
        extra = {"matched_secret_hint": f'"{matched_secret}"'}
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="jwt-weak-signing-secret",
            title=check_def.title,
            severity=check_def.severity,
            owasp_2025_category=check_def.owasp_2025_category,
            cwe_id=check_def.cwe_id,
            portswigger_reference_url=check_def.portswigger_reference_url,
            cvss_vector=check_def.cvss_vector,
            cvss_score=check_def.cvss_score,
            affected_endpoints=["(issued session token)"],
            plain_language_summary=check_def.plain_language_summary,
            technical_description=render_check_template(
                check_def.technical_description, "(issued session token)", extra
            ),
            steps_to_reproduce=[
                "1. Obtain a session for this application and inspect the issued JWT.",
                "2. Attempt to verify its signature against a small list of well-known weak "
                'secrets (e.g. "secret", "changeme", "password", ...).',
                f"3. Observe the token's signature verifies successfully against {matched_secret!r}.",
            ],
            remediation=check_def.remediation,
            references=[*check_def.references, check_def.portswigger_reference_url],
            confirmation_status="ai_confirmed",
        )
        request_raw = auth_session.bearer_token
        response_raw = f"header={header}\nmatched weak secret: {matched_secret!r}"
        screenshot_refs = await capture_and_store_evidence_screenshot(
            scan_run_id=self._scan_run_id,
            check_id=finding.check_id,
            title=finding.title,
            request_raw=request_raw,
            response_raw=response_raw,
        )
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()
            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=request_raw,
                    response_raw=response_raw,
                    screenshot_refs=screenshot_refs,
                )
            )
            await self._session.commit()
        return finding

    async def _check_jwt_alg_confusion(
        self, auth_session: AuthenticatedSession, endpoints: list[str]
    ) -> Finding | None:
        decoded = decode_jwt_unverified(auth_session.bearer_token)
        if decoded is None:
            return None
        header, payload = decoded
        if str(header.get("alg", "")).upper() not in ("RS256", "RS384", "RS512"):
            return None

        jwks_url = find_jwks_url(endpoints)
        if jwks_url is None:
            return None

        try:
            jwks_response = await self._client.get(jwks_url)
        except (ScopeViolationError, httpx.HTTPError):
            return None
        if jwks_response.status_code != 200:
            return None

        public_pem = extract_rsa_public_pem(jwks_response.text)
        if public_pem is None:
            return None

        forged_token = forge_hs256_token(dict(payload), public_pem)
        forged_session = AuthenticatedSession(
            credential_set_id=auth_session.credential_set_id, cookies={}, bearer_token=forged_token
        )

        protected_candidates = [e for e in endpoints if e != jwks_url]
        if not protected_candidates:
            return None
        protected_url = protected_candidates[0]

        try:
            response = await self._client.get(protected_url, session=forged_session)
        except (ScopeViolationError, httpx.HTTPError):
            return None
        if response.status_code >= 400:
            return None

        # §2 step 1: deterministic re-execution before confirming.
        try:
            response_again = await self._client.get(protected_url, session=forged_session)
        except (ScopeViolationError, httpx.HTTPError):
            return None
        if response_again.status_code >= 400:
            return None

        check_def = get_check("jwt-alg-confusion", filename=_CATALOG_FILE)
        extra = {"jwks_url": jwks_url}
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="jwt-alg-confusion",
            title=check_def.title,
            severity=check_def.severity,
            owasp_2025_category=check_def.owasp_2025_category,
            cwe_id=check_def.cwe_id,
            portswigger_reference_url=check_def.portswigger_reference_url,
            cvss_vector=check_def.cvss_vector,
            cvss_score=check_def.cvss_score,
            affected_endpoints=[protected_url],
            plain_language_summary=check_def.plain_language_summary,
            technical_description=render_check_template(
                check_def.technical_description, protected_url, extra
            ),
            steps_to_reproduce=[
                f"1. Fetch the server's published JWKS document ({jwks_url}) and extract its "
                "RSA public key.",
                "2. Take a legitimately-issued RS256 JWT and re-sign it with HS256, using the "
                "RSA public key's raw bytes as the HMAC secret.",
                f"3. Send the re-signed token to {protected_url} and observe it is accepted "
                "as a valid session, despite never being signed with the server's private key.",
            ],
            remediation=check_def.remediation,
            references=[*check_def.references, check_def.portswigger_reference_url],
            confirmation_status="ai_confirmed",
        )
        request_raw = format_request_raw(response_again)
        response_raw = format_response_raw(response_again)
        screenshot_refs = await capture_and_store_evidence_screenshot(
            scan_run_id=self._scan_run_id,
            check_id=finding.check_id,
            title=finding.title,
            request_raw=request_raw,
            response_raw=response_raw,
        )
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()
            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=request_raw,
                    response_raw=response_raw,
                    screenshot_refs=screenshot_refs,
                )
            )
            await self._session.commit()
        return finding

    async def _check_token_entropy(self, token: str, source: str) -> Finding | None:
        issue = entropy_issue(token)
        if issue is None:
            return None
        return await self._persist_static(
            "weak-session-token-entropy",
            url=f"(issued via {source})",
            request_raw=token,
            response_raw=f"token_length={len(token)} pattern_note={issue}",
            extra={"token_length": str(len(token)), "pattern_note": issue},
        )

    async def _persist_static(
        self, check_id: str, *, url: str, request_raw: str, response_raw: str, extra: dict | None = None
    ) -> Finding:
        check_def = get_check(check_id, filename=_CATALOG_FILE)
        extra = extra or {}
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id=check_id,
            title=check_def.title,
            severity=check_def.severity,
            owasp_2025_category=check_def.owasp_2025_category,
            cwe_id=check_def.cwe_id,
            portswigger_reference_url=check_def.portswigger_reference_url,
            cvss_vector=check_def.cvss_vector,
            cvss_score=check_def.cvss_score,
            affected_endpoints=[url],
            plain_language_summary=check_def.plain_language_summary,
            technical_description=render_check_template(check_def.technical_description, url, extra),
            steps_to_reproduce=[
                f"1. Obtain a session for this application and inspect the issued token/cookie.",
                f"2. Observe: {render_check_template(check_def.technical_description, url, extra)}",
            ],
            remediation=check_def.remediation,
            references=[*check_def.references, check_def.portswigger_reference_url],
            confirmation_status="ai_confirmed",
        )
        screenshot_refs = await capture_and_store_evidence_screenshot(
            scan_run_id=self._scan_run_id,
            check_id=finding.check_id,
            title=finding.title,
            request_raw=request_raw,
            response_raw=response_raw,
        )
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()
            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=request_raw,
                    response_raw=response_raw,
                    screenshot_refs=screenshot_refs,
                )
            )
            await self._session.commit()
        return finding
