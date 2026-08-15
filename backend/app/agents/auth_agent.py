import re
import uuid

import httpx
import jwt

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient, ScopeViolationError
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.finding import Evidence, Finding

_CATALOG_FILE = "auth_catalog.yaml"
_MIN_TOKEN_LENGTH = 16
_NUMERIC_RE = re.compile(r"^\d+$")


def find_logout_url(endpoints: list[str]) -> str | None:
    for url in endpoints:
        if "logout" in url.lower():
            return url
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

            for cookie_name, cookie_value in auth_session.cookies.items():
                entropy_finding = await self._check_token_entropy(
                    cookie_value, f"cookie '{cookie_name}'"
                )
                if entropy_finding is not None:
                    findings.append(entropy_finding)

            logout_finding = await self._check_logout_invalidation(auth_session, endpoints)
            if logout_finding is not None:
                findings.append(logout_finding)

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

    async def _check_logout_invalidation(
        self, auth_session: AuthenticatedSession, endpoints: list[str]
    ) -> Finding | None:
        logout_url = find_logout_url(endpoints)
        protected_candidates = [e for e in endpoints if e != logout_url]
        if logout_url is None or not protected_candidates:
            return None
        protected_url = protected_candidates[0]

        try:
            before = await self._client.get(protected_url, session=auth_session)
            if before.status_code >= 400:
                return None
            await self._client.get(logout_url, session=auth_session)
            after = await self._client.get(protected_url, session=auth_session)
        except (ScopeViolationError, httpx.HTTPError):
            return None

        if after.status_code >= 400:
            return None

        # §2 step 1: deterministic re-verification before confirming.
        try:
            after_again = await self._client.get(protected_url, session=auth_session)
        except (ScopeViolationError, httpx.HTTPError):
            return None
        if after_again.status_code >= 400:
            return None

        check_def = get_check("session-not-invalidated-on-logout", filename=_CATALOG_FILE)
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="session-not-invalidated-on-logout",
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
                check_def.technical_description, protected_url, {"logout_url": logout_url}
            ),
            steps_to_reproduce=[
                f"1. Log in and confirm {protected_url} is accessible (returns a non-error status).",
                f"2. Call the logout endpoint: {logout_url}",
                f"3. Request {protected_url} again with the same session credential and observe "
                "it still succeeds instead of being rejected.",
            ],
            remediation=check_def.remediation,
            references=[*check_def.references, check_def.portswigger_reference_url],
            confirmation_status="ai_confirmed",
        )
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()
            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=format_request_raw(after_again),
                    response_raw=format_response_raw(after_again),
                )
            )
            await self._session.commit()
        return finding

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
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()
            self._session.add(
                Evidence(finding_id=finding.id, request_raw=request_raw, response_raw=response_raw)
            )
            await self._session.commit()
        return finding
