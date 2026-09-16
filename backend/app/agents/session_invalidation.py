"""Failure to Invalidate Session on Logout (ported from a sibling DAST
project) — log in via a dedicated, disposable session, hit the app's
real logout endpoint, then try to reuse the pre-logout session and
confirm it's rejected.

Two things make this check easy to get silently wrong, both already
guarded against here:

1. app.agents.recon deliberately excludes logout links from the normal
   crawl (following one would kill the one shared session every other
   concurrent agent depends on) — but it captures them separately as
   discovered_logout_urls specifically so this check has something real
   to test. Relying on discovered_endpoints here would make this check
   permanently, silently unable to find a logout URL at all.
2. This check must log in for itself via a throwaway SessionManager call
   (never the `sessions` dict every other agent shares) — deliberately
   invalidating a session other concurrent agents are still using mid-
   scan would break them in exactly the way recon's own logout-avoidance
   already exists to prevent.

The "still logged in" oracle is a real differential, not a guess: recon's
own pre-login (anonymous) crawl already captured what an anonymous
visitor sees at the target's home page. If a request made *after* logout,
using only the pre-logout session, still produces a response that looks
authenticated (meaningfully different from that anonymous baseline,
not a redirect/4xx), the session was never actually destroyed
server-side. difflib's SequenceMatcher gives a cheap, dependency-free
similarity ratio — good enough to tell "same page, different CSRF
token/timestamp" (still similar) apart from "genuinely different page
content" (not similar), without needing real HTML-aware diffing.
"""

import difflib
import uuid

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.agents.login import SessionManager
from app.agents.recon import FormInfo
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.credential import CredentialSet
from app.models.finding import Evidence, Finding
from app.models.target import Target
from app.vault.credential_vault import decrypt_credential

_CATALOG_FILE = "session_invalidation_catalog.yaml"
_SIMILARITY_THRESHOLD = 0.8
_COMPARE_CHARS = 5000


def _home_url_for(target: Target) -> str:
    if target.base_url:
        return target.base_url.rstrip("/") + "/"
    scheme = "https" if target.port == 443 else "http"
    port_suffix = f":{target.port}" if target.port and target.port not in (80, 443) else ""
    return f"{scheme}://{target.host}{port_suffix}/"


def _looks_like_anonymous(response: httpx.Response, anonymous_baseline: httpx.Response) -> bool:
    if response.status_code >= 400 or response.is_redirect:
        return True
    similarity = difflib.SequenceMatcher(
        None, response.text[:_COMPARE_CHARS], anonymous_baseline.text[:_COMPARE_CHARS]
    ).ratio()
    return similarity >= _SIMILARITY_THRESHOLD


class SessionInvalidationAgent:
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
        self._session_manager = SessionManager(client, db_session=db_session)

    async def run(
        self,
        credential_sets: list[CredentialSet],
        forms: list[FormInfo],
        logout_urls: list[str],
        targets: list[Target],
        anonymous_responses: dict[str, httpx.Response],
    ) -> list[Finding]:
        if not logout_urls:
            return []
        home_urls = [
            url for t in targets if (url := _home_url_for(t)) in anonymous_responses
        ]
        if not home_urls:
            # No anonymous baseline available for any target's home page
            # (e.g. it errored during the pre-login crawl) — nothing
            # trustworthy to diff a post-logout response against, so
            # this check has no real signal here rather than guessing.
            return []

        findings: list[Finding] = []
        for credential_set in credential_sets:
            if credential_set.credential_type != "username_password":
                continue  # a bearer token has no server-side "logout" to invalidate
            finding = await self._check_credential(credential_set, forms, logout_urls[0], home_urls[0], anonymous_responses[home_urls[0]])
            if finding is not None:
                findings.append(finding)
        return findings

    async def _cycle(
        self, credential_set: CredentialSet, forms: list[FormInfo], logout_url: str, home_url: str, anonymous_baseline: httpx.Response
    ) -> tuple[httpx.Response, httpx.Response] | None:
        """One full login -> baseline -> logout -> reuse cycle. Returns
        (baseline_authenticated_response, post_logout_reuse_response) or
        None if any step couldn't even be attempted (never a claim of
        "not vulnerable" — just "couldn't test this time").
        """
        username, secret = decrypt_credential(credential_set.encrypted_secret)
        # A dedicated, disposable session — never `sessions` from
        # ScanState, which every other concurrently-running agent is
        # still relying on for the rest of this scan.
        disposable_session = await self._session_manager.login_with_credentials(
            credential_set, forms, username=username, secret=secret
        )
        if disposable_session is None:
            return None

        try:
            baseline = await self._client.get(home_url, session=disposable_session)
        except (ScopeViolationError, httpx.HTTPError):
            return None
        if _looks_like_anonymous(baseline, anonymous_baseline):
            # This target's home page doesn't actually distinguish
            # authenticated from anonymous visitors — no real signal to
            # diff a post-logout response against for this target.
            return None

        try:
            await self._client.get(logout_url, session=disposable_session)
        except (ScopeViolationError, httpx.HTTPError):
            return None

        try:
            post_logout = await self._client.get(home_url, session=disposable_session)
        except (ScopeViolationError, httpx.HTTPError):
            return None

        return baseline, post_logout

    async def _check_credential(
        self, credential_set: CredentialSet, forms: list[FormInfo], logout_url: str, home_url: str, anonymous_baseline: httpx.Response
    ) -> Finding | None:
        result = await self._cycle(credential_set, forms, logout_url, home_url, anonymous_baseline)
        if result is None:
            return None
        _baseline, post_logout = result
        if _looks_like_anonymous(post_logout, anonymous_baseline):
            return None  # correctly invalidated

        # §2 step 1: deterministic re-execution — a fresh login/logout
        # cycle, not just re-checking the same one response.
        result2 = await self._cycle(credential_set, forms, logout_url, home_url, anonymous_baseline)
        if result2 is None:
            return None
        _baseline2, post_logout2 = result2
        if _looks_like_anonymous(post_logout2, anonymous_baseline):
            return None

        return await self._build_finding(credential_set, logout_url, post_logout2)

    async def _build_finding(
        self, credential_set: CredentialSet, logout_url: str, post_logout_response: httpx.Response
    ) -> Finding:
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
            affected_endpoints=[logout_url],
            plain_language_summary=check_def.plain_language_summary,
            technical_description=render_check_template(check_def.technical_description, logout_url, {}),
            steps_to_reproduce=[
                f"1. Log in as {credential_set.label} and note the session cookie/token.",
                f"2. Visit {logout_url} to log out.",
                "3. Replay any request using the same pre-logout cookie/token — observe it still "
                "returns an authenticated-looking response, confirmed here across two independent "
                "login-logout-reuse cycles, each compared against a real anonymous-visitor baseline.",
            ],
            remediation=check_def.remediation,
            references=[*check_def.references, check_def.portswigger_reference_url],
            confirmation_status="ai_confirmed",
        )
        request_raw = format_request_raw(post_logout_response)
        response_raw = format_response_raw(post_logout_response)
        # The exact proof: the pre-logout Cookie header, reused after
        # logout, that the server still accepted.
        payload = post_logout_response.request.headers.get("cookie")
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()
            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=request_raw,
                    response_raw=response_raw,
                    payload=payload,
                )
            )
            await self._session.commit()
        return finding
