"""Weak Password Policy (ported from a sibling DAST project) — detects a
change-password form (not the login form, and not registration) and
confirms the server actually accepts a brand-new, single-character
password with no minimum-length/complexity enforcement.

Fully deterministic, no LLM anywhere in this path: "did a real login with
the new password succeed" is ground truth already, not something an AI
verdict could add confidence on top of. The confirmation step is a real
re-login with the new password (app.agents.login.SessionManager), not
just trusting the change-password endpoint's own response — a form that
always returns 200 regardless of whether anything actually changed would
otherwise be a guaranteed false positive.

This is the one check in the whole suite that must leave the target in a
different state than it found it — changing a real account's password is
inherently state-mutating, unlike every other agent's read-only-or-
reverted-by-construction probes (CSRF's forged-origin POST, for instance,
performs a real state change too, but to a value the analyst chose and
the app already exposes normally — there's nothing to "revert"). That
asymmetry is exactly why the revert in `finally` below isn't optional
cleanup, it's the actual safety mechanism that makes running this check
at all defensible. A revert that silently fails is a real incident (a
test account now locked to a throwaway one-character password) — logged
at CRITICAL, never swallowed the way "this candidate didn't pan out" is
swallowed everywhere else in this codebase.

Registration forms are explicitly out of scope: a registration form has
no "current password" to revert to and no known-good account state to
restore — there is no safe revert path, so weakening a check to skip the
revert for registration would violate the same safety invariant this
whole agent exists to uphold.
"""

import logging
import uuid
from urllib.parse import urlencode

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.evidence_screenshot import capture_and_store_evidence_screenshot
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient, ScopeViolationError
from app.agents.login import SessionManager, _live_field_values
from app.agents.recon import FormInfo
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.credential import CredentialSet
from app.models.finding import Evidence, Finding
from app.vault.credential_vault import decrypt_credential

logger = logging.getLogger(__name__)

_CATALOG_FILE = "weak_password_policy_catalog.yaml"
_WEAK_PASSWORD = "x"
_CURRENT_FIELD_MARKERS = ("current", "old", "existing")


def _is_current_password_field(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in _CURRENT_FIELD_MARKERS)


def _is_change_password_form(form: FormInfo) -> bool:
    # A login form structurally has exactly one password field; a
    # registration form usually has exactly one too (password +
    # confirm-password registration forms exist, but §1's explicit
    # carve-out means it doesn't matter here — see module docstring).
    # >=2 password-typed fields is both necessary (a change-password form
    # always needs at least new + confirm, often current + new + confirm)
    # and, in practice, sufficient to exclude login/registration without
    # a separate cross-check against whichever form recon happened to
    # also classify as "the" login form.
    return form.method == "POST" and sum(1 for f in form.fields if f.type == "password") >= 2


class WeakPasswordPolicyAgent:
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
        forms: list[FormInfo],
        sessions: dict[uuid.UUID, AuthenticatedSession],
        credential_sets: list[CredentialSet],
    ) -> list[Finding]:
        findings: list[Finding] = []
        credentials_by_id = {c.id: c for c in credential_sets}
        change_forms = [f for f in forms if _is_change_password_form(f)]
        if not change_forms:
            return findings

        for credential_set_id, auth_session in sessions.items():
            credential_set = credentials_by_id.get(credential_set_id)
            # api_token credentials have no password to change or revert —
            # there is no "current secret" that means anything here.
            if credential_set is None or credential_set.credential_type != "username_password":
                continue
            for form in change_forms:
                finding = await self._check_form(form, auth_session, credential_set, forms)
                if finding is not None:
                    findings.append(finding)
        return findings

    async def _submit_change(
        self,
        form: FormInfo,
        auth_session: AuthenticatedSession,
        *,
        current_value: str,
        new_value: str,
    ) -> httpx.Response | None:
        password_fields = [f for f in form.fields if f.type == "password"]
        current_field = next((f for f in password_fields if _is_current_password_field(f.name)), None)
        new_fields = [f for f in password_fields if f is not current_field]

        try:
            pre = await self._client.get(form.action_url, session=auth_session)
        except (ScopeViolationError, httpx.HTTPError):
            return None

        payload: dict[str, str] = {}
        if current_field is not None:
            payload[current_field.name] = current_value
        for field in new_fields:
            payload[field.name] = new_value
        other_names = {
            f.name for f in form.fields if f.type in ("hidden", "submit") and f.name not in payload
        }
        live_values = _live_field_values(pre.text, other_names)
        for name in other_names:
            payload[name] = live_values.get(name, "")

        try:
            return await self._client.post(
                form.action_url,
                body=urlencode(payload),
                content_type="application/x-www-form-urlencoded",
                session=auth_session,
            )
        except (ScopeViolationError, httpx.HTTPError):
            return None

    async def _try_login(
        self, credential_set: CredentialSet, all_forms: list[FormInfo], *, username: str, password: str
    ) -> AuthenticatedSession | None:
        try:
            return await self._session_manager.login_with_credentials(
                credential_set, all_forms, username=username, secret=password
            )
        except (ScopeViolationError, httpx.HTTPError):
            return None

    async def _check_form(
        self,
        form: FormInfo,
        auth_session: AuthenticatedSession,
        credential_set: CredentialSet,
        all_forms: list[FormInfo],
    ) -> Finding | None:
        original_username, original_secret = decrypt_credential(credential_set.encrypted_secret)

        change_response = await self._submit_change(
            form, auth_session, current_value=original_secret, new_value=_WEAK_PASSWORD
        )
        if change_response is None or change_response.status_code >= 400:
            # Rejected outright (or unreachable) — nothing was changed,
            # so there is nothing to revert.
            return None

        # From here on the target may genuinely be in a changed state
        # regardless of what we conclude below, so every exit path must
        # go through the revert in `finally`.
        try:
            relogin_session = await self._try_login(
                credential_set, all_forms, username=original_username, password=_WEAK_PASSWORD
            )
            if relogin_session is None:
                # The change-password endpoint returned success without
                # actually changing anything (a common false-positive
                # shape: a 200 status with an inline validation-error
                # message in the body) — confirmed via re-login, not
                # assumed from the HTTP status alone.
                return None

            return await self._build_finding(form, change_response)
        finally:
            await self._revert(form, auth_session, credential_set, original_username, original_secret, all_forms)

    async def _revert(
        self,
        form: FormInfo,
        auth_session: AuthenticatedSession,
        credential_set: CredentialSet,
        original_username: str,
        original_secret: str,
        all_forms: list[FormInfo],
    ) -> None:
        revert_response = await self._submit_change(
            form, auth_session, current_value=_WEAK_PASSWORD, new_value=original_secret
        )
        revert_ok = revert_response is not None and revert_response.status_code < 400
        if revert_ok:
            relogin_session = await self._try_login(
                credential_set, all_forms, username=original_username, password=original_secret
            )
            revert_ok = relogin_session is not None

        if not revert_ok:
            logger.critical(
                "WEAK PASSWORD POLICY CHECK FAILED TO REVERT credential_set_id=%s (label=%r) at %s "
                "back to its original password after testing a one-character password. This test "
                "account is likely now locked to the throwaway password '%s' and needs MANUAL "
                "remediation — this is a real incident, not a scan artifact.",
                credential_set.id,
                credential_set.label,
                form.action_url,
                _WEAK_PASSWORD,
            )

    async def _build_finding(self, form: FormInfo, change_response: httpx.Response) -> Finding:
        check_def = get_check("weak-password-policy-accepted", filename=_CATALOG_FILE)
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="weak-password-policy-accepted",
            title=check_def.title,
            severity=check_def.severity,
            owasp_2025_category=check_def.owasp_2025_category,
            cwe_id=check_def.cwe_id,
            portswigger_reference_url=check_def.portswigger_reference_url,
            cvss_vector=check_def.cvss_vector,
            cvss_score=check_def.cvss_score,
            affected_endpoints=[form.action_url],
            plain_language_summary=check_def.plain_language_summary,
            technical_description=render_check_template(check_def.technical_description, form.action_url, {}),
            steps_to_reproduce=[
                f"1. As a logged-in user, submit the change-password form at {form.action_url} "
                f'with a new password of a single character (e.g. "{_WEAK_PASSWORD}").',
                "2. Observe the server accepts the change.",
                "3. Log out and log back in using only that one-character password — confirmed "
                "successful here via a real re-authentication, not inferred from the change "
                "form's response alone.",
            ],
            remediation=check_def.remediation,
            references=[*check_def.references, check_def.portswigger_reference_url],
            confirmation_status="ai_confirmed",
        )
        request_raw = format_request_raw(change_response)
        response_raw = format_response_raw(change_response)
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
                    payload=_WEAK_PASSWORD,
                )
            )
            await self._session.commit()
        return finding
