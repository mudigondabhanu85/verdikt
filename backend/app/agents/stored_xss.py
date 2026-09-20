"""Stored XSS (§3) — submit a marker payload to a form, then revisit
OTHER discovered pages in a real browser and check whether it executes
there. Real script execution on a page different from where the payload
was submitted is the defining, unambiguous signature of stored
(persistent) XSS — as opposed to reflected XSS (payload echoed back in
the SAME request/response, app.agents.xss) or DOM XSS (purely
client-side, no server round trip at all, app.agents.dom_xss).
"""

import asyncio
import uuid
from urllib.parse import urlencode

import httpx
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright

from app.agents.browser_session import seed_authenticated_context
from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient, ScopeViolationError
from app.agents.login import _live_field_values, pick_best_session
from app.agents.recon import FormInfo
from app.agents.xss import XSS_FINDING_METADATA
from app.models.finding import Evidence, Finding
from app.storage.local_disk import get_object_storage

# Bounded like ReconAgent's own crawl (§1.2 safe-by-default / §10 cost
# control) — checking every candidate page per submitted form is
# multiplicative (forms x pages); this caps it to a reasonable set of
# most-likely-to-display-stored-data pages rather than exhaustively
# re-visiting everything recon found.
_MAX_REVISIT_PAGES = 10
_PAGE_TIMEOUT_MS = 8000
# Same defensive backstop as app.agents.http_client's
# _HARD_REQUEST_TIMEOUT_SECONDS — see app.agents.xss_browser_proof's
# identical constant for the real, live-found scan hang this class of
# fix exists for. playwright.chromium.launch() has no timeout of its
# own the way page.goto() does.
_HARD_PROOF_TIMEOUT_SECONDS = 30.0


def _marker() -> str:
    return f"verdikt_stored_{uuid.uuid4().hex[:12]}"


def _proof_banner_js(marker: str) -> str:
    # Same real bug as app.agents.xss_browser_proof.visible_proof_banner_js
    # (the window[marker] flag alone is reliable but invisible, so a
    # screenshot taken right after detecting it looked identical to an
    # unexploited page) — deliberately drawn via a separate page.evaluate()
    # call in _find_execution *after* execution is already confirmed,
    # never embedded in the submitted payload itself. See
    # _stored_xss_payloads' docstring for why that distinction matters
    # here even more than for reflected/DOM XSS: this banner's own text
    # ("appendChild", "createElement", ...) contains the letters
    # s/c/r/i/p/t in that relative order, which is exactly what DVWA
    # High's (and plenty of real WAFs') "does this contain something
    # script-shaped" filter strips — submitting it inline silently
    # mangled the payload into something that could never execute.
    return (
        f'var d=document.createElement("div");d.textContent="XSS POC";'
        f'd.style.cssText="position:fixed;top:30%;left:35%;background:#fff;'
        f'border:3px solid red;padding:8px 16px;z-index:2147483647";'
        f"document.body.appendChild(d);"
    )


# Paired with the payload templates below purely for reporting — a
# Finding's write-up should read as a normal proof-of-concept an analyst
# can act on, not our internal marker/window-flag plumbing verbatim.
_STORED_XSS_DISPLAY_PAYLOADS = (
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(document.domain)>",
)


# Two variants for the same reason app.agents.xss_browser_proof tries
# both: DVWA's own stored-XSS guestbook (§14) sanitizes its 'message'
# field with strip_tags() (which removes ANY tag, no bypass exists) but
# its 'name' field only with the same "does this contain s.c.r.i.p.t"
# regex as its reflected-XSS page — a live, real gap where the first
# payload gets fully stripped and the second survives untouched.
# Deliberately minimal (just the flag-set, no visible banner inline) —
# see _proof_banner_js's docstring for why a longer inline payload
# defeats itself against exactly this filter.
def _stored_xss_payloads(marker: str) -> list[tuple[str, str]]:
    real_payloads = (
        f'<script>window["{marker}"]=true;</script>',
        f'<img src=x onerror=\'window["{marker}"]=true\'>',
    )
    return list(zip(real_payloads, _STORED_XSS_DISPLAY_PAYLOADS))


_BASELINE_FIELD_VALUE = "verdikt1"


def _testable_fields(form: FormInfo) -> list:
    return [f for f in form.fields if f.type not in ("hidden", "submit", "button") and f.name]


def _build_payload_fields(form: FormInfo, target_field: str, payload: str) -> dict[str, str]:
    # Same real bug this class of form-filling already had elsewhere
    # (app.agents.probing.form_probe_targets tests one field at a time
    # for exactly this reason): stuffing the SAME long payload into
    # *every* testable field meant a short, tightly-constrained field
    # (DVWA's guestbook `txtName`, maxlength 10) got the same oversized
    # value as the one actually being tested — and since a single INSERT
    # covers every column at once, that field alone failing MySQL's
    # strict-mode length check silently killed the whole submission,
    # including whichever field's XSS was actually being tested.
    return {
        field.name: payload if field.name == target_field else _BASELINE_FIELD_VALUE
        for field in _testable_fields(form)
    }


class StoredXssAgent:
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
        self._auth_session: AuthenticatedSession | None = None

    async def run(
        self,
        forms: list[FormInfo],
        endpoints: list[str],
        sessions: dict[uuid.UUID, AuthenticatedSession] | None = None,
    ) -> list[Finding]:
        # A real, live-found gap (same class as app.agents.xss_browser_proof's
        # own fix): neither the submission nor the revisit ever carried an
        # authenticated session, so a login-gated form (DVWA's own stored-XSS
        # guestbook included) always just hit the login redirect — the
        # submission silently did nothing, and there was nothing to see on
        # revisit either. One representative identity, same reasoning as
        # app.agents.injection.InjectionAgent.run.
        self._auth_session = pick_best_session(sessions)
        findings: list[Finding] = []
        for form in forms:
            if form.method != "POST":
                continue
            # A real, live-found gap: DVWA's own stored-XSS teaching
            # example (a guestbook) — like plenty of real-world comment
            # threads/review pages — displays what you just submitted
            # right back on the SAME page, not some other one. A plain
            # `endpoints[:N]` slice put the page that actually needs
            # checking last (it's typically only discoverable via the
            # authenticated re-crawl, appended after everything an
            # earlier traffic import already seeded), past the cap far
            # more often than not. Guaranteeing the form's own page is
            # always among the candidates, ahead of everything else,
            # fixes that without discarding the "other pages" case a
            # true cross-page stored XSS needs.
            candidates = list(dict.fromkeys([form.action_url, *endpoints]))[:_MAX_REVISIT_PAGES]
            for field in _testable_fields(form):
                finding = await self._check_form(form, field.name, candidates)
                if finding is not None:
                    findings.append(finding)
        return findings

    async def _submit(self, form: FormInfo, target_field: str, payload: str) -> httpx.Response | None:
        fields = _build_payload_fields(form, target_field, payload)
        # Same real bug already fixed for the login form (app.agents.login):
        # a hidden CSRF token or the submit button's own field
        # (`isset($_POST['btnSign'])`-style checks) is often required for
        # the server to treat the request as a real submission at all —
        # live-found against DVWA's own guestbook, whose stored-XSS
        # "vulnerability" silently no-ops without its submit button field
        # present. Best-effort: a live re-fetch that fails just means this
        # submission proceeds without those fields, same as before.
        other_names = {f.name for f in form.fields if f.type in ("hidden", "submit") and f.name not in fields}
        if other_names:
            try:
                pre_submit = await self._client.get(form.action_url, session=self._auth_session)
            except (ScopeViolationError, httpx.HTTPError):
                pre_submit = None
            if pre_submit is not None:
                fields = {**fields, **_live_field_values(pre_submit.text, other_names)}
        try:
            return await self._client.post(
                form.action_url,
                body=urlencode(fields),
                content_type="application/x-www-form-urlencoded",
                session=self._auth_session,
            )
        except (ScopeViolationError, httpx.HTTPError):
            return None

    async def _find_execution(
        self, marker: str, candidates: list[str]
    ) -> tuple[str, bytes] | None:
        try:
            return await asyncio.wait_for(
                self._find_execution_impl(marker, candidates), timeout=_HARD_PROOF_TIMEOUT_SECONDS
            )
        except (TimeoutError, asyncio.TimeoutError):
            return None

    async def _find_execution_impl(
        self, marker: str, candidates: list[str]
    ) -> tuple[str, bytes] | None:
        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(headless=True)
                # See app.agents.macro's identical fix/rationale — an
                # internal staging target's self-signed/internal-CA
                # cert shouldn't fail this check when the analyst
                # already has authorized, scoped access to it.
                context = await browser.new_context(ignore_https_errors=True)
                if candidates:
                    await seed_authenticated_context(context, self._auth_session, candidates[0])
                page = await context.new_page()
                found: tuple[str, bytes] | None = None
                for url in candidates:
                    try:
                        await page.goto(url, wait_until="networkidle", timeout=_PAGE_TIMEOUT_MS)
                    except PlaywrightError:
                        continue
                    executed = bool(await page.evaluate(f'window["{marker}"] === true'))
                    if executed:
                        # Draw the visible proof banner now, client-side,
                        # never as part of what was actually submitted —
                        # see _proof_banner_js's docstring.
                        await page.evaluate(_proof_banner_js(marker))
                        found = (url, await page.screenshot(full_page=True))
                        break
                await browser.close()
                return found
        except PlaywrightError:
            return None

    async def _check_form(self, form: FormInfo, target_field: str, candidates: list[str]) -> Finding | None:
        marker = _marker()
        found = None
        winning_payload: str | None = None
        winning_display_payload: str | None = None
        for payload, display_payload in _stored_xss_payloads(marker):
            submit_response = await self._submit(form, target_field, payload)
            if submit_response is None:
                continue
            found = await self._find_execution(marker, candidates)
            if found is not None:
                winning_payload = payload
                winning_display_payload = display_payload
                break
        if found is None or winning_payload is None:
            return None
        found_url, _screenshot = found

        # §2 step 1: deterministic re-execution — a fresh marker, fresh
        # submission, fresh page load, not just re-checking the same one.
        # Reuses the exact payload shape that just worked rather than
        # restarting the fallback loop, matching app.agents.xss's
        # probe_fn-reuse discipline for the same reason: an already-
        # confirmed technique re-executed with a different one is a new,
        # unproven claim, not a genuine re-confirmation of this finding.
        marker2 = _marker()
        payload2 = winning_payload.replace(marker, marker2)
        submit_response2 = await self._submit(form, target_field, payload2)
        if submit_response2 is None:
            return None
        found_again = await self._find_execution(marker2, [found_url])
        if found_again is None:
            return None
        _found_url_again, screenshot_png = found_again

        screenshot_refs: list[str] = []
        if screenshot_png:
            storage = get_object_storage()
            key = f"stored-xss-proof/{self._scan_run_id}/{uuid.uuid4().hex}.png"
            await storage.put(key, screenshot_png, content_type="image/png")
            screenshot_refs = [key]

        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="xss-stored",
            title="Stored Cross-Site Scripting (XSS)",
            severity="Critical",
            owasp_2025_category=XSS_FINDING_METADATA["owasp_2025_category"],
            cwe_id=XSS_FINDING_METADATA["cwe_id"],
            portswigger_reference_url="https://portswigger.net/web-security/cross-site-scripting/stored",
            cvss_vector="AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
            cvss_score=9.6,
            affected_endpoints=[form.action_url, found_url],
            plain_language_summary=(
                "A script submitted through this form gets permanently stored and then runs "
                "automatically for anyone who later visits a different page that displays it — "
                "unlike a one-off malicious link, this attack persists and can affect every "
                "visitor, including administrators, without them clicking anything."
            ),
            technical_description=(
                f"Submitting {form.action_url} with the payload {winning_display_payload!r} in the "
                f"'{target_field}' field, then loading {found_url} in a real browser, caused the "
                "injected script to execute — confirming the payload was stored server-side and "
                "rendered unescaped on revisit."
            ),
            steps_to_reproduce=[
                f"1. Submit {form.action_url} with the '{target_field}' field set to "
                f"{winning_display_payload} instead of its normal content.",
                f"2. Visit {found_url} (where the stored data is displayed back).",
                "3. Observe the injected script executes — verified here by an automated "
                "headless-browser check across two independent submissions, with a screenshot "
                "captured as evidence.",
            ],
            remediation=XSS_FINDING_METADATA["remediation"],
            references=[
                "https://portswigger.net/web-security/cross-site-scripting/stored",
                "https://cwe.mitre.org/data/definitions/79.html",
            ],
            confirmation_status="ai_confirmed",
        )
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()
            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=format_request_raw(submit_response2),
                    response_raw=format_response_raw(submit_response2),
                    payload=payload2,
                    screenshot_refs=screenshot_refs,
                )
            )
            await self._session.commit()
        return finding
