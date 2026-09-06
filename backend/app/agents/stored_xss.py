"""Stored XSS (§3) — submit a marker payload to a form, then revisit
OTHER discovered pages in a real browser and check whether it executes
there. Real script execution on a page different from where the payload
was submitted is the defining, unambiguous signature of stored
(persistent) XSS — as opposed to reflected XSS (payload echoed back in
the SAME request/response, app.agents.xss) or DOM XSS (purely
client-side, no server round trip at all, app.agents.dom_xss).
"""

import uuid
from urllib.parse import urlencode

import httpx
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.agents.recon import FormInfo
from app.agents.xss import XSS_FINDING_METADATA
from app.agents.xss_browser_proof import visible_proof_banner_js
from app.models.finding import Evidence, Finding
from app.storage.local_disk import get_object_storage

# Bounded like ReconAgent's own crawl (§1.2 safe-by-default / §10 cost
# control) — checking every candidate page per submitted form is
# multiplicative (forms x pages); this caps it to a reasonable set of
# most-likely-to-display-stored-data pages rather than exhaustively
# re-visiting everything recon found.
_MAX_REVISIT_PAGES = 10
_PAGE_TIMEOUT_MS = 8000


def _marker() -> str:
    return f"verdikt_stored_{uuid.uuid4().hex[:12]}"


def _payload_for(marker: str) -> str:
    # See app.agents.xss_browser_proof.visible_proof_banner_js's
    # docstring — the same real bug applied here: the window[marker]
    # flag alone is reliable for the page.evaluate() check below, but
    # invisible, so a screenshot taken right after detecting it looked
    # identical to an unexploited page revisit.
    return f'<script>window["{marker}"]=true;{visible_proof_banner_js(marker)}</script>'


def _build_payload_fields(form: FormInfo, payload: str) -> dict[str, str]:
    return {
        field.name: payload
        for field in form.fields
        if field.type not in ("hidden", "submit", "button") and field.name
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

    async def run(self, forms: list[FormInfo], endpoints: list[str]) -> list[Finding]:
        candidates = endpoints[:_MAX_REVISIT_PAGES]
        findings: list[Finding] = []
        for form in forms:
            if form.method != "POST":
                continue
            finding = await self._check_form(form, candidates)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _submit(self, form: FormInfo, payload: str) -> httpx.Response | None:
        try:
            return await self._client.post(
                form.action_url,
                body=urlencode(_build_payload_fields(form, payload)),
                content_type="application/x-www-form-urlencoded",
            )
        except (ScopeViolationError, httpx.HTTPError):
            return None

    async def _find_execution(
        self, marker: str, candidates: list[str]
    ) -> tuple[str, bytes] | None:
        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(headless=True)
                page = await browser.new_page()
                found: tuple[str, bytes] | None = None
                for url in candidates:
                    try:
                        await page.goto(url, wait_until="networkidle", timeout=_PAGE_TIMEOUT_MS)
                    except PlaywrightError:
                        continue
                    executed = bool(await page.evaluate(f'window["{marker}"] === true'))
                    if executed:
                        found = (url, await page.screenshot(full_page=True))
                        break
                await browser.close()
                return found
        except PlaywrightError:
            return None

    async def _check_form(self, form: FormInfo, candidates: list[str]) -> Finding | None:
        marker = _marker()
        submit_response = await self._submit(form, _payload_for(marker))
        if submit_response is None:
            return None

        found = await self._find_execution(marker, candidates)
        if found is None:
            return None
        found_url, _screenshot = found

        # §2 step 1: deterministic re-execution — a fresh marker, fresh
        # submission, fresh page load, not just re-checking the same one.
        marker2 = _marker()
        submit_response2 = await self._submit(form, _payload_for(marker2))
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
                f"Submitting {form.action_url} with a <script> payload in place of its normal "
                f"field value(s), then loading {found_url} in a real browser, caused the "
                "injected script to execute — confirming the payload was stored server-side and "
                "rendered unescaped on a page different from where it was submitted."
            ),
            steps_to_reproduce=[
                f'1. Submit {form.action_url} with a field value of '
                '<script>alert(document.domain)</script> instead of its normal content.',
                f"2. Visit {found_url} (a different page that displays the stored data).",
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
                    screenshot_refs=screenshot_refs,
                )
            )
            await self._session.commit()
        return finding
