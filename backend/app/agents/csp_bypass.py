"""Content-Security-Policy bypass via a same-origin JSONP-style "callback"
endpoint (§3, A02 Security Misconfiguration). Fully deterministic + real
browser-proof, no LLM triage needed — the same discipline as clickjacking:
a CSP that allows 'self' in script-src is a promise that only the site's
own scripts can run, and a same-origin endpoint that reflects a "callback"
query parameter unescaped as a function-call prefix breaks that promise
outright, since the browser has no way to tell that "script" apart from a
legitimate one.

Detection has two real gaps a naive same-page-only crawl would miss, both
handled here:

1. The vulnerable endpoint is very often never linked from the page's own
   HTML at all — it's referenced only inside an external same-origin
   <script src="...js"> file the page loads (DVWA's own CSP-bypass
   teaching page, §14, works exactly this way: the JSONP URL is a string
   literal inside a separate .js file, never present in the page's raw
   HTML). This fetches same-origin external scripts the page references
   (bounded — see _MAX_EXTERNAL_SCRIPTS_PER_PAGE) and scans their text
   too, not just the page's own body.
2. A CSP header existing at all doesn't mean this bypass applies — only a
   policy whose script-src (or default-src, its fallback per the CSP
   spec) actually includes 'self' is a candidate; a policy that already
   blocks same-origin scripts, or has no CSP at all, is out of scope for
   this specific technique (a missing-CSP finding is already its own,
   separate check).
"""

import re
import uuid
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from app.agents.csp_bypass_proof import attempt_csp_bypass_proof
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient, ScopeViolationError
from app.agents.login import pick_best_session
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.finding import Evidence, Finding
from app.storage.local_disk import get_object_storage

_CATALOG_FILE = "csp_bypass_catalog.yaml"
_CHECK_ID = "csp-bypass-jsonp-callback"

# A same-origin, callback-parameter URL — matches both a literal <script
# src="..."> reference and one embedded as a string inside external JS
# (e.g. `s.src = "source/jsonp.php?callback=solveSum";`). Requires the
# literal parameter name "callback" specifically (the most common
# real-world convention for this pattern, and DVWA's own) rather than
# guessing at every possible name a "give me some JS to run" endpoint
# might use — a narrower, high-confidence net rather than a noisy one.
_CALLBACK_URL_RE = re.compile(r"""(['"])([\w./\-]+\?[\w=&%.\-]*callback=[\w]*[\w=&%.\-]*)\1""")

_MAX_EXTERNAL_SCRIPTS_PER_PAGE = 5


def _script_src_allows_self(csp_header: str) -> bool:
    directives = {}
    for part in csp_header.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        directives[tokens[0].lower()] = tokens[1:]
    # script-src, falling back to default-src per the CSP spec (script-src
    # inherits default-src's value when script-src itself isn't set).
    values = directives.get("script-src", directives.get("default-src", []))
    return "'self'" in values


def _same_origin(url: str, origin_netloc: str) -> bool:
    return urlsplit(url).netloc in ("", origin_netloc)


def _extract_script_srcs(base_url: str, html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    origin_netloc = urlsplit(base_url).netloc
    srcs = []
    for tag in soup.find_all("script", src=True):
        absolute = urljoin(base_url, tag["src"])
        if _same_origin(absolute, origin_netloc):
            srcs.append(absolute)
    return srcs


def _find_callback_urls(base_url: str, text: str) -> list[str]:
    origin_netloc = urlsplit(base_url).netloc
    found = []
    for _quote, candidate in _CALLBACK_URL_RE.findall(text):
        absolute = urljoin(base_url, candidate)
        if _same_origin(absolute, origin_netloc):
            found.append(absolute)
    return found


def _replace_callback_param(url: str, new_value: str) -> str:
    scheme, netloc, path, query, fragment = urlsplit(url)
    params = []
    replaced = False
    for pair in query.split("&"):
        if pair.startswith("callback="):
            params.append(f"callback={new_value}")
            replaced = True
        else:
            params.append(pair)
    if not replaced:
        params.append(f"callback={new_value}")
    from urllib.parse import urlunsplit

    return urlunsplit((scheme, netloc, path, "&".join(params), fragment))


def _callback_url_template(url: str) -> str:
    """Same as _replace_callback_param, but leaves a literal "{callback}"
    placeholder instead of a concrete value — what attempt_csp_bypass_proof
    needs to build the real exploit URL itself.
    """
    return _replace_callback_param(url, "{callback}")


class CspBypassAgent:
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
        discovered_responses: dict[str, httpx.Response],
        sessions: dict[uuid.UUID, AuthenticatedSession] | None = None,
    ) -> list[Finding]:
        self._auth_session = pick_best_session(sessions)
        findings: list[Finding] = []
        for url, response in discovered_responses.items():
            csp = response.headers.get("content-security-policy")
            if not csp or not _script_src_allows_self(csp):
                continue
            finding = await self._check_page(url, response)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _candidate_jsonp_urls(self, url: str, response: httpx.Response) -> list[str]:
        candidates = list(dict.fromkeys(_find_callback_urls(url, response.text)))
        if candidates:
            return candidates

        for script_url in _extract_script_srcs(url, response.text)[:_MAX_EXTERNAL_SCRIPTS_PER_PAGE]:
            try:
                script_resp = await self._client.get(script_url, session=self._auth_session)
            except (ScopeViolationError, httpx.HTTPError):
                continue
            candidates = list(dict.fromkeys(_find_callback_urls(url, script_resp.text)))
            if candidates:
                return candidates
        return []

    async def _check_page(self, url: str, response: httpx.Response) -> Finding | None:
        for jsonp_url in await self._candidate_jsonp_urls(url, response):
            finding = await self._check_candidate(url, jsonp_url)
            if finding is not None:
                return finding
        return None

    async def _check_candidate(self, page_url: str, jsonp_url: str) -> Finding | None:
        marker = f"verdikt{uuid.uuid4().hex[:8]}"
        probe_url = _replace_callback_param(jsonp_url, marker)
        try:
            probe_resp = await self._client.get(probe_url, session=self._auth_session)
        except (ScopeViolationError, httpx.HTTPError):
            return None
        if not probe_resp.text.startswith(f"{marker}("):
            return None

        template = _callback_url_template(jsonp_url)
        proof = await attempt_csp_bypass_proof(page_url, template, session=self._auth_session)
        if not proof.executed:
            return None

        # §2 step 1: deterministic re-execution before confirming — a
        # fresh marker, fresh request, not just re-checking the same one.
        marker2 = f"verdikt{uuid.uuid4().hex[:8]}"
        probe_url2 = _replace_callback_param(jsonp_url, marker2)
        try:
            probe_resp2 = await self._client.get(probe_url2, session=self._auth_session)
        except (ScopeViolationError, httpx.HTTPError):
            return None
        if not probe_resp2.text.startswith(f"{marker2}("):
            return None
        proof2 = await attempt_csp_bypass_proof(page_url, template, session=self._auth_session)
        if not proof2.executed:
            return None

        return await self._persist(page_url, jsonp_url, template, probe_resp2, proof2)

    async def _persist(
        self, page_url: str, jsonp_url: str, template: str, probe_resp: httpx.Response, proof
    ) -> Finding:
        check_def = get_check(_CHECK_ID, filename=_CATALOG_FILE)
        payload_url = template.format(callback="window%5B%22MARKER%22%5D%3Dtrue%3B%2F%2F")
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id=_CHECK_ID,
            title=check_def.title,
            severity=check_def.severity,
            owasp_2025_category=check_def.owasp_2025_category,
            cwe_id=check_def.cwe_id,
            portswigger_reference_url=check_def.portswigger_reference_url,
            cvss_vector=check_def.cvss_vector,
            cvss_score=check_def.cvss_score,
            affected_endpoints=[page_url, jsonp_url],
            plain_language_summary=check_def.plain_language_summary,
            technical_description=render_check_template(
                check_def.technical_description,
                page_url,
                {"jsonp_url": jsonp_url, "jsonp_url_with_payload": payload_url},
            ),
            steps_to_reproduce=[
                f"1. Confirm {page_url} sends a Content-Security-Policy permitting scripts from 'self'.",
                f"2. Confirm {jsonp_url} reflects its 'callback' parameter unescaped: request it with "
                "'callback=x' and observe the response begins with 'x('.",
                f"3. While viewing {page_url} in a browser, inject "
                f"<script src=\"{payload_url}\"> — verified here by an automated headless-browser "
                "check across two independent submissions, with a screenshot captured as evidence.",
            ],
            remediation=check_def.remediation,
            references=check_def.references,
            confirmation_status="ai_confirmed",
        )
        screenshot_refs: list[str] = []
        if proof.screenshot_png is not None:
            storage = get_object_storage()
            key = f"csp-bypass-proof/{self._scan_run_id}/{uuid.uuid4().hex}.png"
            await storage.put(key, proof.screenshot_png, content_type="image/png")
            screenshot_refs = [key]

        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()
            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=f"GET {probe_resp.request.url}",
                    response_raw=probe_resp.text[:2000],
                    payload=jsonp_url,
                    screenshot_refs=screenshot_refs,
                )
            )
            await self._session.commit()
        return finding
