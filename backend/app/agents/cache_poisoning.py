"""Web cache poisoning / cache deception (§3) — two deterministic,
differential checks against a shared/CDN cache sitting in front of the
application:

  - Unkeyed-input poisoning: does the origin reflect an unkeyed header
    (X-Forwarded-Host et al.) into its response, and does a cache in
    front of it store that response without varying on the header —
    such that a later, entirely plain request gets served the poisoned
    copy? Both halves of that are independently observable, so this
    becomes a confirmed Finding, not a heuristic.
  - Cache deception: does the application serve the same substantive
    content for a URL with a fake static extension appended as the
    real URL, while marking it publicly cacheable? Also directly
    observable — no timing/heuristic involved.

Both are one check per distinct host — this is site-wide cache/routing
configuration behavior, not usually a per-page one, matching
app.agents.host_header/cors/clickjacking's same per-host dedup for the
same reason.
"""

import uuid
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.evidence_screenshot import capture_and_store_evidence_screenshot
from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.finding import Evidence, Finding

_CATALOG_FILE = "cache_poisoning_catalog.yaml"
_UNKEYED_HEADER = "X-Forwarded-Host"


def _make_marker() -> str:
    return f"verdikt-cache-{uuid.uuid4().hex[:12]}.invalid"


def _cache_busted(url: str) -> str:
    """Real caches key on URL (including query string) but — per the
    vulnerability class this check targets — typically NOT on headers.
    Appending a unique, per-attempt query param is the standard way to
    force each probe attempt at a fresh cache entry instead of re-
    reading (or being blocked by) whatever an earlier attempt already
    poisoned — the same technique PortSwigger's own methodology uses.
    """
    parts = urlsplit(url)
    query = parse_qs(parts.query, keep_blank_values=True)
    query["verdikt_cb"] = [uuid.uuid4().hex[:8]]
    new_query = urlencode(query, doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def _is_cacheable(response: httpx.Response) -> bool:
    cache_control = response.headers.get("cache-control", "").lower()
    if "private" in cache_control or "no-store" in cache_control:
        return False
    return True


class CachePoisoningAgent:
    """No LLM needed — both checks are differential response
    inspections (§1.2 safe-by-default: read-only GETs, no
    state-changing payloads)."""

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

    async def run(self, endpoints: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        poisoning_seen_hosts: set[str] = set()
        deception_seen_hosts: set[str] = set()
        for url in endpoints:
            host = httpx.URL(url).host
            if host not in poisoning_seen_hosts:
                poisoning_seen_hosts.add(host)
                poisoning = await self._check_poisoning(url)
                if poisoning is not None:
                    findings.append(poisoning)

            # Deception gets its own dedup pass (not shared with
            # poisoning's) that specifically prefers the first *non-root*
            # URL discovered per host: _check_deception always skips "/"
            # (never a meaningful deception target — see its docstring),
            # so reusing poisoning's dedup here would mean a host whose
            # first-crawled URL happens to be its homepage (almost every
            # host, since "/" is always the crawl seed) never gets
            # deception-tested against anything at all.
            if host not in deception_seen_hosts and urlsplit(url).path not in ("", "/"):
                deception_seen_hosts.add(host)
                deception = await self._check_deception(url)
                if deception is not None:
                    findings.append(deception)
        return findings

    async def _check_poisoning(self, url: str) -> Finding | None:
        if not await self._poisoning_round_trip(url):
            return None
        # Re-verify with a fresh marker before confirming — rules out a
        # coincidental static value already present in the response.
        probe_again = await self._poisoning_round_trip(url)
        if not probe_again:
            return None

        marker, poisoned_probe, plain_followup = probe_again
        check_def = get_check("web-cache-poisoning-unkeyed-input", filename=_CATALOG_FILE)
        extra = {"header_name": _UNKEYED_HEADER, "marker": marker}
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="web-cache-poisoning-unkeyed-input",
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
                f'1. Send a GET request to {url} with the header "{_UNKEYED_HEADER}: {marker}" '
                "and observe the marker reflected in the response.",
                "2. Send a second, entirely plain GET request to the same URL (no special "
                "headers) and observe the marker still present — the poisoned response was "
                "cached and served to a request that never sent it.",
            ],
            remediation=check_def.remediation,
            references=[*check_def.references, check_def.portswigger_reference_url],
            confirmation_status="ai_confirmed",
        )
        request_raw = format_request_raw(plain_followup)
        response_raw = format_response_raw(plain_followup)
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

    async def _poisoning_round_trip(
        self, url: str
    ) -> tuple[str, httpx.Response, httpx.Response] | None:
        marker = _make_marker()
        busted_url = _cache_busted(url)
        try:
            poisoned = await self._client.get(busted_url, extra_headers={_UNKEYED_HEADER: marker})
        except (ScopeViolationError, httpx.HTTPError):
            return None
        if marker not in (poisoned.text or ""):
            return None
        try:
            plain = await self._client.get(busted_url)
        except (ScopeViolationError, httpx.HTTPError):
            return None
        if marker not in (plain.text or ""):
            return None
        return marker, poisoned, plain

    async def _check_deception(self, url: str) -> Finding | None:
        # A real, found-via-live-testing false positive (§14 validation
        # against OWASP Juice Shop): every SPA's own root path serves the
        # same public index.html for literally any unmatched route (so
        # the client-side router can take over) — that's completely
        # standard, intentional SPA-fallback behavior, not cache
        # deception. The actual PortSwigger technique targets pages that
        # differ *per session* (e.g. "/my-account"), where the deception
        # is tricking a shared cache into storing and replaying one
        # victim's personalized response to someone else. The site's own
        # homepage is — by definition — never meaningfully session-
        # specific, so there's nothing to deceive a cache into leaking.
        if urlsplit(url).path in ("", "/"):
            return None

        try:
            original = await self._client.get(url)
        except (ScopeViolationError, httpx.HTTPError):
            return None
        if original.status_code >= 400 or not original.text:
            return None

        deceptive_url = url.rstrip("/") + "/nonexistent.css"
        result = await self._deception_probe(deceptive_url, original.text)
        if result is None:
            return None
        # Re-verify — deterministic, so a second identical request is
        # enough (§2 step 1).
        result_again = await self._deception_probe(deceptive_url, original.text)
        if result_again is None:
            return None

        check_def = get_check("web-cache-deception", filename=_CATALOG_FILE)
        extra = {"deceptive_url": deceptive_url}
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="web-cache-deception",
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
                f"1. Send a GET request to {deceptive_url} (the real URL {url} with a fake "
                "static extension appended).",
                "2. Observe it returns the same substantive content as the real URL, marked "
                "as publicly cacheable — a shared cache would store and later serve this "
                "content to other visitors who simply guess or are tricked into requesting "
                "that same deceptive URL.",
            ],
            remediation=check_def.remediation,
            references=[*check_def.references, check_def.portswigger_reference_url],
            confirmation_status="ai_confirmed",
        )
        request_raw = format_request_raw(result_again)
        response_raw = format_response_raw(result_again)
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

    async def _deception_probe(self, deceptive_url: str, original_body: str) -> httpx.Response | None:
        try:
            response = await self._client.get(deceptive_url)
        except (ScopeViolationError, httpx.HTTPError):
            return None
        if response.status_code >= 400:
            return None
        if not _is_cacheable(response):
            return None
        if (response.text or "") != original_body:
            return None
        return response
