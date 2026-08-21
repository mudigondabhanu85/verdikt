"""§8 per-finding retest — re-verifies ONE Finding's specific check
against the live target, without re-running a full scan. Deliberately
reuses each check's own original detection logic (imported directly
from its agent module, including the "private" helper functions —
Python doesn't enforce that, and it guarantees retest can never quietly
drift from what actually earned the Finding its confirmation in the
first place) rather than re-implementing detection a second time.

Coverage is real but intentionally partial: every handler here is a
single deterministic HTTP or real-browser probe against a stable URL
recoverable from Finding.affected_endpoints alone. Checks that need a
fresh authenticated session (CSRF, JWT/session checks, access-control,
business-logic) or AI-assisted adversarial payload validation (the
injection family: SQLi/NoSQLi/SSTI/command-injection/path-traversal)
aren't in this registry — see is_retest_supported(); a full rescan
remains how those get re-verified. This is an honest scope boundary,
not a silently missing feature — the API surfaces "not_supported" as a
real, typed outcome for those check_ids.
"""

import asyncio
from dataclasses import dataclass
from typing import Awaitable, Callable
from urllib.parse import urlsplit

import httpx

from app.agents.checks import CHECKS, FetchedPage
from app.agents.clickjacking_proof import attempt_clickjacking_proof
from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.agents.cors import _classify as _cors_classify
from app.agents.cache_poisoning import _cache_busted, _is_cacheable, _make_marker, _UNKEYED_HEADER
from app.agents.graphql import _INTROSPECTION_QUERY, _schema_summary
from app.agents.host_header import _forged_host_reflected, _FORGED_HOST
from app.agents.oauth import _accepts_attacker_redirect, _ATTACKER_REDIRECT, _swap_redirect_uri
from app.agents.prototype_pollution import attempt_prototype_pollution_proof
from app.agents.raw_http import send_raw
from app.agents.websocket_security import _build_handshake, _handshake_accepted
from app.agents.xss_browser_proof import attempt_dom_xss_fragment_proof
from app.agents.xxe import _FILE_DISCLOSURE_MARKER_RE, _XXE_PAYLOAD
from app.models.finding import Finding


@dataclass
class RetestOutcome:
    still_vulnerable: bool
    request_raw: str
    response_raw: str


RetestHandler = Callable[[Finding, ScopedHttpClient], Awaitable[RetestOutcome | None]]
# A handler returns None when the retest genuinely couldn't be attempted
# (scope violation, network failure) — the caller surfaces that as
# result="error", distinct from a clean still_vulnerable/fixed outcome.

RETEST_HANDLERS: dict[str, RetestHandler] = {}


def register(*check_ids: str):
    def decorator(fn: RetestHandler) -> RetestHandler:
        for check_id in check_ids:
            RETEST_HANDLERS[check_id] = fn
        return fn

    return decorator


def is_retest_supported(check_id: str) -> bool:
    return check_id in RETEST_HANDLERS


async def _retest_catalog_check(finding: Finding, client: ScopedHttpClient) -> RetestOutcome | None:
    url = finding.affected_endpoints[0]
    try:
        response = await client.get(url)
    except (ScopeViolationError, httpx.HTTPError):
        return None
    parsed = urlsplit(url)
    tls_version = None
    if parsed.scheme == "https":
        tls_version = await client.probe_tls_version(parsed.hostname or "", parsed.port or 443)
    page = FetchedPage(
        url=url,
        status_code=response.status_code,
        headers=response.headers,
        text=response.text,
        scheme=parsed.scheme,
        tls_version=tls_version,
    )
    hits = CHECKS[finding.check_id](page)
    return RetestOutcome(
        still_vulnerable=len(hits) > 0,
        request_raw=format_request_raw(response),
        response_raw=format_response_raw(response),
    )


for _check_id in CHECKS:
    RETEST_HANDLERS[_check_id] = _retest_catalog_check


@register("host-header-injection")
async def _retest_host_header(finding: Finding, client: ScopedHttpClient) -> RetestOutcome | None:
    url = finding.affected_endpoints[0]
    try:
        response = await client.get(url, extra_headers={"Host": _FORGED_HOST})
    except (ScopeViolationError, httpx.HTTPError):
        return None
    return RetestOutcome(
        still_vulnerable=_forged_host_reflected(response),
        request_raw=format_request_raw(response),
        response_raw=format_response_raw(response),
    )


@register("cors-reflected-origin-with-credentials", "cors-wildcard-origin")
async def _retest_cors(finding: Finding, client: ScopedHttpClient) -> RetestOutcome | None:
    url = finding.affected_endpoints[0]
    try:
        response = await client.get(url, extra_headers={"Origin": "https://verdikt-cors-test.invalid"})
    except (ScopeViolationError, httpx.HTTPError):
        return None
    return RetestOutcome(
        still_vulnerable=_cors_classify(response) == finding.check_id,
        request_raw=format_request_raw(response),
        response_raw=format_response_raw(response),
    )


@register("xxe-file-disclosure")
async def _retest_xxe(finding: Finding, client: ScopedHttpClient) -> RetestOutcome | None:
    url = finding.affected_endpoints[0]
    try:
        response = await client.post(url, body=_XXE_PAYLOAD, content_type="application/xml")
    except (ScopeViolationError, httpx.HTTPError):
        return None
    still_vulnerable = bool(_FILE_DISCLOSURE_MARKER_RE.search(response.text or ""))
    return RetestOutcome(
        still_vulnerable=still_vulnerable,
        request_raw=format_request_raw(response),
        response_raw=format_response_raw(response),
    )


@register("graphql-introspection-enabled")
async def _retest_graphql(finding: Finding, client: ScopedHttpClient) -> RetestOutcome | None:
    url = finding.affected_endpoints[0]
    try:
        response = await client.post(url, body=_INTROSPECTION_QUERY, content_type="application/json")
    except (ScopeViolationError, httpx.HTTPError):
        return None
    try:
        summary = _schema_summary(response.json())
    except (ValueError, TypeError):
        summary = None
    return RetestOutcome(
        still_vulnerable=summary is not None,
        request_raw=format_request_raw(response),
        response_raw=format_response_raw(response),
    )


@register("oauth-redirect-uri-validation-bypass")
async def _retest_oauth(finding: Finding, client: ScopedHttpClient) -> RetestOutcome | None:
    probe_url = _swap_redirect_uri(finding.affected_endpoints[0], _ATTACKER_REDIRECT)
    try:
        response = await client.get(probe_url)
    except (ScopeViolationError, httpx.HTTPError):
        return None
    return RetestOutcome(
        still_vulnerable=_accepts_attacker_redirect(response),
        request_raw=format_request_raw(response),
        response_raw=format_response_raw(response),
    )


@register("web-cache-poisoning-unkeyed-input")
async def _retest_cache_poisoning(finding: Finding, client: ScopedHttpClient) -> RetestOutcome | None:
    # Cache-busted per attempt, same as the original check — re-reading
    # a stale entry from an earlier scan/retest attempt would give a
    # false answer either direction.
    busted_url = _cache_busted(finding.affected_endpoints[0])
    marker = _make_marker()
    try:
        poisoned = await client.get(busted_url, extra_headers={_UNKEYED_HEADER: marker})
        if marker not in (poisoned.text or ""):
            return RetestOutcome(
                still_vulnerable=False,
                request_raw=format_request_raw(poisoned),
                response_raw=format_response_raw(poisoned),
            )
        plain = await client.get(busted_url)
    except (ScopeViolationError, httpx.HTTPError):
        return None
    return RetestOutcome(
        still_vulnerable=marker in (plain.text or ""),
        request_raw=format_request_raw(plain),
        response_raw=format_response_raw(plain),
    )


@register("web-cache-deception")
async def _retest_cache_deception(finding: Finding, client: ScopedHttpClient) -> RetestOutcome | None:
    url = finding.affected_endpoints[0]
    try:
        original = await client.get(url)
        if original.status_code >= 400 or not original.text:
            return RetestOutcome(
                still_vulnerable=False,
                request_raw=format_request_raw(original),
                response_raw=format_response_raw(original),
            )
        deceptive_url = url.rstrip("/") + "/nonexistent.css"
        response = await client.get(deceptive_url)
    except (ScopeViolationError, httpx.HTTPError):
        return None
    still_vulnerable = (
        response.status_code < 400 and _is_cacheable(response) and (response.text or "") == original.text
    )
    return RetestOutcome(
        still_vulnerable=still_vulnerable,
        request_raw=format_request_raw(response),
        response_raw=format_response_raw(response),
    )


@register("websocket-missing-origin-validation")
async def _retest_websocket(finding: Finding, client: ScopedHttpClient) -> RetestOutcome | None:
    url = finding.affected_endpoints[0]
    normalized = url.replace("wss://", "https://", 1).replace("ws://", "http://", 1)
    parsed = httpx.URL(normalized)
    host = parsed.host
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"
    path = parsed.raw_path.decode() if parsed.raw_path else "/"
    raw_request = _build_handshake(host, path, cookie_header=None)
    try:
        response, _elapsed = await asyncio.to_thread(
            send_raw, host, port, raw_request, use_tls=use_tls, timeout=5.0
        )
    except OSError:
        return None
    return RetestOutcome(
        still_vulnerable=_handshake_accepted(response),
        request_raw=raw_request.decode(errors="replace"),
        response_raw=response.decode(errors="replace"),
    )


@register("clickjacking-confirmed")
async def _retest_clickjacking(finding: Finding, client: ScopedHttpClient) -> RetestOutcome | None:
    url = finding.affected_endpoints[0]
    result = await attempt_clickjacking_proof(url)
    return RetestOutcome(
        still_vulnerable=result.framable,
        request_raw=f"GET {url}\n(loaded inside a real cross-origin iframe)",
        response_raw=f"framable={result.framable}",
    )


@register("dom-xss-fragment")
async def _retest_dom_xss(finding: Finding, client: ScopedHttpClient) -> RetestOutcome | None:
    url = finding.affected_endpoints[0]
    result = await attempt_dom_xss_fragment_proof(url)
    return RetestOutcome(
        still_vulnerable=result.executed,
        request_raw=f"GET {url}#<payload> (real browser navigation)",
        response_raw=f"executed={result.executed}",
    )


@register("client-side-prototype-pollution")
async def _retest_prototype_pollution(finding: Finding, client: ScopedHttpClient) -> RetestOutcome | None:
    url = finding.affected_endpoints[0]
    executed, _screenshot = await attempt_prototype_pollution_proof(url)
    return RetestOutcome(
        still_vulnerable=executed,
        request_raw=f"GET {url}?__proto__[...]=polluted (real browser navigation)",
        response_raw=f"executed={executed}",
    )
