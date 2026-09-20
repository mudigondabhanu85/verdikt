"""API version enumeration → excessive data exposure (§3, item 1). Many
APIs version a resource in its URL path (/v1/, /v2/, ...) and retire an
old version by simply pointing clients at a newer one, without ever
disabling the old version itself — leaving it reachable and, often,
never updated to strip fields a later version's authors tightened up.
This probes nearby version numbers of each discovered versioned endpoint
and confirms a finding only when a real, live JSON response from another
version actually contains a sensitive-looking field the currently-
referenced version's response does not — never from the version number
alone.
"""

import re
import uuid
from urllib.parse import urlsplit

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.evidence_screenshot import capture_and_store_evidence_screenshot
from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.finding import Evidence, Finding

_CATALOG_FILE = "api_version_catalog.yaml"
_VERSION_SEGMENT_RE = re.compile(r"^(.*/v)(\d+)(/.*)$")
_MAX_OLDER_VERSIONS_TRIED = 5
_SENSITIVE_KEY_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "ssn",
    "social_security",
    "credit_card",
    "creditcard",
    "cvv",
    "api_key",
    "apikey",
    "private_key",
    "privatekey",
    "auth",
    "hash",
    "pin",
)


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in _SENSITIVE_KEY_MARKERS)


def _flatten_keys(value, depth: int = 0) -> set[str]:
    """All object key names anywhere in a parsed JSON value, walked
    recursively (bounded depth — real API responses are never deeply
    nested enough for this to matter, and a bound keeps a pathological
    response from ever being a performance concern)."""
    if depth > 6:
        return set()
    keys: set[str] = set()
    if isinstance(value, dict):
        for k, v in value.items():
            keys.add(str(k))
            keys |= _flatten_keys(v, depth + 1)
    elif isinstance(value, list):
        for item in value:
            keys |= _flatten_keys(item, depth + 1)
    return keys


def _candidate_versioned_urls(url: str) -> tuple[str, str, list[tuple[str, str]]] | None:
    """Returns (base_url, current_version, [(version, url), ...]) for
    every older version worth trying, or None if this URL has no
    /v<N>/ path segment at all."""
    parts = urlsplit(url)
    match = _VERSION_SEGMENT_RE.match(parts.path)
    if match is None:
        return None
    prefix, current_version, suffix = match.groups()
    current = int(current_version)
    if current <= 1:
        return None
    oldest = max(1, current - _MAX_OLDER_VERSIONS_TRIED)
    candidates = []
    for v in range(current - 1, oldest - 1, -1):
        path = f"{prefix}{v}{suffix}"
        candidate_url = parts._replace(path=path).geturl()
        candidates.append((str(v), candidate_url))
    return url, current_version, candidates


def _parse_json_or_none(response: httpx.Response):
    if response.status_code >= 400:
        return None
    content_type = response.headers.get("content-type", "")
    looks_like_json = "json" in content_type or response.text.lstrip()[:1] in ("{", "[")
    if not looks_like_json:
        return None
    try:
        return response.json()
    except ValueError:
        return None


class ApiVersionAgent:
    """No LLM needed — confirmation is a real, deterministic diff
    between two live JSON responses (§1.2 safe-by-default: read-only GET
    requests against nearby version numbers only, never a destructive
    verb, never guessing beyond a small bounded range)."""

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
        seen_base_paths: set[tuple[str, str, str]] = set()
        for url in endpoints:
            resolved = _candidate_versioned_urls(url)
            if resolved is None:
                continue
            reference_url, current_version, candidates = resolved
            parts = urlsplit(url)
            # De-dupe by the version-stripped path so the same resource
            # discovered via multiple version links is only probed once.
            stripped = _VERSION_SEGMENT_RE.sub(r"\1N\3", parts.path)
            key = (parts.scheme, parts.netloc, stripped)
            if key in seen_base_paths:
                continue
            seen_base_paths.add(key)

            finding = await self._check_endpoint(reference_url, current_version, candidates)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _fetch(self, url: str) -> httpx.Response | None:
        try:
            return await self._client.get(url)
        except (ScopeViolationError, httpx.HTTPError):
            return None

    async def _check_endpoint(
        self, reference_url: str, current_version: str, candidates: list[tuple[str, str]]
    ) -> Finding | None:
        reference_response = await self._fetch(reference_url)
        if reference_response is None:
            return None
        reference_json = _parse_json_or_none(reference_response)
        if reference_json is None:
            return None
        reference_keys = _flatten_keys(reference_json)

        for candidate_version, candidate_url in candidates:
            candidate_response = await self._fetch(candidate_url)
            if candidate_response is None:
                continue
            candidate_json = _parse_json_or_none(candidate_response)
            if candidate_json is None:
                continue
            candidate_keys = _flatten_keys(candidate_json)
            leaked_fields = sorted(
                k for k in (candidate_keys - reference_keys) if _is_sensitive_key(k)
            )
            if not leaked_fields:
                continue

            # §2 step 1: deterministic re-execution before confirming.
            again = await self._fetch(candidate_url)
            if again is None:
                continue
            again_json = _parse_json_or_none(again)
            if again_json is None:
                continue
            again_keys = _flatten_keys(again_json)
            leaked_fields_again = sorted(
                k for k in (again_keys - reference_keys) if _is_sensitive_key(k)
            )
            if not leaked_fields_again:
                continue

            return await self._persist(
                reference_url=reference_url,
                current_version=current_version,
                candidate_version=candidate_version,
                candidate_url=candidate_url,
                leaked_fields=leaked_fields_again,
                response=again,
            )
        return None

    async def _persist(
        self,
        *,
        reference_url: str,
        current_version: str,
        candidate_version: str,
        candidate_url: str,
        leaked_fields: list[str],
        response: httpx.Response,
    ) -> Finding:
        check_def = get_check("api-deprecated-version-excessive-data-exposure", filename=_CATALOG_FILE)
        extra = {
            "current_version": f"v{current_version}",
            "leaking_version": f"v{candidate_version}",
            "leaking_url": candidate_url,
            "leaked_fields": ", ".join(leaked_fields),
        }
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="api-deprecated-version-excessive-data-exposure",
            title=check_def.title,
            severity=check_def.severity,
            owasp_2025_category=check_def.owasp_2025_category,
            cwe_id=check_def.cwe_id,
            portswigger_reference_url=check_def.portswigger_reference_url,
            cvss_vector=check_def.cvss_vector,
            cvss_score=check_def.cvss_score,
            affected_endpoints=[reference_url, candidate_url],
            plain_language_summary=check_def.plain_language_summary,
            technical_description=render_check_template(
                check_def.technical_description, reference_url, extra
            ),
            steps_to_reproduce=[
                f"1. Request {reference_url} (the version the application currently references) "
                "and note its JSON response fields.",
                f"2. Request {candidate_url} (an older version of the same resource) and observe "
                f"its response includes: {', '.join(leaked_fields)} — fields the current version's "
                "response does not expose.",
            ],
            remediation=check_def.remediation,
            references=[*check_def.references, check_def.portswigger_reference_url],
            confirmation_status="ai_confirmed",
        )
        request_raw = format_request_raw(response)
        response_raw = format_response_raw(response)
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
                    payload=candidate_url,
                    screenshot_refs=screenshot_refs,
                    additional_notes=(
                        f"The {extra['leaking_version']} response above includes "
                        f"{', '.join(leaked_fields)}, absent from the {extra['current_version']} "
                        "response the application actually references."
                    ),
                )
            )
            await self._session.commit()
        return finding
