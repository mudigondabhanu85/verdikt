"""GraphQL introspection detection (§3) — deterministic check: does a
GraphQL endpoint at one of the common standard paths answer a schema
introspection query? Many GraphQL endpoints aren't linked from any HTML
page recon crawls (no <a href>), so this probes a short list of
conventional paths per host directly, the same "blind probe" approach
recon itself already uses for /robots.txt and /sitemap.xml.
"""

import json
import uuid
from urllib.parse import urlsplit

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.evidence_screenshot import capture_and_store_evidence_screenshot
from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.finding import Evidence, Finding

_CATALOG_FILE = "graphql_catalog.yaml"
_CANDIDATE_PATHS = ("/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql")
_INTROSPECTION_QUERY = json.dumps({"query": "{ __schema { queryType { name } types { name } } } "})


def _origin_of(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _schema_summary(body: dict) -> str | None:
    schema = (body.get("data") or {}).get("__schema")
    if not isinstance(schema, dict):
        return None
    query_type = (schema.get("queryType") or {}).get("name")
    type_count = len(schema.get("types") or [])
    if query_type is None:
        return None
    return f'query type "{query_type}", {type_count} known types'


class GraphQLAgent:
    """No LLM needed — a single deterministic response-shape check
    (§1.2 safe-by-default: read-only introspection query, one request
    per candidate path per host)."""

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
        seen_origins: set[str] = set()
        for url in endpoints:
            origin = _origin_of(url)
            if origin in seen_origins:
                continue
            seen_origins.add(origin)
            for path in _CANDIDATE_PATHS:
                finding = await self._check_path(origin + path)
                if finding is not None:
                    findings.append(finding)
                    break  # one confirmed GraphQL endpoint per host is enough signal
        return findings

    async def _check_path(self, url: str) -> Finding | None:
        try:
            response = await self._client.post(
                url, body=_INTROSPECTION_QUERY, content_type="application/json"
            )
        except (ScopeViolationError, httpx.HTTPError):
            return None
        if response.status_code != 200:
            return None
        try:
            summary = _schema_summary(response.json())
        except (json.JSONDecodeError, ValueError):
            return None
        if summary is None:
            return None

        # §2 step 1: deterministic re-execution before confirming.
        try:
            response_again = await self._client.post(
                url, body=_INTROSPECTION_QUERY, content_type="application/json"
            )
        except (ScopeViolationError, httpx.HTTPError):
            return None
        try:
            summary_again = _schema_summary(response_again.json())
        except (json.JSONDecodeError, ValueError):
            return None
        if summary_again is None:
            return None

        check_def = get_check("graphql-introspection-enabled", filename=_CATALOG_FILE)
        extra = {"schema_summary": summary_again}
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="graphql-introspection-enabled",
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
                f'1. Send a POST request to {url} with Content-Type: application/json and body '
                '{"query": "{ __schema { queryType { name } } }"}.',
                "2. Observe the response includes schema information instead of an "
                '"introspection disabled" error.',
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
