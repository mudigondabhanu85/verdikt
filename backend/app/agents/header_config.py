from urllib.parse import urlsplit

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.checks import CHECKS, CheckHit, FetchedPage, run_all_checks
from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.checks.loader import CheckDefinition, get_check
from app.checks.render import render_check_template as _render
from app.models.finding import Evidence, Finding


def _steps_to_reproduce(check_def: CheckDefinition, hit: CheckHit) -> list[str]:
    return [
        f"1. Send an HTTP GET request to {hit.affected_endpoint} "
        f"(e.g. `curl -i {hit.affected_endpoint}`).",
        "2. Inspect the response headers and body.",
        f"3. Confirm the condition described above: {check_def.title.lower()}.",
    ]


def _references(check_def: CheckDefinition) -> list[str]:
    refs = list(check_def.references)
    if check_def.portswigger_reference_url:
        refs.append(check_def.portswigger_reference_url)
    return refs


class HeaderConfigAgent:
    """Runs the Phase-1 check catalog against each discovered endpoint.
    A hit only becomes a Finding after it reproduces on a fresh,
    independent re-fetch (§2 step 1, deterministic re-execution) —
    non-reproducing hits (rate limiting, WAF noise, a page that changed
    between recon and now) are discarded, not persisted.
    """

    def __init__(
        self,
        client: ScopedHttpClient,
        *,
        scan_run_id,
        agent_job_id,
        db_session: AsyncSession,
    ):
        self._client = client
        self._scan_run_id = scan_run_id
        self._agent_job_id = agent_job_id
        self._session = db_session
        self._tls_cache: dict[tuple[str, int], str | None] = {}

    async def run(self, endpoints: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for url in endpoints:
            fetched = await self._fetch_page(url)
            if fetched is None:
                continue
            page, _response = fetched
            for hit in run_all_checks(page):
                finding = await self._confirm_and_persist(hit)
                if finding is not None:
                    findings.append(finding)
        return findings

    async def _fetch_page(self, url: str) -> tuple[FetchedPage, httpx.Response] | None:
        try:
            response = await self._client.get(url)
        except (ScopeViolationError, httpx.HTTPError):
            return None
        return await self._to_fetched_page(url, response), response

    async def _to_fetched_page(self, url: str, response: httpx.Response) -> FetchedPage:
        parsed = urlsplit(url)
        tls_version = None
        if parsed.scheme == "https":
            key = (parsed.hostname or "", parsed.port or 443)
            if key not in self._tls_cache:
                self._tls_cache[key] = await self._client.probe_tls_version(*key)
            tls_version = self._tls_cache[key]
        return FetchedPage(
            url=url,
            status_code=response.status_code,
            headers=response.headers,
            text=response.text,
            scheme=parsed.scheme,
            tls_version=tls_version,
        )

    async def _confirm_and_persist(self, hit: CheckHit) -> Finding | None:
        fetched = await self._fetch_page(hit.affected_endpoint)
        if fetched is None:
            return None
        page, response = fetched

        reproduced = CHECKS[hit.check_id](page)
        if not reproduced:
            return None

        check_def = get_check(hit.check_id)
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id=hit.check_id,
            title=check_def.title,
            severity=check_def.severity,
            owasp_2025_category=check_def.owasp_2025_category,
            cwe_id=check_def.cwe_id,
            portswigger_reference_url=check_def.portswigger_reference_url,
            cvss_vector=check_def.cvss_vector,
            cvss_score=check_def.cvss_score,
            affected_endpoints=[hit.affected_endpoint],
            plain_language_summary=_render(check_def.plain_language_summary, hit.affected_endpoint, hit.extra),
            technical_description=_render(check_def.technical_description, hit.affected_endpoint, hit.extra),
            steps_to_reproduce=_steps_to_reproduce(check_def, hit),
            remediation=_render(check_def.remediation, hit.affected_endpoint, hit.extra),
            references=_references(check_def),
            confirmation_status="ai_confirmed",
        )
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()

            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=format_request_raw(response),
                    response_raw=format_response_raw(response),
                )
            )
            await self._session.commit()
        return finding
