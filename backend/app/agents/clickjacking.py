"""Wires the real clickjacking browser-proof (app.agents.clickjacking_proof)
into the Finding pipeline — one check per distinct host (framability is a
site-wide header/CSP behavior, not usually a per-page one; matches
app.agents.host_header/cors's same per-host dedup for the same reason).
"""

import uuid

import httpx

from app.agents.clickjacking_proof import attempt_clickjacking_proof
from app.agents.http_client import ScopedHttpClient
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.finding import Evidence, Finding
from app.storage.local_disk import get_object_storage

_CATALOG_FILE = "clickjacking_catalog.yaml"


class ClickjackingAgent:
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
        seen_hosts: set[str] = set()
        for url in endpoints:
            host = httpx.URL(url).host
            if host in seen_hosts:
                continue
            seen_hosts.add(host)
            finding = await self._check_endpoint(url)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _check_endpoint(self, url: str) -> Finding | None:
        result = await attempt_clickjacking_proof(url)
        if not result.framable:
            return None

        screenshot_refs: list[str] = []
        if result.screenshot_png is not None:
            storage = get_object_storage()
            key = f"clickjacking-proof/{self._scan_run_id}/{uuid.uuid4().hex}.png"
            await storage.put(key, result.screenshot_png, content_type="image/png")
            screenshot_refs = [key]

        check_def = get_check("clickjacking-confirmed", filename=_CATALOG_FILE)
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="clickjacking-confirmed",
            title=check_def.title,
            severity=check_def.severity,
            owasp_2025_category=check_def.owasp_2025_category,
            cwe_id=check_def.cwe_id,
            portswigger_reference_url=check_def.portswigger_reference_url,
            cvss_vector=check_def.cvss_vector,
            cvss_score=check_def.cvss_score,
            affected_endpoints=[url],
            plain_language_summary=check_def.plain_language_summary,
            technical_description=render_check_template(check_def.technical_description, url, {}),
            steps_to_reproduce=[
                f'1. Create an HTML page with <iframe src="{url}"></iframe> embedding this page.',
                "2. Open that wrapper page in a real browser.",
                "3. Observe the target page's content actually renders inside the iframe "
                "(confirmed here by a real headless browser, with a screenshot captured as "
                "evidence) instead of being blocked.",
            ],
            remediation=check_def.remediation,
            references=[*check_def.references, check_def.portswigger_reference_url],
            confirmation_status="ai_confirmed",
        )
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()
            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=f'GET {url} (loaded inside a cross-origin <iframe>)',
                    response_raw="(see screenshot evidence — target content rendered inside the iframe)",
                    screenshot_refs=screenshot_refs,
                )
            )
            await self._session.commit()
        return finding
