"""File upload vulnerabilities (§3) — deterministic acceptance check: for
each discovered file-upload form, does the endpoint accept a file with a
dangerous, potentially server-executable extension with no apparent
validation? See app.checks.file_upload_catalog.yaml for the honest scope
of what this does and doesn't prove.
"""

import uuid

import httpx

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.evidence_screenshot import capture_and_store_evidence_screenshot
from app.agents.http_client import ScopedHttpClient, ScopeViolationError
from app.agents.recon import FormInfo
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.finding import Evidence, Finding

_CATALOG_FILE = "file_upload_catalog.yaml"

# (extension, content-type, marker content) — the three most common
# server-side stacks' web-shell extensions. Stops at the first one
# accepted; doesn't try to prove all three are exploitable.
_DANGEROUS_UPLOADS = (
    (".php", "application/x-php", b'<?php echo "verdikt-upload-test"; ?>'),
    (".jsp", "application/x-jsp", b'<% out.println("verdikt-upload-test"); %>'),
    (".asp", "application/x-asp", b'<% Response.Write("verdikt-upload-test") %>'),
)


def _file_field_name(form: FormInfo) -> str | None:
    for field in form.fields:
        if field.type == "file":
            return field.name
    return None


def _other_fields(form: FormInfo, file_field_name: str) -> dict[str, str]:
    return {
        field.name: "verdikt-test-value"
        for field in form.fields
        if field.name != file_field_name and field.type not in ("submit", "button") and field.name
    }


class FileUploadAgent:
    """No LLM needed — a single deterministic acceptance check per form
    (§1.2 safe-by-default: uploads a small, inert marker file — no
    payload here is ever actually executed by this agent)."""

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
        for form in forms:
            if form.method != "POST":
                continue
            file_field = _file_field_name(form)
            if file_field is None:
                continue
            finding = await self._check_form(form, file_field)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _try_upload(
        self, form: FormInfo, file_field: str, extension: str, content_type: str, content: bytes
    ) -> httpx.Response | None:
        filename = f"verdikt-upload-test{extension}"
        try:
            return await self._client.post_multipart(
                form.action_url,
                files={file_field: (filename, content, content_type)},
                fields=_other_fields(form, file_field),
            )
        except (ScopeViolationError, httpx.HTTPError):
            return None

    async def _check_form(self, form: FormInfo, file_field: str) -> Finding | None:
        for extension, content_type, content in _DANGEROUS_UPLOADS:
            response = await self._try_upload(form, file_field, extension, content_type, content)
            if response is None or response.status_code >= 400:
                continue

            # §2 step 1: deterministic re-execution before confirming.
            response_again = await self._try_upload(
                form, file_field, extension, content_type, content
            )
            if response_again is None or response_again.status_code >= 400:
                continue

            return await self._persist(form, extension, content_type, response_again)
        return None

    async def _persist(
        self, form: FormInfo, extension: str, content_type: str, response: httpx.Response
    ) -> Finding:
        check_def = get_check("file-upload-insufficient-validation", filename=_CATALOG_FILE)
        extra = {
            "extension": extension,
            "content_type": content_type,
            "status_code": str(response.status_code),
        }
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="file-upload-insufficient-validation",
            title=check_def.title,
            severity=check_def.severity,
            owasp_2025_category=check_def.owasp_2025_category,
            cwe_id=check_def.cwe_id,
            portswigger_reference_url=check_def.portswigger_reference_url,
            cvss_vector=check_def.cvss_vector,
            cvss_score=check_def.cvss_score,
            affected_endpoints=[form.action_url],
            plain_language_summary=render_check_template(
                check_def.plain_language_summary, form.action_url, extra
            ),
            technical_description=render_check_template(
                check_def.technical_description, form.action_url, extra
            ),
            steps_to_reproduce=[
                f'1. Submit {form.action_url} with a file named "verdikt-upload-test{extension}" '
                f'(Content-Type: {content_type}).',
                f"2. Observe the upload is accepted (HTTP {response.status_code}) instead of "
                "being rejected for its extension/content type.",
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
                    screenshot_refs=screenshot_refs,
                )
            )
            await self._session.commit()
        return finding
