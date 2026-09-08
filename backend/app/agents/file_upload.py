"""File upload vulnerabilities (§3) — deterministic acceptance check: for
each discovered file-upload form, does the endpoint accept a file with a
dangerous, potentially server-executable extension with no apparent
validation? See app.checks.file_upload_catalog.yaml for the honest scope
of what this does and doesn't prove.
"""

import re
import struct
import uuid
import zlib
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from app.agents.evidence import format_request_raw, format_response_raw
from app.agents.evidence_screenshot import capture_and_store_evidence_screenshot
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient, ScopeViolationError
from app.agents.login import _live_field_values
from app.agents.recon import FormInfo
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.finding import Evidence, Finding

_CATALOG_FILE = "file_upload_catalog.yaml"

_MARKER = b'<?php echo "verdikt-upload-test"; ?>'

# (extension, content-type, marker content) — the three most common
# server-side stacks' web-shell extensions. Stops at the first one
# accepted; doesn't try to prove all three are exploitable.
_DANGEROUS_UPLOADS = (
    (".php", "application/x-php", _MARKER),
    (".jsp", "application/x-jsp", b'<% out.println("verdikt-upload-test"); %>'),
    (".asp", "application/x-asp", b'<% Response.Write("verdikt-upload-test") %>'),
)


def _gif_polyglot() -> bytes:
    """GIF89a signature + the minimum Logical Screen Descriptor a
    getimagesize()-style content check needs to report real dimensions
    (1x1, no global color table) — everything after this is invisible
    to a GIF parser but still physically stored in the file. The
    classic, most reliable image/code polyglot technique because GIF
    readers stop at a trailer marker and never validate what follows."""
    header = b"GIF89a" + struct.pack("<HH", 1, 1) + b"\x00\x00\x00"
    return header + _MARKER


def _png_polyglot() -> bytes:
    """PNG signature + a real IHDR chunk (1x1, 8-bit grayscale) with a
    correctly computed CRC — some getimagesize()-style checks validate
    the CRC, not just the presence of a PNG-looking header, so a fake
    one would fail validation on those. No IDAT/IEND chunks follow, so
    this won't survive a decoder that actually renders pixel data (e.g.
    Pillow/ImageMagick round-tripping the file) — only ones that, like
    PHP's getimagesize(), just read the header."""
    signature = b"\x89PNG\r\n\x1a\n"
    chunk_type = b"IHDR"
    chunk_data = struct.pack(">II", 1, 1) + bytes([8, 0, 0, 0, 0])
    crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
    ihdr_chunk = struct.pack(">I", len(chunk_data)) + chunk_type + chunk_data + struct.pack(">I", crc)
    return signature + ihdr_chunk + _MARKER


# Only tried when every extension in _DANGEROUS_UPLOADS above is
# rejected — i.e. the endpoint enforces an image-extension allow-list.
# Each payload is a structurally real image (passes a getimagesize()-
# style check) with a PHP payload appended after the image data.
_POLYGLOT_UPLOADS = (
    (".gif", "image/gif", _gif_polyglot()),
    (".png", "image/png", _png_polyglot()),
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
    """No LLM needed — a deterministic acceptance check per form (§1.2
    safe-by-default: uploads a small, inert marker file — no payload
    here is ever actually executed by this agent). Confirmation requires
    actually fetching the uploaded file back and finding our marker
    content in it — not just inferring acceptance from a status code —
    after a real, live-found false positive: an unauthenticated upload
    attempt against DVWA got redirected to its login page (a 302, well
    under the old ">= 400 means rejected" bar) and was wrongly recorded
    as an accepted upload on every security level, every scan, all
    session (see (1) and (2) below for the two underlying causes)."""

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
        forms: list[FormInfo],
        sessions: dict[uuid.UUID, "AuthenticatedSession"] | None = None,
    ) -> list[Finding]:
        # (1) A real, live-found bug: this never carried any session at
        # all, so every upload attempt was fully unauthenticated —
        # structurally unable to reach a login-gated upload form
        # regardless of how permissive its validation really was.
        self._auth_session = next(iter((sessions or {}).values()), None)
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

    async def _live_hidden_and_submit_values(self, form: FormInfo, file_field: str) -> dict[str, str]:
        # (2) Same bug class already fixed for the login form and Stored
        # XSS: a hidden anti-CSRF token or the submit button's own field
        # is often required for the server to treat this as a real
        # submission at all, and both need a *fresh* value read right
        # before submitting, not a stale one captured whenever recon
        # first crawled the page.
        other_names = {
            f.name for f in form.fields if f.type in ("hidden", "submit") and f.name != file_field
        }
        if not other_names:
            return {}
        try:
            pre_submit = await self._client.get(form.action_url, session=self._auth_session)
        except (ScopeViolationError, httpx.HTTPError):
            return {}
        return _live_field_values(pre_submit.text, other_names)

    async def _try_upload(
        self, form: FormInfo, file_field: str, extension: str, content_type: str, content: bytes
    ) -> tuple[str, httpx.Response] | None:
        filename = f"verdikt-upload-test{extension}"
        fields = {**_other_fields(form, file_field), **await self._live_hidden_and_submit_values(form, file_field)}
        try:
            response = await self._client.post_multipart(
                form.action_url,
                files={file_field: (filename, content, content_type)},
                fields=fields,
                session=self._auth_session,
            )
        except (ScopeViolationError, httpx.HTTPError):
            return None
        return filename, response

    def _rejected(self, response: httpx.Response) -> bool:
        # A redirect elsewhere (a login page being the real, live-found
        # case) means the request was never actually processed as an
        # upload attempt at all — treating "any status under 400" as
        # acceptance, as this used to, counted an unauthenticated
        # redirect-to-login as a confirmed vulnerability.
        return response.status_code >= 400 or response.is_redirect

    async def _fetch_uploaded_file(self, form: FormInfo, response: httpx.Response, filename: str) -> str | None:
        """Looks for the uploaded filename anywhere in the acceptance
        response — as a plain-text echoed path (DVWA's own low/medium/
        high all do exactly this: `{path}/{filename} succesfully
        uploaded!`, no link markup at all) or as a real `<a href>` — and
        actually fetches whatever URL that resolves to, returning its
        body only if our own marker content is really present there.
        Real reproduction, not an inference from a status code or a
        hopeful success-looking message: matches this codebase's
        Confirmed-Only bar for every other check (SSRF's real
        out-of-band callback, XSS's real browser execution).
        """
        text = response.text
        candidate_paths: list[str] = []

        soup = BeautifulSoup(text, "html.parser")
        for a in soup.find_all("a", href=True):
            if filename in a["href"] or filename in a.get_text():
                candidate_paths.append(a["href"])

        for match in re.finditer(r"[\w./-]*" + re.escape(filename), text):
            candidate_paths.append(match.group(0))

        base_url = str(response.url) if response.url else form.action_url
        for path in dict.fromkeys(candidate_paths):
            url = urljoin(base_url, path)
            try:
                fetched = await self._client.get(url, session=self._auth_session)
            except (ScopeViolationError, httpx.HTTPError):
                continue
            if fetched.status_code < 400 and "verdikt-upload-test" in fetched.text:
                return url
        return None

    async def _confirm_upload(
        self, form: FormInfo, file_field: str, extension: str, content_type: str, content: bytes
    ) -> tuple[httpx.Response, str] | None:
        """One accept-and-fetch-back attempt, run twice (§2 step 1:
        deterministic re-execution before confirming — a fresh upload,
        fresh fetch-back, not just re-checking the same one). Returns the
        second attempt's response/URL so callers cite the reproduced
        evidence, not the first."""
        for _ in range(2):
            result = await self._try_upload(form, file_field, extension, content_type, content)
            if result is None:
                return None
            filename, response = result
            if self._rejected(response):
                return None
            uploaded_url = await self._fetch_uploaded_file(form, response, filename)
            if uploaded_url is None:
                return None
        return response, uploaded_url

    async def _check_form(self, form: FormInfo, file_field: str) -> Finding | None:
        for extension, content_type, content in _DANGEROUS_UPLOADS:
            confirmed = await self._confirm_upload(form, file_field, extension, content_type, content)
            if confirmed is not None:
                response, uploaded_url = confirmed
                return await self._persist(
                    "file-upload-insufficient-validation", form, extension, content_type, response, uploaded_url
                )

        # Only reached when every dangerous extension above was
        # rejected — i.e. this endpoint does enforce an image-extension
        # allow-list. Try the same accept-and-fetch-back proof with a
        # payload that's simultaneously a structurally real image and
        # executable code, disguised under an allowed extension.
        for extension, content_type, content in _POLYGLOT_UPLOADS:
            confirmed = await self._confirm_upload(form, file_field, extension, content_type, content)
            if confirmed is not None:
                response, uploaded_url = confirmed
                return await self._persist(
                    "file-upload-image-polyglot-bypass", form, extension, content_type, response, uploaded_url
                )
        return None

    async def _persist(
        self,
        check_id: str,
        form: FormInfo,
        extension: str,
        content_type: str,
        response: httpx.Response,
        uploaded_url: str,
    ) -> Finding:
        check_def = get_check(check_id, filename=_CATALOG_FILE)
        extra = {
            "extension": extension,
            "content_type": content_type,
            "status_code": str(response.status_code),
        }
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id=check_id,
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
                f"2. Fetch {uploaded_url} and observe the uploaded content is served back "
                "unchanged — the file was genuinely accepted and stored, not just given a "
                "non-error status code.",
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
                    additional_notes=(
                        f"Confirmed by actually fetching the uploaded file back at {uploaded_url} "
                        "and finding our own marker content in it — not inferred from the upload "
                        "response's status code alone."
                    ),
                )
            )
            await self._session.commit()
        return finding
