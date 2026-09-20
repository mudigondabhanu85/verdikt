"""Cross-site WebSocket hijacking / CSWSH (§3) — a deterministic check:
does the WebSocket handshake endpoint complete (101 Switching
Protocols) despite an Origin header from an unrelated,
attacker-controlled site? If so, and authentication rides on ambient
session cookies (the normal case), a malicious page visited by a
logged-in victim can open a live, authenticated WebSocket to the target
from the victim's own browser — the WebSocket-era equivalent of CSRF.

httpx doesn't speak the WebSocket upgrade handshake, so this sends a
raw HTTP/1.1 Upgrade request directly (app.agents.raw_http), the same
way app.agents.request_smuggling and http_client.probe_tls_version()
already talk to a raw socket when httpx can't do what's needed. Only
the handshake response's status line is inspected — no WebSocket
frames are ever exchanged, so this never risks sending/receiving real
application data over the hijacked connection (§1.2 safe-by-default).
"""

import asyncio
import base64
import os
import uuid
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from app.agents.evidence_screenshot import capture_and_store_evidence_screenshot
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.agents.raw_http import send_raw
from app.agents.scope import is_in_scope
from app.checks.loader import get_check
from app.checks.render import render_check_template
from app.models.finding import Evidence, Finding
from app.models.project import ScopeEntry

_CATALOG_FILE = "websocket_catalog.yaml"
_FORGED_ORIGIN = "https://verdikt-cswsh-test.invalid"
_HANDSHAKE_TIMEOUT = 5.0


def _websocket_key() -> str:
    return base64.b64encode(os.urandom(16)).decode()


def _build_handshake(host: str, path: str, *, cookie_header: str | None) -> bytes:
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {_websocket_key()}",
        "Sec-WebSocket-Version: 13",
        f"Origin: {_FORGED_ORIGIN}",
    ]
    if cookie_header:
        lines.append(f"Cookie: {cookie_header}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode()


def _handshake_accepted(response: bytes) -> bool:
    status_line = response.split(b"\r\n", 1)[0]
    return b"101" in status_line


def _strip_stale_session_id(path: str) -> str:
    """A WebSocket URL discovered from captured traffic (HAR/proxy) may
    carry an Engine.IO `sid` query param (socket.io and compatible
    libraries) — that identifies one specific, already-established
    polling session at capture time, not a stable identifier of the
    endpoint itself. Replaying it verbatim in a fresh handshake attempt
    made later always fails ("Session ID unknown" — confirmed via §14
    live validation against OWASP Juice Shop's real socket.io endpoint),
    which would misreport a real CSWSH vulnerability as not present.
    Stripping it makes the probe behave like a fresh client connecting
    for the first time, which is exactly the scenario CSWSH describes.
    """
    split = urlsplit(path)
    if not split.query:
        return path
    query = parse_qsl(split.query, keep_blank_values=True)
    filtered = [(k, v) for k, v in query if k.lower() != "sid"]
    if len(filtered) == len(query):
        return path
    return urlunsplit(("", "", split.path, urlencode(filtered), ""))


class WebSocketAgent:
    """No LLM needed — a single binary check (§1.2 safe-by-default:
    inspects only the handshake status line, never exchanges a real
    WebSocket frame)."""

    def __init__(
        self,
        client: ScopedHttpClient,
        *,
        scan_run_id: uuid.UUID,
        agent_job_id: uuid.UUID,
        db_session,
        scope_entries: list[ScopeEntry],
    ):
        self._client = client
        self._scan_run_id = scan_run_id
        self._agent_job_id = agent_job_id
        self._session = db_session
        self._scope_entries = scope_entries

    async def run(
        self,
        endpoints: list[str],
        sessions: dict[uuid.UUID, AuthenticatedSession],
    ) -> list[Finding]:
        cookie_header = self._first_cookie_header(sessions)
        findings: list[Finding] = []
        seen: set[str] = set()
        for url in endpoints:
            normalized = url.replace("wss://", "https://", 1).replace("ws://", "http://", 1)
            if not is_in_scope(normalized, self._scope_entries):
                continue
            if url in seen:
                continue
            seen.add(url)
            finding = await self._check(url, cookie_header)
            if finding is not None:
                findings.append(finding)
        return findings

    @staticmethod
    def _first_cookie_header(sessions: dict[uuid.UUID, AuthenticatedSession]) -> str | None:
        for auth_session in sessions.values():
            if auth_session.cookies:
                return "; ".join(f"{k}={v}" for k, v in auth_session.cookies.items())
        return None

    async def _check(self, url: str, cookie_header: str | None) -> Finding | None:
        parsed = httpx.URL(url.replace("wss://", "https://", 1).replace("ws://", "http://", 1))
        host = parsed.host
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"
        path = parsed.raw_path.decode() if parsed.raw_path else "/"
        path = _strip_stale_session_id(path)

        try:
            response, _ = await self._handshake(host, port, path, use_tls, cookie_header)
        except OSError:
            return None
        if not _handshake_accepted(response):
            return None

        # §2 step 1: deterministic re-execution (fresh key + fresh
        # forged origin marker each time) before confirming.
        try:
            response_again, _ = await self._handshake(host, port, path, use_tls, cookie_header)
        except OSError:
            return None
        if not _handshake_accepted(response_again):
            return None

        check_def = get_check("websocket-missing-origin-validation", filename=_CATALOG_FILE)
        extra = {"forged_origin": _FORGED_ORIGIN}
        finding = Finding(
            scan_run_id=self._scan_run_id,
            agent_job_id=self._agent_job_id,
            check_id="websocket-missing-origin-validation",
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
                f'1. From an attacker-controlled page, open a WebSocket to {url} with the '
                f'header "Origin: {_FORGED_ORIGIN}" — the browser sends this automatically, '
                "no way for the page to override it.",
                "2. Observe the server completes the handshake (101 Switching Protocols) "
                "despite the foreign Origin, using only the victim's ambient session cookies "
                "for authentication.",
            ],
            remediation=check_def.remediation,
            references=[*check_def.references, check_def.portswigger_reference_url],
            confirmation_status="ai_confirmed",
        )
        request_raw = _build_handshake(host, path, cookie_header=cookie_header).decode(errors="replace")
        response_raw = response_again.decode(errors="replace")
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
                    payload=_FORGED_ORIGIN,
                    screenshot_refs=screenshot_refs,
                )
            )
            await self._session.commit()
        return finding

    async def _handshake(
        self, host: str, port: int, path: str, use_tls: bool, cookie_header: str | None
    ) -> tuple[bytes, float]:
        raw_request = _build_handshake(host, path, cookie_header=cookie_header)
        return await asyncio.to_thread(
            send_raw, host, port, raw_request, use_tls=use_tls, timeout=_HANDSHAKE_TIMEOUT
        )
