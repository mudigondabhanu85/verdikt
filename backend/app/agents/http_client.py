import asyncio
import socket
import ssl
import time
from datetime import datetime, timezone

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.scope import is_in_scope
from app.models.project import ScopeEntry
from app.models.traffic import TrafficInteraction


class ScopeViolationError(Exception):
    """Raised when an agent attempts to request a URL outside the
    Version's scope allow-list. This must never be silently swallowed —
    it means an agent tried to do something §1.1 explicitly forbids."""


def probe_tls_version(host: str, port: int, *, timeout: float = 5.0) -> str | None:
    """Synchronous TLS handshake probe (connection-level, not per-request —
    call once per host). Returns None if the handshake fails for any
    reason (e.g. plaintext-only host); callers should treat that as "no
    TLS info available", not an error.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                return tls_sock.version()
    except (OSError, ssl.SSLError):
        return None


class ScopedHttpClient:
    """The only way agents talk to a target. Enforces the scope allow-list
    on every single request (§1.1) and records every request/response as a
    TrafficInteraction with source="agent" (§1.3's audit trail for agent
    HTTP calls). Read-only (GET/HEAD) in Phase 1 — both agents are
    non-destructive by design.
    """

    def __init__(
        self,
        *,
        version_id,
        scope_entries: list[ScopeEntry],
        db_session: AsyncSession,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self._version_id = version_id
        self._scope_entries = scope_entries
        self._session = db_session
        self._client = httpx.AsyncClient(
            timeout=timeout, follow_redirects=False, transport=transport
        )
        # Agents fetch concurrently (ReconAgent's bounded semaphore), but a
        # single AsyncSession can't be flushed/committed from more than one
        # coroutine at a time — serialize just the DB write, not the fetch.
        self._session_lock = asyncio.Lock()

    async def get(self, url: str) -> httpx.Response:
        if not is_in_scope(url, self._scope_entries):
            raise ScopeViolationError(f"URL outside Version scope: {url}")

        start = time.monotonic()
        response = await self._client.get(url)
        elapsed_ms = (time.monotonic() - start) * 1000

        async with self._session_lock:
            await self._record_traffic(url, "GET", response, elapsed_ms)
        return response

    async def probe_tls_version(self, host: str, port: int) -> str | None:
        return await asyncio.to_thread(probe_tls_version, host, port)

    async def _record_traffic(
        self, url: str, method: str, response: httpx.Response, elapsed_ms: float
    ) -> None:
        self._session.add(
            TrafficInteraction(
                version_id=self._version_id,
                credential_set_id=None,
                source="agent",
                timestamp=datetime.now(timezone.utc),
                request_method=method,
                request_url=url,
                request_headers=dict(response.request.headers),
                request_query_params={},
                request_body=None,
                response_status=response.status_code,
                response_headers=dict(response.headers),
                response_body=response.text if _is_textual(response) else None,
                timing_ms=elapsed_ms,
            )
        )
        await self._session.commit()

    async def aclose(self) -> None:
        await self._client.aclose()


def _is_textual(response: httpx.Response) -> bool:
    content_type = response.headers.get("content-type", "")
    return any(marker in content_type.lower() for marker in ("text", "json", "html", "xml"))
