import asyncio
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.scope import is_in_scope
from app.models.project import ScopeEntry
from app.models.traffic import TrafficInteraction


class ScopeViolationError(Exception):
    """Raised when an agent attempts to request a URL outside the
    Version's scope allow-list. This must never be silently swallowed —
    it means an agent tried to do something §1.1 explicitly forbids."""


@dataclass
class AuthenticatedSession:
    """An identity established by app.agents.login.SessionManager, applied
    per-request (not via httpx's shared cookie jar) so the Access-Control
    agent can safely juggle multiple identities concurrently on the same
    ScopedHttpClient without cross-identity contamination.
    """

    credential_set_id: UUID
    cookies: dict[str, str] = field(default_factory=dict)
    bearer_token: str | None = None


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
    HTTP calls). GET and POST only — still no PUT/DELETE/PATCH in Phase 2;
    write-method probing is Business Logic (Phase 3) territory.
    """

    def __init__(
        self,
        *,
        version_id,
        scope_entries: list[ScopeEntry],
        db_session: AsyncSession,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        session_lock: asyncio.Lock | None = None,
    ):
        self._version_id = version_id
        self._scope_entries = scope_entries
        self._session = db_session
        self._client = httpx.AsyncClient(
            timeout=timeout, follow_redirects=False, transport=transport
        )
        # Every agent shares this one AsyncSession (Phase 2's LangGraph
        # orchestrator runs several agents truly concurrently), but a
        # single AsyncSession can't be flushed/committed from more than one
        # coroutine at a time. This lock is the single point of
        # serialization for ALL writes to that session — not just traffic
        # recording below, but every agent's own Finding/Evidence/
        # AgentJob/ReviewCandidate persistence too (see their `_persist`-
        # style methods, which acquire `client.session_lock` before
        # touching the session). HTTP fetches themselves stay concurrent;
        # only the DB write is serialized. Callers that construct several
        # cooperating objects around the same session (e.g. runner.py's
        # BudgetGuard) should pass the same Lock in explicitly.
        self.session_lock = session_lock or asyncio.Lock()

    async def get(self, url: str, *, session: AuthenticatedSession | None = None) -> httpx.Response:
        return await self._request("GET", url, session=session)

    async def post(
        self,
        url: str,
        *,
        body: str,
        content_type: str = "application/json",
        session: AuthenticatedSession | None = None,
    ) -> httpx.Response:
        return await self._request("POST", url, body=body, content_type=content_type, session=session)

    async def _request(
        self,
        method: str,
        url: str,
        *,
        body: str | None = None,
        content_type: str | None = None,
        session: AuthenticatedSession | None = None,
    ) -> httpx.Response:
        if not is_in_scope(url, self._scope_entries):
            raise ScopeViolationError(f"URL outside Version scope: {url}")

        headers: dict[str, str] = {}
        if session is not None:
            if session.bearer_token:
                headers["Authorization"] = f"Bearer {session.bearer_token}"
            if session.cookies:
                # Built manually (not httpx's cookies= param, deprecated
                # for per-request use) so each identity's cookies stay
                # fully isolated — the Access-Control agent juggles
                # several identities concurrently on one client and must
                # never let them leak into a shared jar.
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
        if content_type:
            headers["Content-Type"] = content_type

        start = time.monotonic()
        response = await self._client.request(method, url, headers=headers, content=body)
        elapsed_ms = (time.monotonic() - start) * 1000

        credential_set_id = session.credential_set_id if session else None
        async with self.session_lock:
            await self._record_traffic(url, method, body, response, elapsed_ms, credential_set_id)
        return response

    async def probe_tls_version(self, host: str, port: int) -> str | None:
        return await asyncio.to_thread(probe_tls_version, host, port)

    async def _record_traffic(
        self,
        url: str,
        method: str,
        body: str | None,
        response: httpx.Response,
        elapsed_ms: float,
        credential_set_id: UUID | None,
    ) -> None:
        self._session.add(
            TrafficInteraction(
                version_id=self._version_id,
                credential_set_id=credential_set_id,
                source="agent",
                timestamp=datetime.now(timezone.utc),
                request_method=method,
                request_url=url,
                request_headers=dict(response.request.headers),
                request_query_params={},
                request_body=body,
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
