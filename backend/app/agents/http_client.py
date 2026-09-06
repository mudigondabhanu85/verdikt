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


def _strip_nul_bytes(value: str | None) -> str | None:
    """This IS the "intermittent stall" bug's real root cause, found via
    §14 live validation against OWASP Juice Shop — the same NUL-byte-vs-
    Postgres-text-columns issue already fixed for *imported* HAR traffic
    (app.api.routes.traffic_import) turns out to have a second, separate
    code path: every agent-issued request ScopedHttpClient itself makes
    is ALSO recorded as a TrafficInteraction (the §1.3 audit trail), and
    that path had no NUL stripping at all. A single real response body
    containing a NUL byte (confirmed live: an uploaded image asset,
    decoded as "textual" by _is_textual's content-type check) doesn't
    just fail its own insert — it poisons the *entire shared
    AsyncSession* (SQLAlchemy raises PendingRollbackError on every
    subsequent operation until an explicit rollback()), which cascades
    into every other concurrent agent sharing that same session and
    silently crashes the whole background scan task from inside its own
    cleanup `finally` block. Four increasingly comprehensive
    asyncio.wait_for backstops never caught this because it isn't a
    hang at all — it's a fast, cascading exception, not a timeout.
    """
    if value is None:
        return None
    return value.replace("\x00", "")


# A defensive backstop above the httpx client's own `timeout` (10s by
# default) — found via §14 live validation against OWASP Juice Shop: a
# real scan intermittently stalled forever on a single request whose
# exact URL, reproduced in total isolation (curl, a standalone
# httpx.AsyncClient with identical config), returned instantly every
# time. httpx's own per-request timeout should already bound this and
# normally does, but relying on that alone left a real scan able to
# hang an AgentJob at "running" forever with zero error, zero timeout,
# and no diagnosable cause. Wrapping every request in an explicit
# asyncio-level deadline guarantees forward progress regardless of
# *why* any single request doesn't return — the actual failure mode
# worth eliminating structurally, independent of ever fully
# root-causing the specific trigger.
_HARD_REQUEST_TIMEOUT_SECONDS = 20.0


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


# Every DB-touching AsyncSession method actually awaited anywhere in a
# scan's hot path — across app.agents.graph (_start_job/_finish_job use
# commit/refresh/get) and every individual agent's own Finding/Evidence
# persistence (commit/flush). `add()` is deliberately excluded: it's
# synchronous (no await, can't hang) everywhere it's used.
_BACKSTOPPED_SESSION_METHODS = ("commit", "flush", "refresh", "get")


def install_commit_backstop(session: AsyncSession) -> None:
    """Patches this specific AsyncSession *instance*'s DB-touching
    methods (see _BACKSTOPPED_SESSION_METHODS) with a hard asyncio-level
    deadline each. §14 live validation against OWASP Juice Shop found a
    live scan intermittently stalling forever with zero DB activity,
    zero CPU, and — critically — ScopedHttpClient's own request-level
    backstop never firing, because the hang wasn't in the HTTP request
    at all: every one of the ~15 agents (and app.agents.graph's own
    AgentJob bookkeeping) touches this same shared AsyncSession
    directly, completely bypassing ScopedHttpClient. No single call
    site can be trusted to cover all of them — this patches the session
    itself, once, so every one of its DB-touching methods anywhere in a
    scan run shares the same guarantee: forward progress, no matter
    which of the many scattered call sites the next hang turns up in.
    """

    def _wrap(name: str):
        original = getattr(session, name)

        async def _with_backstop(*args, **kwargs):
            try:
                return await asyncio.wait_for(
                    original(*args, **kwargs), timeout=_HARD_REQUEST_TIMEOUT_SECONDS
                )
            except asyncio.TimeoutError as exc:
                raise TimeoutError(
                    f"DB {name}() exceeded hard backstop timeout ({_HARD_REQUEST_TIMEOUT_SECONDS}s)"
                ) from exc
            except Exception:
                # A confirmed-real failure mode, not hypothetical (§14
                # live validation against OWASP Juice Shop): one bad
                # write (a NUL byte Postgres rejects, or anything else)
                # leaves SQLAlchemy's AsyncSession in a poisoned
                # "pending rollback" state where *every* subsequent
                # operation raises PendingRollbackError — cascading the
                # one agent's failure into every other agent sharing
                # this same session, silently killing the whole scan.
                # Rolling back here lets the *one* agent whose write
                # actually failed fail cleanly (its own exception still
                # propagates), while every other concurrent agent keeps
                # making real progress on a healthy session.
                try:
                    await session.rollback()
                except Exception:
                    pass  # best-effort recovery — the original failure is what matters
                raise

        return _with_backstop

    for method_name in _BACKSTOPPED_SESSION_METHODS:
        setattr(session, method_name, _wrap(method_name))


class ScopedHttpClient:
    """The only way agents talk to a target. Enforces the scope allow-list
    on every single request (§1.1) and records every request/response as a
    TrafficInteraction with source="agent" (§1.3's audit trail for agent
    HTTP calls). GET/POST plus generic request() for PUT/PATCH/DELETE
    (Phase 3's Business Logic agent needs those for workflow-order and
    price/quantity-tampering rules — Phase 1/2 agents only ever needed
    GET/POST, so those stay as the named convenience methods).
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

    async def get(
        self,
        url: str,
        *,
        session: AuthenticatedSession | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        return await self._request("GET", url, session=session, extra_headers=extra_headers)

    async def post(
        self,
        url: str,
        *,
        body: str,
        content_type: str = "application/json",
        session: AuthenticatedSession | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        return await self._request(
            "POST", url, body=body, content_type=content_type, session=session, extra_headers=extra_headers
        )

    async def request(
        self,
        method: str,
        url: str,
        *,
        body: str | None = None,
        content_type: str | None = None,
        session: AuthenticatedSession | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Generic escape hatch for PUT/PATCH/DELETE (or anything else) —
        get()/post() are just named convenience wrappers around this."""
        return await self._request(
            method, url, body=body, content_type=content_type, session=session, extra_headers=extra_headers
        )

    async def post_multipart(
        self,
        url: str,
        *,
        files: dict[str, tuple[str, bytes, str]],
        fields: dict[str, str] | None = None,
        session: AuthenticatedSession | None = None,
    ) -> httpx.Response:
        """Multipart/form-data POST — for file upload testing
        (app.agents.file_upload). Bypasses _request()'s body/content_type
        params (those assume a pre-built raw string body, which
        multipart isn't) — httpx builds the multipart body and its
        Content-Type boundary itself from files=/data=.

        files maps field_name -> (filename, content_bytes, content_type).
        """
        if not is_in_scope(url, self._scope_entries):
            raise ScopeViolationError(f"URL outside Version scope: {url}")

        headers: dict[str, str] = {}
        if session is not None:
            if session.bearer_token:
                headers["Authorization"] = f"Bearer {session.bearer_token}"
            if session.cookies:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in session.cookies.items())

        start = time.monotonic()
        try:
            response = await asyncio.wait_for(
                self._client.request("POST", url, headers=headers, data=fields or {}, files=files),
                timeout=_HARD_REQUEST_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError as exc:
            raise httpx.ReadTimeout(
                f"Hard backstop timeout ({_HARD_REQUEST_TIMEOUT_SECONDS}s) exceeded for POST {url}",
                request=httpx.Request("POST", url),
            ) from exc
        finally:
            # See _request's identical fix for why this matters.
            self._client.cookies.clear()
        elapsed_ms = (time.monotonic() - start) * 1000

        credential_set_id = session.credential_set_id if session else None
        body_summary = f"(multipart/form-data body — files: {list(files.keys())})"
        await self._record_traffic_locked(
            url, "POST", body_summary, response, elapsed_ms, credential_set_id
        )
        return response

    async def _request(
        self,
        method: str,
        url: str,
        *,
        body: str | None = None,
        content_type: str | None = None,
        session: AuthenticatedSession | None = None,
        extra_headers: dict[str, str] | None = None,
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
        if extra_headers:
            # Escape hatch for checks that need to control a specific
            # header directly (e.g. the Host Header Injection check
            # overriding Host itself) — merged in last so a caller can
            # deliberately override Content-Type/anything else above too.
            headers.update(extra_headers)

        start = time.monotonic()
        try:
            response = await asyncio.wait_for(
                self._client.request(method, url, headers=headers, content=body),
                timeout=_HARD_REQUEST_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError as exc:
            raise httpx.ReadTimeout(
                f"Hard backstop timeout ({_HARD_REQUEST_TIMEOUT_SECONDS}s) exceeded for {method} {url}",
                request=httpx.Request(method, url),
            ) from exc
        finally:
            # httpx.AsyncClient auto-extracts and persists every
            # Set-Cookie it ever sees into its own implicit jar,
            # regardless of the fact that every cookie this class sends
            # is already built explicitly above — directly contradicting
            # this class's own stated "never let identities leak into a
            # shared jar" design. Real, observed failure against DVWA: a
            # scan with 9+ agents hammering the target truly concurrently
            # (many of them anonymous, session=None) filled this jar with
            # a churn of different PHPSESSID values; once contaminated,
            # httpx started merging jar cookies into supposedly-explicit
            # session-bearing requests too, silently downgrading
            # authenticated probes to anonymous ones for the rest of the
            # scan — injection/xss found nothing not because DVWA wasn't
            # vulnerable, but because every probe after the jar got
            # polluted was quietly redirected to the login page instead.
            # Clearing after every single request guarantees the jar
            # never accumulates anything to leak in the first place.
            self._client.cookies.clear()
        elapsed_ms = (time.monotonic() - start) * 1000

        credential_set_id = session.credential_set_id if session else None
        await self._record_traffic_locked(url, method, body, response, elapsed_ms, credential_set_id)
        return response

    async def _record_traffic_locked(
        self,
        url: str,
        method: str,
        body: str | None,
        response: httpx.Response,
        elapsed_ms: float,
        credential_set_id: UUID | None,
    ) -> None:
        # Same defensive backstop as the HTTP request itself, and for
        # the same reason (§14 live validation against OWASP Juice
        # Shop): _record_traffic's own `await self._session.commit()`
        # is a real, unprotected await — a single hung DB commit (e.g.
        # a silently-dropped connection to Postgres) would block
        # whoever's holding session_lock forever, and every other
        # concurrent agent right along with it, since every write in
        # the whole scan funnels through this same lock. Wrapping the
        # *entire* lock-acquire-and-commit sequence (not just the
        # commit) means a stuck lock-holder can't wedge the scan
        # forever either.
        try:
            await asyncio.wait_for(
                self._locked_record_traffic(url, method, body, response, elapsed_ms, credential_set_id),
                timeout=_HARD_REQUEST_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError as exc:
            raise httpx.ReadTimeout(
                f"Hard backstop timeout ({_HARD_REQUEST_TIMEOUT_SECONDS}s) exceeded recording "
                f"traffic for {method} {url}",
                request=httpx.Request(method, url),
            ) from exc

    async def _locked_record_traffic(
        self,
        url: str,
        method: str,
        body: str | None,
        response: httpx.Response,
        elapsed_ms: float,
        credential_set_id: UUID | None,
    ) -> None:
        async with self.session_lock:
            await self._record_traffic(url, method, body, response, elapsed_ms, credential_set_id)

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
                request_body=_strip_nul_bytes(body),
                response_status=response.status_code,
                response_headers=dict(response.headers),
                response_body=_strip_nul_bytes(response.text) if _is_textual(response) else None,
                timing_ms=elapsed_ms,
            )
        )
        await self._session.commit()

    async def aclose(self) -> None:
        await self._client.aclose()

    def reset_cookie_jar(self) -> None:
        """Every request here is meant to carry cookies explicitly
        (session=None means "anonymous," not "whatever the underlying
        httpx client happens to remember") — but httpx.AsyncClient
        maintains its own implicit cookie jar regardless, silently
        storing and re-attaching every Set-Cookie it ever sees on this
        shared client instance. Real, observed failure: a real target
        (DVWA) issues a fresh PHPSESSID on every unauthenticated page
        view; after ReconAgent's crawl alone, the jar held multiple
        same-named cookies with inconsistent domain attributes, which
        httpx can't cleanly resolve — the wrong (or an ambiguous) one
        then gets silently attached to the login attempt, breaking
        session continuity in a way that looks like a normal failed
        login. Call this right before a login attempt (see
        SessionManager) to guarantee a clean slate — nothing downstream
        depends on the crawl's incidental cookies surviving.
        """
        self._client.cookies.clear()


def _is_textual(response: httpx.Response) -> bool:
    content_type = response.headers.get("content-type", "")
    return any(marker in content_type.lower() for marker in ("text", "json", "html", "xml"))
