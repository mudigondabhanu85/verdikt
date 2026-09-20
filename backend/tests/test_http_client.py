import asyncio
import time
import uuid

import httpx
import pytest
from sqlalchemy import select

from app.agents.http_client import (
    AuthenticatedSession,
    ScopedHttpClient,
    ScopeViolationError,
    install_commit_backstop,
)
from app.models.project import ScopeEntry
from app.models.traffic import TrafficInteraction
from tests.conftest import session_scope


async def test_session_extra_headers_are_sent_on_every_request(db_adapter):
    """AuthenticatedSession.extra_headers is the header-shaped equivalent
    of CredentialSet.extra_cookies — a static header (e.g. a custom
    "X-API-Key") forced onto every request for that identity, applied
    whether or not a real login/macro flow also runs.
    """
    seen_headers: dict[str, str] = {}

    async def _capture(request: httpx.Request) -> httpx.Response:
        seen_headers.update(request.headers)
        return httpx.Response(200, json={"ok": True})

    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(_capture),
        )
        auth_session = AuthenticatedSession(
            credential_set_id=uuid.uuid4(),
            extra_headers={"X-API-Key": "abc123"},
        )
        await client.get("http://site.test/api/resource", session=auth_session)

        assert seen_headers.get("x-api-key") == "abc123"
        await client.aclose()


async def test_hard_backstop_timeout_fires_independent_of_client_timeout(db_adapter, monkeypatch):
    """A real, not-fully-root-caused bug found via §14 live validation
    against OWASP Juice Shop: a live scan intermittently stalled forever
    on a single request whose exact URL, reproduced in total isolation
    (curl, a standalone httpx.AsyncClient with identical config),
    returned instantly every time — meaning httpx's own configured
    timeout, which should bound any single request, wasn't reliably
    doing so in the real scan process. ScopedHttpClient now wraps every
    request in its own explicit asyncio-level deadline as a defensive
    backstop, independent of whatever the underlying httpx.AsyncClient's
    own timeout is configured to. Proven here by configuring the client
    with an enormous httpx-level timeout (3600s) and a tiny backstop
    (via monkeypatch) — if the fix only relied on httpx's own timeout,
    this would hang for the full 3600s instead of returning in well
    under a second.
    """
    monkeypatch.setattr("app.agents.http_client._HARD_REQUEST_TIMEOUT_SECONDS", 0.2)

    import asyncio

    async def _never_responds(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(3600)
        return httpx.Response(200)  # pragma: no cover — unreachable

    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            timeout=3600.0,
            transport=httpx.MockTransport(_never_responds),
        )
        start = time.monotonic()
        with pytest.raises(httpx.HTTPError):
            await client.get("http://site.test/")
        elapsed = time.monotonic() - start

        assert elapsed < 5
        await client.aclose()


async def test_hard_backstop_timeout_fires_for_post_multipart(db_adapter, monkeypatch):
    monkeypatch.setattr("app.agents.http_client._HARD_REQUEST_TIMEOUT_SECONDS", 0.2)

    import asyncio

    async def _never_responds(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(3600)
        return httpx.Response(200)  # pragma: no cover — unreachable

    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            timeout=3600.0,
            transport=httpx.MockTransport(_never_responds),
        )
        start = time.monotonic()
        with pytest.raises(httpx.HTTPError):
            await client.post_multipart(
                "http://site.test/upload", files={"file": ("a.txt", b"hi", "text/plain")}
            )
        elapsed = time.monotonic() - start

        assert elapsed < 5
        await client.aclose()


async def test_hard_backstop_fires_when_db_commit_hangs(db_adapter, monkeypatch):
    """The backstop originally only wrapped the HTTP request itself —
    _record_traffic's own `await self._session.commit()`, made on
    *every* agent request while holding session_lock, was a real,
    unprotected await. A single hung commit (e.g. a silently-dropped
    connection to Postgres) would block whoever holds the lock forever,
    and every other concurrent agent sharing it right along with them —
    exactly the failure mode observed live against OWASP Juice Shop
    (zero DB activity visible afterwards, zero CPU, and critically the
    original HTTP-only backstop never fired, since the request itself
    had already completed by the time the commit hung). Proven here by
    forcing the session's own commit() to hang forever."""
    monkeypatch.setattr("app.agents.http_client._HARD_REQUEST_TIMEOUT_SECONDS", 0.2)

    import asyncio

    async def _hung_commit():
        await asyncio.sleep(3600)

    async with session_scope(db_adapter) as session:
        monkeypatch.setattr(session, "commit", _hung_commit)

        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(lambda r: httpx.Response(200, text="ok")),
        )
        start = time.monotonic()
        with pytest.raises(httpx.HTTPError):
            await client.get("http://site.test/")
        elapsed = time.monotonic() - start

        assert elapsed < 5
        await client.aclose()


@pytest.mark.parametrize("method_name", ["commit", "flush", "refresh", "get"])
async def test_install_commit_backstop_protects_every_backstopped_method(
    db_adapter, monkeypatch, method_name
):
    """The request-level and traffic-recording backstops above only
    cover ScopedHttpClient's own two call sites — every one of ~15
    agents (and app.agents.graph's own AgentJob bookkeeping) also
    touches the *same shared* AsyncSession directly for commit/flush/
    refresh/get, completely bypassing ScopedHttpClient. §14 live
    validation against OWASP Juice Shop found exactly this: a live scan
    stalled forever with none of the ScopedHttpClient-level backstops
    ever firing — the hang wasn't in an HTTP request or in
    traffic-recording at all, and (as later confirmed) wasn't even
    always a commit specifically; flush() and refresh() are separate,
    equally real DB-touching calls in the exact same hot paths.
    install_commit_backstop patches the session itself once, so *any*
    call to any of these methods anywhere in a scan — regardless of
    which of the many scattered call sites — shares the same
    forward-progress guarantee. Parametrized to prove every one of the
    four backstopped methods is actually covered, not just commit.
    """
    monkeypatch.setattr("app.agents.http_client._HARD_REQUEST_TIMEOUT_SECONDS", 0.2)

    import asyncio

    async with session_scope(db_adapter) as session:
        async def _hung_original(self, *args, **kwargs):
            await asyncio.sleep(3600)

        # Simulates any of the many direct `await self._session.<method>(...)`
        # call sites scattered across the agent modules — not going
        # through ScopedHttpClient at all. Patched on the class *before*
        # install_commit_backstop runs, so it's what gets captured as
        # the "original" method to wrap.
        monkeypatch.setattr(type(session), method_name, _hung_original)
        install_commit_backstop(session)

        start = time.monotonic()
        with pytest.raises(TimeoutError):
            if method_name == "refresh":
                await session.refresh(object())
            elif method_name == "get":
                await session.get(object, 1)
            else:
                await getattr(session, method_name)()
        elapsed = time.monotonic() - start

        assert elapsed < 5


async def test_agent_issued_request_with_nul_byte_response_does_not_poison_the_session(
    db_adapter,
):
    """This IS the real root cause of the "intermittent stall" §14 live
    validation against OWASP Juice Shop kept surfacing — not a hang at
    all. app.api.routes.traffic_import already strips NUL bytes from
    *imported* HAR traffic, but ScopedHttpClient records every
    agent-issued request as its own TrafficInteraction (the §1.3 audit
    trail) through a completely separate, unpatched path. A single real
    response body containing a NUL byte (confirmed live against Juice
    Shop) doesn't just fail its own insert — Postgres text columns
    reject NUL outright, which poisons the *entire shared AsyncSession*
    (PendingRollbackError on every subsequent operation), cascading
    into every other concurrent agent and silently killing the whole
    scan from inside its own cleanup path. Proven here: a response body
    containing a literal NUL byte no longer crashes the request, and
    the persisted TrafficInteraction has no NUL bytes in it, and a
    second, unrelated request on the same client/session still succeeds
    afterwards (proving no lingering poisoning).
    """
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(
                lambda r: httpx.Response(
                    200, headers={"content-type": "text/html"}, content=b"before\x00after"
                )
            ),
        )
        response = await client.get("http://site.test/asset-with-nul")
        assert response.status_code == 200

        stored = (await session.execute(select(TrafficInteraction))).scalars().all()
        assert len(stored) == 1
        assert "\x00" not in stored[0].response_body

        # The session must still be healthy for the next agent's request.
        second_response = await client.get("http://site.test/asset-with-nul")
        assert second_response.status_code == 200
        stored_again = (await session.execute(select(TrafficInteraction))).scalars().all()
        assert len(stored_again) == 2

        await client.aclose()


async def test_install_commit_backstop_recovers_session_after_one_bad_write(
    db_adapter, monkeypatch
):
    """Even with the NUL-byte fix above, any future bad write could
    poison the shared AsyncSession the same way — this proves the
    general recovery mechanism itself: install_commit_backstop rolls
    the session back after any failed commit/flush/refresh/get, so one
    agent's genuine failure doesn't cascade into every other
    concurrently-running agent sharing the same session.
    """
    async with session_scope(db_adapter) as session:
        real_commit = type(session).commit
        calls = {"n": 0}

        async def _fails_once(self):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("simulated bad write")
            return await real_commit(self)

        monkeypatch.setattr(type(session), "commit", _fails_once)
        install_commit_backstop(session)

        with pytest.raises(RuntimeError):
            await session.commit()

        # A second, unrelated commit must still succeed — the session
        # was rolled back, not left poisoned.
        await session.commit()


async def test_ordinary_request_still_succeeds_within_backstop(db_adapter):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(lambda r: httpx.Response(200, text="ok")),
        )
        response = await client.get("http://site.test/")
        assert response.status_code == 200
        assert response.text == "ok"
        await client.aclose()


async def _raise_invalid_url(*args, **kwargs):
    # Reproduces httpx's own real error for a URL its stricter parser
    # rejects (a scheme with no netloc and a path not starting with
    # "/") — is_in_scope()'s far more lenient stdlib urlsplit-based
    # check happily extracts a host/port from such a string and lets it
    # through, so the exception can only ever surface here, once httpx
    # itself actually tries to parse/build the request.
    raise httpx.InvalidURL("For absolute URLs, path must be empty or begin with '/'")


async def test_malformed_url_that_passes_scope_check_raises_scope_violation_not_invalid_url(db_adapter):
    """Real, live-found bug: an AI-suggested-and-crawler-confirmed
    endpoint (app.agents.recon_planner) fed a syntactically-odd URL
    into later agents. is_in_scope()'s lenient urlsplit-based check let
    it through (a real host/port were still extractable), but httpx's
    own stricter parser refused it once a request was actually
    attempted, raising a bare httpx.InvalidURL that none of the ~50
    `except (ScopeViolationError, httpx.HTTPError)` call sites across
    every agent catch (InvalidURL is a plain Exception subclass, NOT an
    HTTPError subclass) — crashing the entire scan run outright, and
    (via LangGraph's cancel-the-rest-of-the-group-on-one-failure
    semantics) leaving several sibling nodes' AgentJob rows stuck
    "running" forever with the shared session left permanently poisoned
    for even the scan's own final status-recording commit. Translating
    this to ScopeViolationError here means every one of those call
    sites already handles it correctly, with no changes needed there.
    """
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(lambda r: httpx.Response(200)),  # never actually reached
        )
        client._client.request = _raise_invalid_url
        with pytest.raises(ScopeViolationError):
            await client.get("http://site.test/some-malformed-endpoint")
        await client.aclose()


async def test_set_cookie_response_never_populates_the_shared_jar(db_adapter):
    """Real, live-found bug (§ "run a scan and validate the fixes"): a
    genuine full scan against DVWA saw injection/xss/stored_xss/
    file_upload/csp_bypass all find nothing on a target independently
    confirmed vulnerable moments earlier by hand. Root cause traced to
    httpx.AsyncClient's own implicit cookie jar: it auto-extracts every
    Set-Cookie it ever sees (any request, including a plain anonymous
    one with session=None), and — confirmed by reading httpx's own
    Request.__init__ — merges that jar into every subsequent outgoing
    request's Cookie header via Cookies.set_cookie_header(), appended
    after whatever this class already built explicitly. PHP (DVWA's own
    stack) takes the LAST same-named cookie in a merged header, so a
    stale/different identity's PHPSESSID appended after the real one
    silently wins server-side, downgrading an authenticated probe to an
    anonymous one with no error anywhere.

    The original fix attempt — reactively clearing the jar right after
    each request — closes most of the window but not all of it under
    genuine concurrency: a second request can be *built* (reading the
    still-dirty jar) while a first request's response already populated
    it but that request's own cleanup hasn't run yet. That precise gap
    is real but too timing-sensitive to force open reliably through the
    public API in a unit test (a sequential test always sees the reactive
    clear() finish before the next request builds, and so cannot tell
    the two fixes apart merely by running requests one after another).

    What's fully deterministic, and what this test proves: a real
    Set-Cookie response never populates the jar at all — the actual fix,
    checked directly on the client's own jar rather than inferred from a
    single request's own before/after behavior (which the pre-existing
    reactive clear() would already satisfy on its own, sequentially, and
    so can't distinguish the two fixes). A jar that can never become
    non-empty in the first place has nothing for
    Cookies.set_cookie_header() to ever merge into a concurrent,
    explicitly-authenticated request, regardless of how the two happen
    to interleave.
    """
    async def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"set-cookie": "PHPSESSID=leaked-anonymous-id"})

    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )

        # A plain anonymous request whose response sets a real session
        # cookie — the exact shape of what leaked live against DVWA.
        # Checked on the client's own jar mid-request (via a hook fired
        # before this request's own reactive clear() runs), not after
        # the fact — a check made only afterward can't tell this fix
        # apart from the pre-existing reactive clear(), which already
        # leaves the jar empty by the time a single sequential request
        # returns either way.
        seen_during_request: list[int] = []
        real_extract = client._client.cookies.extract_cookies

        def _spy_extract(response):
            real_extract(response)
            seen_during_request.append(len(client._client.cookies))

        client._client.cookies.extract_cookies = _spy_extract
        await client.get("http://site.test/set-cookie")

        assert seen_during_request == [0]
        assert len(client._client.cookies) == 0

        await client.aclose()


async def test_malformed_url_in_post_multipart_also_raises_scope_violation(db_adapter):
    async with session_scope(db_adapter) as session:
        client = ScopedHttpClient(
            version_id=uuid.uuid4(),
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(lambda r: httpx.Response(200)),
        )
        client._client.request = _raise_invalid_url
        with pytest.raises(ScopeViolationError):
            await client.post_multipart(
                "http://site.test/some-malformed-endpoint",
                files={"file": ("a.txt", b"data", "text/plain")},
            )
        await client.aclose()
