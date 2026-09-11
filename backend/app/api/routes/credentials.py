import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.http_client import AuthenticatedSession, ScopedHttpClient, ScopeViolationError
from app.agents.login import SessionManager
from app.agents.macro import MacroRecorder, RecordingHandle
from app.api.deps import get_version_or_404, write_audit_log
from app.auth.rbac import require_permission
from app.db.session import get_db_session
from app.models.credential import CredentialSet
from app.models.login_macro import LoginMacro
from app.models.organization import User
from app.models.project import ScopeEntry
from app.models.target import Target
from app.schemas.credential import (
    CredentialSetCreate,
    CredentialSetOut,
    CredentialSetUpdate,
    TestLoginResult,
)
from app.schemas.login_macro import LoginMacroOut, RecordingStartedOut, RecordMacroRequest
from app.vault.credential_vault import decrypt_credential, encrypt_credential, mask_reference

router = APIRouter(prefix="/versions/{version_id}/credentials", tags=["credentials"])


async def _get_credential_or_404(
    session: AsyncSession, version_id: uuid.UUID, credential_id: uuid.UUID
) -> CredentialSet:
    credential = await session.get(CredentialSet, credential_id)
    if credential is None or credential.version_id != version_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Credential set not found")
    return credential


async def _ensure_login_endpoint_in_scope(
    session: AsyncSession, version_id: uuid.UUID, login_endpoint: str | None
) -> None:
    """Same auto-derivation targets.py already does for Target.host —
    an analyst explicitly typing a login endpoint (very often a
    third-party IdP like Okta/Auth0/Microsoft for an SSO-fronted app,
    never the target application's own host) is explicit authorization
    to reach it for login purposes, the same way adding a Target is
    explicit authorization to crawl it. Without this, SessionManager.
    _login_explicit's POST to that endpoint (app.agents.login) hits
    ScopeViolationError on every real scan and on the Test Login check
    — scope enforcement exists to keep the scanner from wandering onto
    hosts nobody authorized, not to block a host the analyst just
    configured by hand. port=None matches any port for that host (see
    app.agents.scope.is_in_scope) — simpler than computing the URL's
    actual default port here.
    """
    if not login_endpoint:
        return
    host = (urlsplit(login_endpoint).hostname or "").lower()
    if not host:
        return
    existing = await session.execute(
        select(ScopeEntry).where(ScopeEntry.version_id == version_id, ScopeEntry.host == host)
    )
    if existing.scalar_one_or_none() is None:
        session.add(ScopeEntry(version_id=version_id, host=host, port=None, in_scope=True))


@router.post("", response_model=CredentialSetOut, status_code=201)
async def add_credential_set(
    version_id: uuid.UUID,
    payload: CredentialSetCreate,
    user: User = Depends(require_permission("credential", "create")),
    session: AsyncSession = Depends(get_db_session),
) -> CredentialSet:
    await get_version_or_404(session, version_id, user.org_id)
    credential = CredentialSet(
        version_id=version_id,
        label=payload.label,
        credential_type=payload.credential_type,
        encrypted_secret=encrypt_credential(payload.username, payload.secret),
        masked_reference=mask_reference(payload.username, payload.secret),
        login_endpoint=payload.login_endpoint,
        login_method=payload.login_method,
        login_body_template=payload.login_body_template,
        login_content_type=payload.login_content_type,
        token_response_path=payload.token_response_path,
        extra_cookies=payload.extra_cookies,
        privilege_rank=payload.privilege_rank,
    )
    session.add(credential)
    await _ensure_login_endpoint_in_scope(session, version_id, payload.login_endpoint)
    # Audit the creation event, never the secret material itself (§1.5).
    await write_audit_log(
        session,
        user=user,
        action="credential.create",
        resource_type="version",
        resource_id=version_id,
        metadata={"label": payload.label, "credential_type": payload.credential_type},
    )
    await session.commit()
    await session.refresh(credential)
    return credential


@router.get("", response_model=list[CredentialSetOut])
async def list_credential_sets(
    version_id: uuid.UUID,
    user: User = Depends(require_permission("credential", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[CredentialSet]:
    await get_version_or_404(session, version_id, user.org_id)
    result = await session.execute(
        select(CredentialSet).where(CredentialSet.version_id == version_id)
    )
    return list(result.scalars().all())


@router.patch("/{credential_id}", response_model=CredentialSetOut)
async def update_credential_set(
    version_id: uuid.UUID,
    credential_id: uuid.UUID,
    payload: CredentialSetUpdate,
    user: User = Depends(require_permission("credential", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> CredentialSet:
    await get_version_or_404(session, version_id, user.org_id)
    credential = await _get_credential_or_404(session, version_id, credential_id)

    updates = payload.model_dump(exclude_unset=True)

    if "username" in updates or "secret" in updates:
        current_username, current_secret = decrypt_credential(credential.encrypted_secret)
        new_username = updates.pop("username", current_username)
        new_secret = updates.pop("secret", current_secret)
        credential.encrypted_secret = encrypt_credential(new_username, new_secret)
        credential.masked_reference = mask_reference(new_username, new_secret)

    for field, value in updates.items():
        setattr(credential, field, value)

    if "login_endpoint" in updates:
        await _ensure_login_endpoint_in_scope(session, version_id, updates["login_endpoint"])

    await write_audit_log(
        session,
        user=user,
        action="credential.update",
        resource_type="version",
        resource_id=version_id,
        metadata={"credential_id": str(credential.id), "fields_updated": list(payload.model_dump(exclude_unset=True).keys())},
    )
    await session.commit()
    await session.refresh(credential)
    return credential


@router.delete("/{credential_id}", status_code=204)
async def delete_credential_set(
    version_id: uuid.UUID,
    credential_id: uuid.UUID,
    user: User = Depends(require_permission("credential", "delete")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    await get_version_or_404(session, version_id, user.org_id)
    credential = await _get_credential_or_404(session, version_id, credential_id)
    await write_audit_log(
        session,
        user=user,
        action="credential.delete",
        resource_type="version",
        resource_id=version_id,
        metadata={"label": credential.label},
    )
    await session.delete(credential)
    await session.commit()


_MAX_TEST_LOGIN_REDIRECTS = 5
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


async def _get_following_redirects(
    client: ScopedHttpClient, url: str, *, session: AuthenticatedSession
) -> httpx.Response:
    """ScopedHttpClient deliberately never follows redirects on its own
    (agents need the raw response to detect e.g. open-redirect/cache-
    poisoning issues) — but that's the wrong default for this quick
    check: a bare `/` returning 302 to the app's real SPA entry point
    (very common — `/` -> `/app/index.html#/login` or similar) is not a
    login failure, and reporting it as one is actively misleading. Follows
    up to _MAX_TEST_LOGIN_REDIRECTS hops with the same session, then
    returns whichever response stopped being a redirect.
    """
    current_url = url
    response = await client.get(current_url, session=session)
    for _ in range(_MAX_TEST_LOGIN_REDIRECTS):
        if response.status_code not in _REDIRECT_STATUSES or "location" not in response.headers:
            return response
        current_url = str(httpx.URL(current_url).join(response.headers["location"]))
        response = await client.get(current_url, session=session)
    return response


def _test_url_for(target: Target) -> str:
    if target.base_url:
        return target.base_url
    port_suffix = f":{target.port}" if target.port and target.port not in (80, 443) else ""
    scheme = "https" if target.port != 80 else "http"
    return f"{scheme}://{target.host}{port_suffix}"


@router.post("/{credential_id}/test-login", response_model=TestLoginResult)
async def test_login(
    version_id: uuid.UUID,
    credential_id: uuid.UUID,
    user: User = Depends(require_permission("credential", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> TestLoginResult:
    """A quick "is this actually working" check an analyst can run before
    committing to a full scan — this is the direct answer to "how do I
    confirm login is working and getting a 200": attempts to establish a
    session for this credential, then fires one real authenticated
    request at the version's first Target and reports back the real
    HTTP status code, not just "session created" (a session can be
    "established" with a garbage token and still get 401s on every real
    request — that's the failure mode this exists to catch).

    Deliberately does NOT crawl for a <form> to auto-discover a login
    page (that's a real crawl, not a quick check) — credentials that
    rely on pure <form> auto-discovery (no login_endpoint, no recorded
    macro, no credential_type="api_token") report "no session
    established" here with a message pointing at running a real scan
    instead. Explicit-login-endpoint, macro-replay, and api_token
    credentials are all fully exercised for real.
    """
    await get_version_or_404(session, version_id, user.org_id)
    credential = await _get_credential_or_404(session, version_id, credential_id)

    targets = list(
        (await session.execute(select(Target).where(Target.version_id == version_id))).scalars()
    )
    if not targets:
        return TestLoginResult(
            session_established=False,
            test_request_url=None,
            test_request_status=None,
            ok=False,
            message="No target configured for this version yet — add one on the Targets tab first.",
        )
    test_url = _test_url_for(targets[0])

    scope_entries = list(
        (await session.execute(select(ScopeEntry).where(ScopeEntry.version_id == version_id))).scalars()
    )
    client = ScopedHttpClient(version_id=version_id, scope_entries=scope_entries, db_session=session)
    try:
        manager = SessionManager(client, db_session=session)
        try:
            auth_session = await manager.login(credential, forms=[])
        except Exception as exc:  # noqa: BLE001 — surface as a result, not a 500
            return TestLoginResult(
                session_established=False,
                test_request_url=test_url,
                test_request_status=None,
                ok=False,
                message=f"Login attempt raised an error: {exc}",
            )

        if auth_session is None:
            return TestLoginResult(
                session_established=False,
                test_request_url=test_url,
                test_request_status=None,
                ok=False,
                message=(
                    "No session could be established from this quick check. If this credential relies on "
                    "<form> auto-discovery (no explicit login endpoint, no recorded macro, not an API token), "
                    "that needs a real crawl this check doesn't do — run a full scan instead, or set an "
                    "explicit login endpoint / record a macro to test directly here."
                ),
            )

        try:
            response = await _get_following_redirects(client, test_url, session=auth_session)
        except ScopeViolationError as exc:
            return TestLoginResult(
                session_established=True,
                test_request_url=test_url,
                test_request_status=None,
                ok=False,
                message=(
                    f"A session was established, but following the redirect chain from {test_url} left this "
                    f"version's configured scope ({exc}) — that's likely a scope-configuration gap (add the "
                    "redirect target's host on the Scope tab), not necessarily a credential problem."
                ),
            )
        except Exception as exc:  # noqa: BLE001
            return TestLoginResult(
                session_established=True,
                test_request_url=test_url,
                test_request_status=None,
                ok=False,
                message=f"A session was established, but the follow-up request to {test_url} failed: {exc}",
            )

        final_url = str(response.url)
        redirected = final_url != test_url
        ok = 200 <= response.status_code < 300
        return TestLoginResult(
            session_established=True,
            test_request_url=final_url,
            test_request_status=response.status_code,
            ok=ok,
            message=(
                (
                    f"Login looks correct — {test_url} redirected to {final_url}, which responded 200."
                    if redirected
                    else f"Login looks correct — {test_url} responded 200."
                )
                if ok
                else (
                    f"A session was established, but "
                    f"{f'{test_url} redirected to {final_url}, which' if redirected else test_url} "
                    f"responded {response.status_code}, not 2xx — the credential/token may be invalid, "
                    "expired, or lacking access to that page."
                )
            ),
        )
    finally:
        await client.aclose()


# Single-process, in-memory registry of open recording sessions — fine
# for this app's self-hosted, single-analyst-at-a-time deployment model
# (same simplicity the old synchronous record-macro endpoint already
# leaned on). Keyed by a fresh recording_id, not the credential_id, so
# nothing breaks if an analyst opens a second recording (e.g. after a
# mistake) before finishing the first. Value is (handle, started_at) so
# _reap_stale_recordings can find abandoned ones (closed tab, crashed
# client, browser closed out-of-band) without a background task loop.
_ACTIVE_RECORDINGS: dict[uuid.UUID, tuple[RecordingHandle, datetime]] = {}
_MAX_RECORDING_AGE = timedelta(minutes=30)


async def _reap_stale_recordings() -> None:
    """Best-effort cleanup for recordings nobody ever finished or
    cancelled — no client, tab-close, or crash notifies this server, so
    without this a headed Chromium/Playwright process leaks indefinitely.
    Called opportunistically at the start of every recording-lifecycle
    endpoint rather than run as a background task loop, which would need
    its own startup/shutdown wiring in app.main's lifespan for a leak
    this rare — piggybacking on requests that are already happening is
    simpler and just as effective for a single-analyst-at-a-time tool.
    """
    now = datetime.now(timezone.utc)
    stale_ids = [
        rid for rid, (_handle, started_at) in _ACTIVE_RECORDINGS.items()
        if now - started_at > _MAX_RECORDING_AGE
    ]
    for rid in stale_ids:
        handle, _started_at = _ACTIVE_RECORDINGS.pop(rid, (None, None))
        if handle is not None:
            try:
                await MacroRecorder().cancel(handle)
            except Exception:  # noqa: BLE001 — best-effort; never block a real request on this
                pass


@router.post("/{credential_id}/record-macro/start", response_model=RecordingStartedOut, status_code=201)
async def start_recording_macro(
    version_id: uuid.UUID,
    credential_id: uuid.UUID,
    payload: RecordMacroRequest,
    user: User = Depends(require_permission("credential", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> RecordingStartedOut:
    """Launches a headed browser and returns immediately — split from
    the old single-request "block until the analyst closes the browser"
    design (see MacroRecorder.start's docstring for why: that design
    silently lost the whole recording whenever the analyst couldn't
    reliably close the *remote*, VNC-streamed browser window itself).
    The Verdikt UI streams this browser live (docker-compose's
    novnc/websockify port) and shows a "Finish recording" button that
    calls .../finish below — closing the browser is now something
    Verdikt itself does, on an explicit signal, not something that has
    to happen inside the remote view.
    """
    await _reap_stale_recordings()
    await get_version_or_404(session, version_id, user.org_id)
    await _get_credential_or_404(session, version_id, credential_id)

    recorder = MacroRecorder()
    handle = await recorder.start(payload.start_url, headless=False)
    recording_id = uuid.uuid4()
    _ACTIVE_RECORDINGS[recording_id] = (handle, datetime.now(timezone.utc))
    return RecordingStartedOut(recording_id=recording_id)


@router.post("/{credential_id}/record-macro/{recording_id}/finish", response_model=LoginMacroOut, status_code=201)
async def finish_recording_macro(
    version_id: uuid.UUID,
    credential_id: uuid.UUID,
    recording_id: uuid.UUID,
    user: User = Depends(require_permission("credential", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> LoginMacroOut:
    """The analyst's "Finish recording" click — closes the browser
    server-side and persists whatever was captured as a LoginMacro.
    Ownership is validated BEFORE the handle is popped: popping first and
    validating after meant a 404 here (stale/mismatched ids, or the
    version/credential deleted mid-recording) left the handle popped but
    never closed — a leaked headed Chromium/Playwright process, and a
    silent no-op for any later cancel attempt since the entry was
    already gone.
    """
    if recording_id not in _ACTIVE_RECORDINGS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No active recording with that id")
    await get_version_or_404(session, version_id, user.org_id)
    credential = await _get_credential_or_404(session, version_id, credential_id)
    handle, _started_at = _ACTIVE_RECORDINGS.pop(recording_id, (None, None))
    if handle is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No active recording with that id")

    recorder = MacroRecorder()
    steps = await recorder.finish(handle)

    macro = LoginMacro(
        version_id=version_id,
        credential_set_id=credential.id,
        steps=[step.to_dict() for step in steps],
    )
    session.add(macro)
    await write_audit_log(
        session,
        user=user,
        action="credential.record_macro",
        resource_type="version",
        resource_id=version_id,
        metadata={"credential_id": str(credential.id), "step_count": len(steps)},
    )
    await session.commit()
    await session.refresh(macro)

    return LoginMacroOut(
        id=macro.id,
        version_id=macro.version_id,
        credential_set_id=macro.credential_set_id,
        step_count=len(macro.steps),
        created_at=macro.created_at,
    )


@router.post("/{credential_id}/record-macro/{recording_id}/cancel", status_code=204)
async def cancel_recording_macro(
    version_id: uuid.UUID,
    credential_id: uuid.UUID,
    recording_id: uuid.UUID,
    user: User = Depends(require_permission("credential", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    await get_version_or_404(session, version_id, user.org_id)
    await _get_credential_or_404(session, version_id, credential_id)
    handle, _started_at = _ACTIVE_RECORDINGS.pop(recording_id, (None, None))
    if handle is not None:
        await MacroRecorder().cancel(handle)


@router.get("/{credential_id}/macros", response_model=list[LoginMacroOut])
async def list_login_macros(
    version_id: uuid.UUID,
    credential_id: uuid.UUID,
    user: User = Depends(require_permission("credential", "read")),
    session: AsyncSession = Depends(get_db_session),
) -> list[LoginMacroOut]:
    """§7 frontend — lets the UI show whether a credential already has a
    recorded macro (and how many steps) without re-deriving that from
    finish_recording_macro's one-shot response, which nothing previously
    persisted client-side."""
    await get_version_or_404(session, version_id, user.org_id)
    await _get_credential_or_404(session, version_id, credential_id)
    result = await session.execute(
        select(LoginMacro).where(LoginMacro.credential_set_id == credential_id)
    )
    return [
        LoginMacroOut(
            id=macro.id,
            version_id=macro.version_id,
            credential_set_id=macro.credential_set_id,
            step_count=len(macro.steps),
            created_at=macro.created_at,
        )
        for macro in result.scalars().all()
    ]


async def _get_macro_or_404(
    session: AsyncSession, version_id: uuid.UUID, credential_id: uuid.UUID, macro_id: uuid.UUID
) -> LoginMacro:
    macro = await session.get(LoginMacro, macro_id)
    if macro is None or macro.version_id != version_id or macro.credential_set_id != credential_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Login macro not found")
    return macro


@router.delete("/{credential_id}/macros/{macro_id}", status_code=204)
async def delete_login_macro(
    version_id: uuid.UUID,
    credential_id: uuid.UUID,
    macro_id: uuid.UUID,
    # Same permission as record-macro/start|finish|cancel — a macro is
    # a sub-resource of its credential, not its own RBAC resource.
    user: User = Depends(require_permission("credential", "update")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    """Lets an analyst re-record from scratch (e.g. the app's login flow
    changed, or the recording captured a wrong click) without first
    deleting and recreating the whole CredentialSet just to shed a bad
    macro — same rationale as rotate-secret existing instead of forcing
    a delete-and-recreate for a new token.
    """
    await get_version_or_404(session, version_id, user.org_id)
    await _get_credential_or_404(session, version_id, credential_id)
    macro = await _get_macro_or_404(session, version_id, credential_id, macro_id)
    await write_audit_log(
        session,
        user=user,
        action="credential.delete_macro",
        resource_type="version",
        resource_id=version_id,
        metadata={"credential_id": str(credential_id), "macro_id": str(macro_id)},
    )
    await session.delete(macro)
    await session.commit()
