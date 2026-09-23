"""sandbox-runner — the sidecar service that holds the Docker socket on
behalf of Verdikt's AI-driven autonomous pentest mode, so the much
larger main `backend` container (57 agent modules, every
app.integrations.*, Playwright/Chromium, and — the sharper reason —
the code path that parses untrusted target HTTP responses) never has
to. Docker-socket access is effectively host-root-equivalent (a
container holding it can trivially launch a new container with
`-v /:/host` and chroot into the host filesystem); if the main backend
were ever compromised — a dependency CVE, or a prompt-injection payload
in a scanned response tricking the autonomous agent into misusing its
own tool access — that access level would be a categorically bigger
blast radius than "a compromised ephemeral sandbox," which is *meant*
to run attacker-adjacent commands against a target in the first place.

This service does exactly three things, on purpose kept small enough to
actually audit: create an ephemeral, network-isolated container per
pentest session (docker_manager.py + network_policy.py), exec commands
into it, and destroy it. No published host port — reachable only over
the internal Docker Compose network (see docker-compose.yml), same
posture as the `db` service.
"""

import asyncio
import logging
import os
import socket
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException

from app.auth import require_api_key
from app.docker_manager import SessionManager
from app.models import (
    CreateSessionRequest,
    CreateSessionResponse,
    ExecRequest,
    ExecResponse,
    SessionInfo,
    SessionStatus,
)

logger = logging.getLogger("sandbox_runner")

_sessions = SessionManager()
# How often the self-reap loop below sweeps for TTL-expired sessions —
# independent of, and a fair bit tighter than, the main backend's own
# reaper interval (app.config.Settings.autonomous_pentest_reaper_interval_seconds),
# since this loop's only job is enforcing what each session's own creator
# already asked for (ttl_seconds), not reconciling against ScanRun state.
_REAP_INTERVAL_SECONDS = int(os.environ.get("SANDBOX_RUNNER_REAP_INTERVAL_SECONDS", "60"))


async def _reap_loop() -> None:
    while True:
        await asyncio.sleep(_REAP_INTERVAL_SECONDS)
        try:
            reaped = _sessions.reap_expired()
            if reaped:
                logger.warning("reaped %d TTL-expired session(s): %s", len(reaped), reaped)
        except Exception:  # noqa: BLE001 — a reap-loop crash must never take the whole service down
            logger.exception("session reap sweep failed")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    task = asyncio.create_task(_reap_loop())
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="Verdikt sandbox-runner", lifespan=lifespan)

# Every session's iptables ruleset explicitly DROPs traffic to these,
# regardless of what's on the caller-supplied allow-list — a sandboxed
# pentest tool reaching a sibling compose service (or, in a real cloud
# deployment, the instance metadata endpoint network_policy.py already
# denies unconditionally) would be a scope violation no allow-list
# mistake should be able to produce. Resolved once at import time since
# these are this deployment's own fixed services, not per-session data;
# a resolution failure for any one of them is logged and skipped rather
# than crashing the whole service, since a genuinely misconfigured
# compose network shouldn't make sandbox-runner itself unable to start.
_PEER_SERVICE_HOSTNAMES = ("backend", "db", "sandbox-runner")


def _resolve_peer_deny_ips() -> list[str]:
    ips: list[str] = []
    for hostname in _PEER_SERVICE_HOSTNAMES:
        try:
            ips.append(socket.gethostbyname(hostname))
        except OSError:
            logger.warning("could not resolve peer service %r for the deny-list, skipping", hostname)
    return ips


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post(
    "/sessions", response_model=CreateSessionResponse, status_code=201, dependencies=[Depends(require_api_key)]
)
async def create_session(payload: CreateSessionRequest) -> CreateSessionResponse:
    deny_ips = _resolve_peer_deny_ips()
    try:
        session_id = _sessions.create_session(
            scan_run_id=payload.scan_run_id,
            allow_list=[e.model_dump() for e in payload.allow_list],
            image=payload.image,
            deny_ips=deny_ips,
            ttl_seconds=payload.ttl_seconds,
        )
    except Exception as exc:  # noqa: BLE001 — surfaced to the caller, not swallowed
        logger.exception("session creation failed for scan_run_id=%s", payload.scan_run_id)
        raise HTTPException(status_code=502, detail=f"could not create sandbox session: {exc}") from exc
    return CreateSessionResponse(session_id=session_id)


@app.post("/sessions/{session_id}/exec", response_model=ExecResponse, dependencies=[Depends(require_api_key)])
async def exec_in_session(session_id: str, payload: ExecRequest) -> ExecResponse:
    try:
        result = _sessions.exec_command(session_id, payload.command, payload.timeout_seconds)
    except KeyError:
        raise HTTPException(status_code=404, detail="session not found")
    return ExecResponse(**result)


@app.delete("/sessions/{session_id}", status_code=204, dependencies=[Depends(require_api_key)])
async def destroy_session(session_id: str) -> None:
    # Idempotent by design, not just tolerant of it: the main backend's
    # own cancellation/cleanup path may call this more than once for the
    # same session (a cancel racing an already-completing run) — a
    # second delete on an already-gone session is a normal outcome, not
    # an error, so this returns 204 either way instead of 404.
    _sessions.destroy_session(session_id)


@app.get("/sessions/{session_id}", response_model=SessionStatus, dependencies=[Depends(require_api_key)])
async def get_session_status(session_id: str) -> SessionStatus:
    return SessionStatus(**_sessions.session_status(session_id))


@app.get("/sessions", response_model=list[SessionInfo], dependencies=[Depends(require_api_key)])
async def list_sessions() -> list[SessionInfo]:
    # Polled by the main backend's own reaper
    # (app.agents.autonomous_pentest.reaper) to reconcile against
    # ScanRun state — see that module for the other half of this.
    return [SessionInfo(**s) for s in _sessions.list_sessions()]
