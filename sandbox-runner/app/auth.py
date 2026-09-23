"""Shared-secret auth for sandbox-runner's own API. This service holds
the Docker socket (see main.py's module docstring on why that's kept out
of the main backend) — leaving its API unauthenticated would mean
"reachable on the compose network" is the entire access control, which
is a real privilege-escalation path for anything else that can reach
that network, not just the intended caller.

SANDBOX_RUNNER_API_KEY unset means this deployment hasn't opted in (most
likely local dev running this service directly, outside Docker Compose)
— the check is skipped entirely rather than locking everyone out by
default, matching every other "None disables this" setting in
app.config.Settings on the main backend's side. Once set, every request
must present it; there's no partial/optional mode.
"""

import hmac
import os

from fastapi import Header, HTTPException


def _configured_api_key() -> str | None:
    # Read directly from the environment, not cached at import time —
    # keeps this trivially testable (monkeypatch os.environ) without a
    # settings-module indirection this small a service doesn't otherwise
    # need.
    return os.environ.get("SANDBOX_RUNNER_API_KEY") or None


async def require_api_key(authorization: str | None = Header(default=None)) -> None:
    expected = _configured_api_key()
    if expected is None:
        return
    provided = ""
    if authorization and authorization.startswith("Bearer "):
        provided = authorization[len("Bearer ") :]
    # Constant-time comparison — this is a bearer secret gating
    # Docker-socket-equivalent access, not a UI-facing string compare.
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="missing or invalid API key")
