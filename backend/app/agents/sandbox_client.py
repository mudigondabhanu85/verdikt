"""Thin async HTTP client for sandbox-runner (the separate sidecar
service that holds the Docker socket — see docker-compose.yml and
sandbox-runner/app/main.py's own module docstring for the isolation
model). Nothing here talks to Docker directly; this backend never
touches the socket.
"""

import socket
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from app.config import get_settings
from app.models.project import ScopeEntry


class SandboxRunnerUnavailableError(RuntimeError):
    """Raised when app.config.Settings.sandbox_runner_base_url isn't
    configured, or sandbox-runner itself can't be reached — the
    autonomous pentest mode fails loudly with this rather than silently
    doing nothing, since most deployments running only the deterministic
    agents never set this at all."""


@dataclass
class AllowListEntry:
    host: str
    ip: str
    port: int | None  # None = every port on this host is in scope
    protocol: str = "tcp"

    def to_dict(self) -> dict:
        return {"host": self.host, "ip": self.ip, "port": self.port, "protocol": self.protocol}


def derive_allow_list(scope_entries: list[ScopeEntry]) -> list[AllowListEntry]:
    """The real allow-list a session's sandbox container's egress gets
    locked to — built from the same rows app.agents.scope.is_in_scope
    already treats as the hard technical allow-list for every
    deterministic agent, filtered to purpose="target" only.
    purpose="login_only" entries (e.g. a third-party IdP host — see
    app.api.routes.credentials._ensure_login_endpoint_in_scope) are real,
    technical in-scope access for *login* purposes only and must never
    become a pentest target, exactly the same distinction
    app.agents.scope.filter_out_login_only already enforces for the
    existing crawl-derived surface.

    DNS is resolved once, here, at session-create time — not by
    sandbox-runner, which makes no DNS trust decisions of its own (see
    its models.py). This is a real, accepted TOCTOU tradeoff: if a
    target's DNS record changes mid-session, the IP-bound egress rules
    won't follow it. That fails closed (the sandbox loses connectivity
    rather than gaining connectivity to whatever the new IP maps to),
    which is the safe direction for a security tool to fail in.
    """
    entries: list[AllowListEntry] = []
    for scope_entry in scope_entries:
        if not scope_entry.in_scope or scope_entry.purpose != "target":
            continue
        try:
            # getaddrinfo (not gethostbyname) so this also resolves
            # IPv6-only hosts if that's ever relevant — only the IPv4
            # result is used today since iptables (not ip6tables) is
            # what network_policy.py applies, matching every other
            # IPv4-only assumption already in this codebase's scope
            # handling (ScopedHttpClient included).
            ip = socket.getaddrinfo(scope_entry.host, None, family=socket.AF_INET)[0][4][0]
        except OSError:
            # A host that doesn't resolve right now can't be reached by
            # anything anyway — skip it rather than fail the whole
            # session over one bad ScopeEntry. The gap is visible in the
            # session's own allow-list (recorded in PentestCommand
            # evidence at persistence time), not silently swallowed.
            continue
        entries.append(AllowListEntry(host=scope_entry.host, ip=ip, port=scope_entry.port))
    return entries


class SandboxClient:
    def __init__(self, *, base_url: str | None = None, timeout: float = 30.0) -> None:
        self._base_url = base_url if base_url is not None else get_settings().sandbox_runner_base_url
        if not self._base_url:
            raise SandboxRunnerUnavailableError(
                "sandbox_runner_base_url is not configured in this deployment — the autonomous "
                "pentest mode is unavailable. Set Settings.sandbox_runner_base_url (e.g. "
                "http://sandbox-runner:8090) to enable it."
            )
        self._client = httpx.AsyncClient(base_url=self._base_url, timeout=timeout)

    async def create_session(
        self, *, scan_run_id: uuid.UUID, allow_list: list[AllowListEntry], image: str, ttl_seconds: int = 3600
    ) -> str:
        try:
            response = await self._client.post(
                "/sessions",
                json={
                    "scan_run_id": str(scan_run_id),
                    "allow_list": [e.to_dict() for e in allow_list],
                    "image": image,
                    "ttl_seconds": ttl_seconds,
                },
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise SandboxRunnerUnavailableError(f"could not reach sandbox-runner to create a session: {exc}") from exc
        return response.json()["session_id"]

    async def exec_command(self, session_id: str, command: str, *, timeout_seconds: int = 60) -> dict:
        response = await self._client.post(
            f"/sessions/{session_id}/exec",
            json={"command": command, "timeout_seconds": timeout_seconds},
            # A command can legitimately run up to timeout_seconds inside
            # the sandbox — the HTTP call waiting on that result needs
            # real headroom on top, not the client's own default timeout
            # cutting it off first.
            timeout=timeout_seconds + 15,
        )
        response.raise_for_status()
        return response.json()

    async def destroy_session(self, session_id: str) -> None:
        # Best-effort — a session the caller already believes is gone
        # (or sandbox-runner itself briefly unreachable during teardown)
        # must never raise out of a cleanup path and mask whatever the
        # real outcome/error already was. See docker_manager.py's own
        # idempotent-delete design on the sandbox-runner side.
        try:
            await self._client.delete(f"/sessions/{session_id}")
        except httpx.HTTPError:
            pass

    async def aclose(self) -> None:
        await self._client.aclose()
