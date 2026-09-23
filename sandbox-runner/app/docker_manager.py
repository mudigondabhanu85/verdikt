"""Container lifecycle for sandbox-runner — the only module in this
service that talks to the Docker socket directly. Kept deliberately
small (create/exec/destroy, nothing else) so this trusted-computing base
stays easy to actually audit, unlike granting the same socket access to
Verdikt's much larger main backend (see this service's README/the AI
Pentest Mode plan for the full reasoning).

Session state is in-memory only (a process-local dict), not persisted —
same "process restart naturally drops in-flight state" tradeoff the main
backend's app.agents.task_registry already accepts for scan cancellation.
A sandbox-runner restart still loses track of any container it created
before restarting (this module has no way to rediscover which running
containers are "its own" sessions vs. anything else on the host) — the
main backend's own reaper (app.agents.autonomous_pentest.reaper) is the
outer safety net for that case, reconciling against ScanRun state instead.
What THIS module's own reap_expired() below covers is the narrower,
much more common case: a session nobody ever explicitly destroyed (a
crashed backend mid-session, a network blip during teardown) but that
sandbox-runner itself is still alive and tracking — enforced by TTL,
independent of whether the backend ever calls back at all.
"""

import time
import uuid
from dataclasses import dataclass, field

import docker
from docker.models.containers import Container
from docker.models.networks import Network

from app.network_policy import apply_ruleset


@dataclass
class Session:
    session_id: str
    scan_run_id: str
    container: Container
    network: Network
    ttl_seconds: int
    created_at: float = field(default_factory=time.time)


class SessionManager:
    def __init__(self) -> None:
        self._client = docker.from_env()
        self._sessions: dict[str, Session] = {}

    def create_session(
        self,
        *,
        scan_run_id: str,
        allow_list: list[dict],
        image: str,
        deny_ips: list[str],
        ttl_seconds: int = 3600,
    ) -> str:
        session_id = str(uuid.uuid4())
        network_name = f"pentest-session-{session_id}"
        # A plain bridge network, not --internal: the container still
        # needs real egress to the target, which --internal would also
        # block. Isolation is done by the iptables ruleset applied
        # below, not by Docker's own network mode — see
        # network_policy.py's module docstring.
        network = self._client.networks.create(network_name, driver="bridge")
        container = None
        try:
            container = self._client.containers.run(
                image,
                # Keeps the container alive for repeated exec() calls
                # without giving it any command of its own to run yet —
                # every real command arrives via exec_session() below.
                command="sleep infinity",
                detach=True,
                network=network_name,
                # The one capability this container actually needs (to
                # run iptables inside its own netns) — nothing else
                # privileged, no --privileged, no other added
                # capabilities.
                cap_add=["NET_ADMIN"],
                labels={"verdikt.scan_run_id": scan_run_id, "verdikt.session_id": session_id},
                # No published ports, no volumes from the host — this
                # container has no reachability back into the compose
                # network beyond what the iptables ruleset explicitly
                # allows, and no filesystem access outside itself.
            )
            apply_ruleset(container, allow_list, deny_ips=deny_ips)
        except Exception:
            # Fail loudly and clean up completely rather than leaving a
            # half-configured (and therefore unpredictable-scope)
            # container running — same "never hang, never leave a
            # partial state around" discipline the main backend already
            # applies to its own scan runs.
            if container is not None:
                container.remove(force=True)
            network.remove()
            raise

        self._sessions[session_id] = Session(
            session_id=session_id,
            scan_run_id=scan_run_id,
            container=container,
            network=network,
            ttl_seconds=ttl_seconds,
        )
        return session_id

    def exec_command(self, session_id: str, command: str, timeout_seconds: int) -> dict:
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(session_id)
        started = time.monotonic()
        # `timeout <n>s` (GNU coreutils, present in every Debian/Kali-
        # based image by default) does the actual enforcement — exec_run
        # itself has no timeout parameter of its own, and a Python-side
        # wait-then-give-up wouldn't stop the process actually running
        # inside the container. A command that overruns exits 124 (GNU
        # timeout's own convention), which the caller can recognize.
        # `sh -c` (not a bare argv split) so the model's own command
        # string can use pipes/redirects/quoting the way a real shell
        # command normally would.
        result = session.container.exec_run(
            ["timeout", f"{timeout_seconds}s", "sh", "-c", command], demux=True
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        stdout, stderr = result.output if result.output else (None, None)
        return {
            "stdout": (stdout or b"").decode(errors="replace"),
            "stderr": (stderr or b"").decode(errors="replace"),
            "exit_code": result.exit_code,
            "duration_ms": duration_ms,
        }

    def destroy_session(self, session_id: str) -> bool:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        session.container.remove(force=True)
        session.network.remove()
        return True

    def session_status(self, session_id: str) -> dict:
        session = self._sessions.get(session_id)
        if session is None:
            return {"session_id": session_id, "status": "not_found", "created_at": None}
        return {"session_id": session_id, "status": "running", "created_at": str(session.created_at)}

    def list_sessions(self) -> list[dict]:
        """Every session this process currently knows about — the basis
        for both the main backend's own reaper (which cross-references
        scan_run_id against ScanRun state) and this module's own
        TTL-based self-reaping below."""
        return [
            {
                "session_id": s.session_id,
                "scan_run_id": s.scan_run_id,
                "created_at": s.created_at,
                "ttl_seconds": s.ttl_seconds,
            }
            for s in self._sessions.values()
        ]

    def reap_expired(self) -> list[str]:
        """Destroys every session whose ttl_seconds has elapsed since
        creation, regardless of whether its parent ScanRun is still
        "running" — a session left alive well past what its own creator
        asked for is a resource leak either way, independent of whatever
        state the main backend's database says. Returns the destroyed
        session_ids so the caller can log what happened."""
        now = time.time()
        expired = [s.session_id for s in self._sessions.values() if now - s.created_at > s.ttl_seconds]
        for session_id in expired:
            self.destroy_session(session_id)
        return expired
