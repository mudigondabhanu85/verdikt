"""Request/response shapes for sandbox-runner's own small API. Kept
separate from Verdikt's main backend schemas deliberately — this service
has its own minimal, independently-versioned surface (see main.py's
module docstring for why it's a separate codebase at all)."""

from pydantic import BaseModel, Field


class AllowListEntry(BaseModel):
    host: str
    ip: str
    # None means "every port on this host is in scope" — mirrors
    # app.agents.scope.is_in_scope's own null-port semantics exactly
    # (a ScopeEntry with no port set matches any port), not a narrower
    # {80, 443} default of this service's own invention.
    port: int | None = None
    protocol: str = "tcp"  # "tcp" or "udp"


class CreateSessionRequest(BaseModel):
    scan_run_id: str
    allow_list: list[AllowListEntry]
    image: str = "verdikt-pentest-tools:latest"
    ttl_seconds: int = 3600


class CreateSessionResponse(BaseModel):
    session_id: str


class ExecRequest(BaseModel):
    command: str
    timeout_seconds: int = 60


class ExecResponse(BaseModel):
    stdout: str
    stderr: str
    exit_code: int | None
    duration_ms: int
    # Deliberately NOT included: any "was this in scope" verdict.
    # sandbox-runner can't reliably infer a command's actual network
    # destination(s) from an arbitrary shell string (nmap, sqlmap, and
    # curl all have wildly different CLI syntax) — the iptables ruleset
    # is what actually enforces scope, invisibly, regardless of what
    # this response says. A blocked command still returns a normal
    # ExecResponse (whatever exit code/stderr the tool itself produced
    # when its connection was refused/timed out) — the caller (the main
    # backend, which already knows what it intended this command to
    # reach) is responsible for its own PentestCommand.scope_decision
    # judgment, not this service.


class SessionStatus(BaseModel):
    session_id: str
    status: str  # "running" | "not_found"
    created_at: str | None = None


class SessionInfo(BaseModel):
    """One row of GET /sessions — the listing the main backend's reaper
    (app.agents.autonomous_pentest.reaper) polls to reconcile against
    ScanRun state, and this service's own TTL-based self-reap loop uses
    internally via SessionManager.list_sessions."""

    session_id: str
    scan_run_id: str
    created_at: float
    ttl_seconds: int
