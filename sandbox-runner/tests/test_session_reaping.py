import time
from unittest.mock import MagicMock

from app.docker_manager import Session, SessionManager


def _bare_manager() -> SessionManager:
    """Builds a SessionManager without going through __init__ (which
    calls docker.from_env() — real Docker access this unit test has no
    business needing, since list_sessions/reap_expired only manipulate
    the in-memory _sessions dict itself)."""
    manager = SessionManager.__new__(SessionManager)
    manager._sessions = {}
    return manager


def _fake_session(session_id: str, *, scan_run_id: str = "run-1", ttl_seconds: int = 3600, age_seconds: float = 0) -> Session:
    return Session(
        session_id=session_id,
        scan_run_id=scan_run_id,
        container=MagicMock(),
        network=MagicMock(),
        ttl_seconds=ttl_seconds,
        created_at=time.time() - age_seconds,
    )


def test_list_sessions_reports_every_tracked_session():
    manager = _bare_manager()
    manager._sessions["s1"] = _fake_session("s1", scan_run_id="run-a")
    manager._sessions["s2"] = _fake_session("s2", scan_run_id="run-b")

    listed = manager.list_sessions()

    assert {s["session_id"] for s in listed} == {"s1", "s2"}
    assert {s["scan_run_id"] for s in listed} == {"run-a", "run-b"}


def test_reap_expired_destroys_only_sessions_past_their_own_ttl():
    """Real, live-found bug this fixes: create_session's own ttl_seconds
    parameter used to be silently dropped before ever reaching Session —
    every session was untracked for TTL purposes regardless of what its
    creator asked for. Session now stores it, and this is what actually
    uses it."""
    manager = _bare_manager()
    manager._sessions["expired"] = _fake_session("expired", ttl_seconds=60, age_seconds=120)
    manager._sessions["fresh"] = _fake_session("fresh", ttl_seconds=3600, age_seconds=5)

    reaped = manager.reap_expired()

    assert reaped == ["expired"]
    assert "expired" not in manager._sessions
    assert "fresh" in manager._sessions


def test_reap_expired_actually_tears_down_the_container_and_network():
    manager = _bare_manager()
    expired = _fake_session("expired", ttl_seconds=60, age_seconds=120)
    manager._sessions["expired"] = expired

    manager.reap_expired()

    expired.container.remove.assert_called_once_with(force=True)
    expired.network.remove.assert_called_once()


def test_reap_expired_is_a_no_op_when_nothing_has_expired():
    manager = _bare_manager()
    manager._sessions["fresh"] = _fake_session("fresh", ttl_seconds=3600, age_seconds=5)

    reaped = manager.reap_expired()

    assert reaped == []
    assert "fresh" in manager._sessions
