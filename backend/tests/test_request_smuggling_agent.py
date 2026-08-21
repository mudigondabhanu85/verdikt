import socket
import threading
import uuid

from sqlalchemy import select

from app.agents.http_client import ScopedHttpClient
from app.agents.request_smuggling import RequestSmugglingAgent
from app.models.project import ScopeEntry
from app.models.review_candidate import ReviewCandidate
from tests.conftest import session_scope

_HANG_TIMEOUT = 2.0


def _make_server(*, prioritizes: str | None):
    """prioritizes: "te", "cl", or None (safe — rejects ambiguous framing
    outright, matching modern RFC 7230 §3.3.3-compliant servers)."""
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(0.5)
    stop = threading.Event()

    def _handle(conn: socket.socket) -> None:
        conn.settimeout(_HANG_TIMEOUT)
        with conn:
            data = b""
            try:
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    data += chunk
            except (TimeoutError, socket.timeout):
                return
            head, _, rest = data.partition(b"\r\n\r\n")
            headers = {}
            for line in head.split(b"\r\n")[1:]:
                if b":" in line:
                    k, v = line.split(b":", 1)
                    headers[k.strip().lower()] = v.strip()
            has_cl = b"content-length" in headers
            has_te = b"transfer-encoding" in headers

            if has_cl and has_te:
                if prioritizes is None:
                    conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                    return
                if prioritizes == "te":
                    body = rest
                    while not body.endswith(b"0\r\n\r\n"):
                        try:
                            more = conn.recv(4096)
                        except (TimeoutError, socket.timeout):
                            break
                        if not more:
                            break
                        body += more
                else:
                    target = int(headers[b"content-length"])
                    body = rest
                    while len(body) < target:
                        try:
                            more = conn.recv(4096)
                        except (TimeoutError, socket.timeout):
                            break
                        if not more:
                            break
                        body += more
            try:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            except OSError:
                pass

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                # listener.settimeout(0.5) above is just how this loop
                # polls stop.is_set() cooperatively — NOT a fatal error.
                # (TimeoutError is an OSError subclass since Python
                # 3.10, so a bare `except OSError` here would silently
                # kill the whole server on the first idle gap between
                # probes — a real bug this test caught during
                # development.)
                continue
            except OSError:
                return
            threading.Thread(target=_handle, args=(conn,), daemon=True).start()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return listener, stop


async def test_te_prioritizing_backend_is_flagged(db_adapter):
    listener, stop = _make_server(prioritizes="te")
    try:
        host, port = listener.getsockname()
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            agent = RequestSmugglingAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            candidates = await agent.run([f"http://{host}:{port}/"])

            assert len(candidates) == 1
            assert candidates[0].check_type == "potential-http-request-smuggling"

            stored = (await session.execute(select(ReviewCandidate))).scalars().all()
            assert len(stored) == 1

            await client.aclose()
    finally:
        stop.set()
        listener.close()


async def test_cl_prioritizing_backend_is_flagged(db_adapter):
    listener, stop = _make_server(prioritizes="cl")
    try:
        host, port = listener.getsockname()
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            agent = RequestSmugglingAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            candidates = await agent.run([f"http://{host}:{port}/"])
            assert len(candidates) == 1
            await client.aclose()
    finally:
        stop.set()
        listener.close()


async def test_compliant_backend_rejecting_ambiguous_framing_is_not_flagged(db_adapter):
    listener, stop = _make_server(prioritizes=None)
    try:
        host, port = listener.getsockname()
        async with session_scope(db_adapter) as session:
            client = ScopedHttpClient(
                version_id=uuid.uuid4(),
                scope_entries=[ScopeEntry(host=host, port=port, in_scope=True)],
                db_session=session,
            )
            agent = RequestSmugglingAgent(
                client, scan_run_id=uuid.uuid4(), agent_job_id=uuid.uuid4(), db_session=session
            )
            candidates = await agent.run([f"http://{host}:{port}/"])
            assert candidates == []
            await client.aclose()
    finally:
        stop.set()
        listener.close()
