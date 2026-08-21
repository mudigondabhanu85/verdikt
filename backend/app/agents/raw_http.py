"""Raw-socket HTTP/1.1 primitives for checks that need control over the
wire format httpx won't allow — deliberately ambiguous Content-Length
vs Transfer-Encoding framing (request smuggling) and a raw Upgrade
handshake (WebSocket). httpx normalizes/validates headers and won't
send genuinely conflicting framing, so these checks talk to a raw
socket directly, the same way probe_tls_version() (app.agents.
http_client) already does for TLS-version detection.
"""

import socket
import ssl
import time


def send_raw(
    host: str,
    port: int,
    raw_request: bytes,
    *,
    use_tls: bool = False,
    timeout: float = 5.0,
    max_bytes: int = 65536,
) -> tuple[bytes, float]:
    """Opens a fresh connection, sends raw_request verbatim, and does a
    SINGLE read of up to max_bytes. Returns (response_bytes,
    elapsed_seconds) — elapsed_seconds is the primary signal for the
    request-smuggling timing probes (a connection that hangs waiting
    for bytes that never arrive times out rather than raising, since
    that hang *is* the result); response_bytes (typically just the
    status line) is what the WebSocket handshake check inspects.

    Deliberately not a read-until-EOF loop: these targets speak
    HTTP/1.1 persistent connections, so after the first response the
    peer just waits for the next request on the same socket rather
    than closing it — looping would make every probe (even a fast,
    non-hanging one) block for the full timeout waiting for a second
    read that's never coming, which would corrupt the very timing
    signal this function exists to measure.
    """
    start = time.monotonic()
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.sendall(raw_request)
        sock.settimeout(timeout)
        try:
            response = sock.recv(max_bytes)
        except (TimeoutError, socket.timeout):
            response = b""  # timing out is itself the smuggling signal
        return response, time.monotonic() - start
    finally:
        sock.close()
