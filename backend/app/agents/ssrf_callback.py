"""A local, real HTTP listener SsrfAgent starts for itself, per scan
run, to detect out-of-band SSRF (§3) — the only way to reliably confirm
SSRF is a real callback hit, not an in-band error-message/timing
heuristic (which produces far too many false positives/negatives). Same
"real callback, not a guess" principle as Burp Collaborator.

Real, stated-plainly limitation: this only works when the *target* can
actually route back to wherever this listener is reachable (same Docker
network, same LAN, or a scanner with a public hostname/IP —
app.config.Settings.ssrf_callback_host). A target on the public internet
with no path back to a scanner running on a private network can never be
provably confirmed this way; this agent finds nothing in that case
rather than guessing from indirect signals.
"""

import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class SsrfCallbackServer:
    def __init__(self, host: str = "0.0.0.0"):
        self._hits: set[str] = set()
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer((host, 0), self._make_handler())
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def shutdown(self) -> None:
        self._server.shutdown()
        self._thread.join(timeout=2)

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    def new_token(self) -> str:
        return uuid.uuid4().hex

    def was_hit(self, token: str) -> bool:
        with self._lock:
            return token in self._hits

    def _record_hit(self, token: str) -> None:
        with self._lock:
            self._hits.add(token)

    def _make_handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self) -> None:
                token = self.path.strip("/").rsplit("/", 1)[-1]
                outer._record_hit(token)
                self.send_response(200)
                self.end_headers()

            def do_GET(self) -> None:  # noqa: N802
                self._handle()

            def do_POST(self) -> None:  # noqa: N802
                self._handle()

            def log_message(self, format, *args):  # noqa: A002
                pass

        return Handler


def callback_url_for(host: str, port: int, token: str) -> str:
    return f"http://{host}:{port}/ssrf-callback/{token}"
