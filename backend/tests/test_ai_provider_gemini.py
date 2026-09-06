import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.ai.adapters.base import Message
from app.ai.adapters.gemini import GeminiAdapter


def _make_gemini_fixture(*, status: int = 200):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            received.append({"path": self.path, "body": json.loads(body)})
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            payload = {
                "candidates": [
                    {"content": {"parts": [{"text": '{"vulnerable": true, "confidence": "high", "reasoning": "sql error"}'}]}}
                ],
                "usageMetadata": {"promptTokenCount": 42, "candidatesTokenCount": 17},
            }
            self.wfile.write(json.dumps(payload).encode())

        def log_message(self, format, *args):  # noqa: A002
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, received


@pytest.mark.anyio
async def test_gemini_adapter_sends_expected_request_and_parses_response():
    server, thread, received = _make_gemini_fixture()
    try:
        host, port = server.server_address
        adapter = GeminiAdapter("test-key", base_url=f"http://{host}:{port}")
        response = await adapter.complete(
            [
                Message(role="system", content="You are a triage assistant."),
                Message(role="user", content="Is this vulnerable?"),
            ],
            model="gemini-2.0-flash",
        )
        assert response.content == '{"vulnerable": true, "confidence": "high", "reasoning": "sql error"}'
        assert response.input_tokens == 42
        assert response.output_tokens == 17

        assert len(received) == 1
        req = received[0]
        assert req["path"].startswith("/v1beta/models/gemini-2.0-flash:generateContent?key=test-key")
        assert req["body"]["generationConfig"]["temperature"] == 0
        assert req["body"]["systemInstruction"]["parts"][0]["text"] == "You are a triage assistant."
        assert req["body"]["contents"][0]["role"] == "user"
    finally:
        server.shutdown()
        thread.join(timeout=2)


@pytest.mark.anyio
async def test_gemini_adapter_raises_on_non_2xx():
    server, thread, _received = _make_gemini_fixture(status=500)
    try:
        host, port = server.server_address
        adapter = GeminiAdapter("test-key", base_url=f"http://{host}:{port}")
        with pytest.raises(Exception):
            await adapter.complete([Message(role="user", content="hi")], model="gemini-2.0-flash")
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_gemini_cost_estimation_uses_pricing_table():
    adapter = GeminiAdapter("k")
    cost = adapter.estimate_cost(1_000_000, 1_000_000, "gemini-2.0-flash")
    assert cost == 0.10 + 0.40


def test_gemini_cost_estimation_falls_back_for_unknown_model():
    adapter = GeminiAdapter("k")
    cost = adapter.estimate_cost(1_000_000, 0, "some-future-model")
    assert cost == 1.25
