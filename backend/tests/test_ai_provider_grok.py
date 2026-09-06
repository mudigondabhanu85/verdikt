import json

import httpx2

from app.ai.adapters.base import Message
from app.ai.adapters.grok import GrokAdapter


def _handler(request: httpx2.Request) -> httpx2.Response:
    assert str(request.url) == "https://api.x.ai/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer xai-test-key"
    body = json.loads(request.content.decode())
    assert body["model"] == "grok-2"
    assert body["temperature"] == 0

    return httpx2.Response(
        200,
        json={
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": "vulnerable: true"}, "finish_reason": "stop"}
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        },
    )


async def test_grok_adapter_hits_xai_base_url_with_bearer_auth_and_zero_temperature():
    adapter = GrokAdapter(
        "xai-test-key",
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(_handler)),
    )
    response = await adapter.complete([Message("user", "hi")], model="grok-2")
    assert response.content == "vulnerable: true"
    assert response.input_tokens == 10
    assert response.output_tokens == 5


def test_grok_cost_estimation_uses_pricing_table():
    adapter = GrokAdapter("k")
    cost = adapter.estimate_cost(1_000_000, 1_000_000, "grok-2")
    assert cost == 2.00 + 10.00


def test_grok_cost_estimation_falls_back_for_unknown_model():
    adapter = GrokAdapter("k")
    cost = adapter.estimate_cost(1_000_000, 0, "grok-3-preview")
    assert cost == 5.00
