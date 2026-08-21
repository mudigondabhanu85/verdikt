import json
from decimal import Decimal

import httpx2

from app.ai.adapters.base import Message
from app.ai.adapters.generic_openai import GenericOpenAIAdapter


def _handler(request: httpx2.Request) -> httpx2.Response:
    assert str(request.url) == "http://localhost:11434/v1/chat/completions"
    body = json.loads(request.content.decode())
    assert body["model"] == "llama3.1:8b"
    assert body["messages"][0]["role"] == "system"

    return httpx2.Response(
        200,
        json={
            "id": "chatcmpl-abc",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": '{"vulnerable": false}'},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 42, "completion_tokens": 7, "total_tokens": 49},
        },
    )


async def test_generic_openai_adapter_hits_configured_base_url():
    adapter = GenericOpenAIAdapter(
        "unused-key-for-local-server",
        base_url="http://localhost:11434/v1",
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(_handler)),
    )

    response = await adapter.complete(
        [Message("system", "You are a security triage assistant."), Message("user", "Triage this.")],
        model="llama3.1:8b",
    )

    assert response.content == '{"vulnerable": false}'
    assert response.input_tokens == 42
    assert response.output_tokens == 7


def test_generic_openai_adapter_defaults_to_zero_cost():
    adapter = GenericOpenAIAdapter("key", base_url="http://localhost:11434/v1")
    assert adapter.estimate_cost(1_000_000, 1_000_000, "llama3.1:8b") == Decimal(0)


def test_generic_openai_adapter_uses_supplied_pricing():
    adapter = GenericOpenAIAdapter(
        "key",
        base_url="https://my-inhouse-llm.example.com/v1",
        input_price_per_mtok=Decimal("1.00"),
        output_price_per_mtok=Decimal("2.00"),
    )
    cost = adapter.estimate_cost(500_000, 250_000, "in-house-model")
    assert cost == Decimal("0.50") + Decimal("0.50")
