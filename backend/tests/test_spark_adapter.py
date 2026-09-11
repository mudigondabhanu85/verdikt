import json
from decimal import Decimal

import httpx2
import pytest

from app.ai.adapters.base import Message
from app.ai.adapters.spark import SparkAdapter


def _handler(request: httpx2.Request) -> httpx2.Response:
    # Spark ignores the SDK's auto-computed Authorization header entirely —
    # what actually authenticates the call is api-key + app_id.
    assert request.headers["api-key"] == "test-bearer-token"
    assert request.headers["app_id"] == "sparkassist"
    assert "/v1/sparkassist/" in str(request.url)
    body = json.loads(request.content.decode())
    assert body["model"] == "gpt-4o-mini"
    assert body["messages"][0]["role"] == "system"

    return httpx2.Response(
        200,
        json={
            "id": "chatcmpl-spark-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": '{"vulnerable": false}'},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 30, "completion_tokens": 5, "total_tokens": 35},
        },
    )


async def test_spark_adapter_sends_app_id_header_and_path_segment_when_given():
    # api_key mode's shape — app_id is set explicitly.
    adapter = SparkAdapter(
        "test-bearer-token",
        base_url="https://sparkapi.spglobal.com",
        api_version="2024-02-01",
        app_id="sparkassist",
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(_handler)),
    )

    response = await adapter.complete(
        [Message("system", "You are a security triage assistant."), Message("user", "Triage this.")],
        model="gpt-4o-mini",
    )

    assert response.content == '{"vulnerable": false}'
    assert response.input_tokens == 30
    assert response.output_tokens == 5


async def test_spark_adapter_omits_app_id_when_not_given():
    # bearer_token mode's normal shape — app_id is an api_key-mode-only
    # concept (confirmed against real Spark behavior): a bearer token
    # authenticates on its own, with no app_id association at all.
    def handler(request: httpx2.Request) -> httpx2.Response:
        assert request.headers["api-key"] == "test-bearer-token"
        assert "app_id" not in request.headers
        assert str(request.url).startswith("https://sparkapi.spglobal.com/v1/openai/deployments/")
        return _success_response()

    adapter = SparkAdapter(
        "test-bearer-token",
        base_url="https://sparkapi.spglobal.com",
        api_version="2024-02-01",
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(handler)),
    )

    response = await adapter.complete([Message("user", "Triage this.")], model="gpt-4o-mini")
    assert response.content == '{"vulnerable": true}'


def _success_response() -> httpx2.Response:
    return httpx2.Response(
        200,
        json={
            "id": "chatcmpl-spark-2",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": '{"vulnerable": true}'},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
        },
    )


async def test_spark_adapter_estimates_tokens_when_usage_is_missing():
    # Empirically observed 2026-09: Spark's chat-completions response
    # consistently omits `usage` — confirmed across 20 real, successful
    # calls in one live scan, all recording 0 tokens despite genuine
    # responses. Falls back to a rough ~4-chars-per-token estimate
    # rather than a flat, misleading 0.
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200,
            json={
                "id": "chatcmpl-spark-3",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "twenty characters!!"},
                        "finish_reason": "stop",
                    }
                ],
                # No "usage" key at all — the observed real-world shape.
            },
        )

    adapter = SparkAdapter(
        "test-bearer-token",
        base_url="https://sparkapi.spglobal.com",
        api_version="2024-02-01",
        app_id="sparkassist",
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(handler)),
    )

    response = await adapter.complete(
        [Message("user", "twelve chars")], model="gpt-4o-mini"
    )

    assert response.content == "twenty characters!!"
    # "twelve chars" is 12 chars -> ~3 tokens; "twenty characters!!" is
    # 19 chars -> ~4 tokens. Never exact, just non-zero and roughly
    # proportional to text length.
    assert response.input_tokens == 3
    assert response.output_tokens == 4


async def test_spark_adapter_retries_once_with_fallback_key_on_401():
    attempts: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        key = request.headers["api-key"]
        attempts.append(key)
        if key == "bad-primary-key":
            return httpx2.Response(401, json={"error": {"message": "invalid api key"}})
        assert key == "good-secondary-key"
        return _success_response()

    adapter = SparkAdapter(
        "bad-primary-key",
        base_url="https://sparkapi.spglobal.com",
        api_version="2024-02-01",
        app_id="sparkassist",
        fallback_token="good-secondary-key",
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(handler)),
    )

    response = await adapter.complete(
        [Message("user", "Triage this.")],
        model="gpt-4o-mini",
    )

    assert attempts == ["bad-primary-key", "good-secondary-key"]
    assert response.content == '{"vulnerable": true}'


async def test_spark_adapter_raises_when_both_keys_fail():
    def handler(_request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(401, json={"error": {"message": "invalid api key"}})

    adapter = SparkAdapter(
        "bad-primary-key",
        base_url="https://sparkapi.spglobal.com",
        api_version="2024-02-01",
        app_id="sparkassist",
        fallback_token="also-bad-key",
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(handler)),
    )

    with pytest.raises(Exception):  # openai.AuthenticationError
        await adapter.complete([Message("user", "Triage this.")], model="gpt-4o-mini")


def test_spark_adapter_defaults_to_zero_cost():
    adapter = SparkAdapter(
        "unused",
        base_url="https://sparkapi.spglobal.com",
        api_version="2024-02-01",
        app_id="sparkassist",
    )
    assert adapter.estimate_cost(1_000_000, 1_000_000, "gpt-4o-mini") == Decimal(0)
