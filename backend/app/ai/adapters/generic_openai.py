from decimal import Decimal
from typing import Any

from openai import AsyncOpenAI

from app.ai.adapters.base import AgentResponse, AIProviderAdapter, Message


class GenericOpenAIAdapter(AIProviderAdapter):
    """One adapter for any OpenAI-chat-completions-compatible endpoint —
    covers self-hosted/in-house LLM servers (vLLM, Ollama, LM Studio,
    text-generation-inference, ...) and any hosted proxy that speaks the
    same protocol, via a caller-supplied base_url. Not provider-specific
    pricing (unlike ClaudeAdapter/OpenAIAdapter's built-in tables) since
    there's no fixed catalog for arbitrary/custom deployments — pricing is
    supplied explicitly per instance and defaults to $0, matching the
    common case of a self-hosted model with no per-token billing.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str,
        input_price_per_mtok: Decimal = Decimal(0),
        output_price_per_mtok: Decimal = Decimal(0),
        http_client: Any = None,
    ):
        # http_client is test-only plumbing — lets tests inject an
        # httpx2.MockTransport-backed client instead of hitting a real
        # local server.
        self._client = AsyncOpenAI(api_key=api_key, base_url=base_url, http_client=http_client)
        self._input_price = input_price_per_mtok
        self._output_price = output_price_per_mtok

    async def complete(
        self, messages: list[Message], *, model: str, max_tokens: int = 1024
    ) -> AgentResponse:
        response = await self._client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": m.role, "content": m.content} for m in messages],
        )
        content = response.choices[0].message.content or ""
        usage = response.usage
        return AgentResponse(
            content=content,
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
            model=model,
        )

    def estimate_cost(self, input_tokens: int, output_tokens: int, model: str) -> Decimal:
        return (
            Decimal(input_tokens) * self._input_price + Decimal(output_tokens) * self._output_price
        ) / Decimal(1_000_000)
