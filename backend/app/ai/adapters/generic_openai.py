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
        auth_type: str = "bearer_token",
        input_price_per_mtok: Decimal = Decimal(0),
        output_price_per_mtok: Decimal = Decimal(0),
        http_client: Any = None,
    ):
        # http_client is test-only plumbing — lets tests inject an
        # httpx2.MockTransport-backed client instead of hitting a real
        # local server.
        #
        # auth_type: most self-hosted/in-house OpenAI-compatible servers
        # (vLLM, Ollama, LM Studio, TGI) expect a standard
        # "Authorization: Bearer <key>" header, which is what the SDK's
        # own api_key= constructor arg already sends — the default. Some
        # proxies/gateways instead expect the raw key in some other
        # header (an "api_key"-style convention); those are covered by
        # overriding default_headers directly rather than the SDK's
        # bearer-shaped api_key= path, and dropping api_key entirely so
        # AsyncOpenAI doesn't also add its own Authorization header.
        if auth_type == "api_key":
            self._client = AsyncOpenAI(
                api_key="unused",
                base_url=base_url,
                http_client=http_client,
                default_headers={"api-key": api_key},
            )
        else:
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
            # See ClaudeAdapter.complete's identical rationale: every
            # prompt here is a structured classification, not open-ended
            # generation, so deterministic output is correct.
            temperature=0,
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
