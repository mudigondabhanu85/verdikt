from decimal import Decimal
from typing import Any

from openai import AsyncOpenAI

from app.ai.adapters._openai_tools import build_openai_messages, build_openai_tools, parse_openai_tool_response
from app.ai.adapters.base import (
    AgentResponse,
    AIProviderAdapter,
    ConversationTurn,
    Message,
    ToolCallResponse,
    ToolSpec,
    estimate_tokens,
)


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
        if usage:
            input_tokens, output_tokens = usage.prompt_tokens, usage.completion_tokens
        else:
            # Some self-hosted/in-house OpenAI-compatible gateways omit
            # `usage` from otherwise-successful responses — falling back
            # to a flat 0 here makes real, successful LLM work look like
            # "the AI didn't run" in every cost/token report. Estimate
            # instead, same rationale as every other adapter's fallback.
            input_tokens = estimate_tokens("".join(m.content for m in messages))
            output_tokens = estimate_tokens(content)
        return AgentResponse(
            content=content,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=model,
        )

    async def complete_with_tools(
        self,
        *,
        system: str,
        turns: list[ConversationTurn],
        model: str,
        tools: list[ToolSpec],
        max_tokens: int = 2048,
    ) -> ToolCallResponse:
        response = await self._client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            messages=build_openai_messages(system, turns),
            tools=build_openai_tools(tools),
            temperature=0,
        )
        choice = response.choices[0]
        result = parse_openai_tool_response(choice.message, usage=response.usage, model=model)
        if response.usage is None:
            # See complete()'s identical fallback above — some self-
            # hosted gateways omit `usage` even on a successful
            # tool-calling response.
            prompt_text = system + "".join(t.content or "" for t in turns)
            result.input_tokens = estimate_tokens(prompt_text)
            result.output_tokens = estimate_tokens(result.content or "")
        return result

    def estimate_cost(self, input_tokens: int, output_tokens: int, model: str) -> Decimal:
        return (
            Decimal(input_tokens) * self._input_price + Decimal(output_tokens) * self._output_price
        ) / Decimal(1_000_000)
