from decimal import Decimal

from openai import AsyncOpenAI

from app.ai.adapters.base import AgentResponse, AIProviderAdapter, Message

# USD per million tokens (input, output). Approximate — keep these current;
# they only drive the §10.5 budget guardrail, not billing.
_PRICING_PER_MTOK: dict[str, tuple[Decimal, Decimal]] = {
    "gpt-4o-mini": (Decimal("0.15"), Decimal("0.60")),
    "gpt-4o": (Decimal("2.50"), Decimal("10.00")),
    "gpt-4.1-mini": (Decimal("0.40"), Decimal("1.60")),
    "gpt-4.1": (Decimal("2.00"), Decimal("8.00")),
}
_DEFAULT_PRICING = (Decimal("2.50"), Decimal("10.00"))


def _pricing_for(model: str) -> tuple[Decimal, Decimal]:
    for prefix, pricing in _PRICING_PER_MTOK.items():
        if prefix in model:
            return pricing
    return _DEFAULT_PRICING


class OpenAIAdapter(AIProviderAdapter):
    def __init__(self, api_key: str):
        self._client = AsyncOpenAI(api_key=api_key)

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
        input_price, output_price = _pricing_for(model)
        return (Decimal(input_tokens) * input_price + Decimal(output_tokens) * output_price) / Decimal(
            1_000_000
        )
