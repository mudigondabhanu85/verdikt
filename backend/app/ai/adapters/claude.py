from decimal import Decimal

from anthropic import AsyncAnthropic

from app.ai.adapters.base import AgentResponse, AIProviderAdapter, Message

# USD per million tokens (input, output). Approximate — keep these current;
# they only drive the §10.5 budget guardrail, not billing.
_PRICING_PER_MTOK: dict[str, tuple[Decimal, Decimal]] = {
    "claude-haiku": (Decimal("1.00"), Decimal("5.00")),
    "claude-sonnet": (Decimal("3.00"), Decimal("15.00")),
    "claude-opus": (Decimal("15.00"), Decimal("75.00")),
}
_DEFAULT_PRICING = (Decimal("3.00"), Decimal("15.00"))


def _pricing_for(model: str) -> tuple[Decimal, Decimal]:
    for prefix, pricing in _PRICING_PER_MTOK.items():
        if prefix in model:
            return pricing
    return _DEFAULT_PRICING


class ClaudeAdapter(AIProviderAdapter):
    def __init__(self, api_key: str):
        self._client = AsyncAnthropic(api_key=api_key)

    async def complete(
        self, messages: list[Message], *, model: str, max_tokens: int = 1024
    ) -> AgentResponse:
        system = "\n".join(m.content for m in messages if m.role == "system") or None
        turns = [{"role": m.role, "content": m.content} for m in messages if m.role != "system"]

        response = await self._client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=turns,
            # Every prompt this adapter serves is a structured
            # vulnerable/not-vulnerable classification, not open-ended
            # generation — the API's default temperature (1.0) is fully
            # stochastic and was observed live to flip the verdict for
            # the exact same evidence across two real calls (a genuine
            # DVWA reflected-XSS candidate). Deterministic (temperature=0)
            # output is what "confirmed" should mean for a security
            # scanner's triage step.
            temperature=0,
        )
        content = "".join(block.text for block in response.content if block.type == "text")
        return AgentResponse(
            content=content,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            model=model,
        )

    def estimate_cost(self, input_tokens: int, output_tokens: int, model: str) -> Decimal:
        input_price, output_price = _pricing_for(model)
        return (Decimal(input_tokens) * input_price + Decimal(output_tokens) * output_price) / Decimal(
            1_000_000
        )
