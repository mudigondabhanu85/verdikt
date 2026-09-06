from decimal import Decimal
from typing import Any

from app.ai.adapters.generic_openai import GenericOpenAIAdapter

# USD per million tokens (input, output). Approximate — keep these current;
# they only drive the §10.5 budget guardrail, not billing.
_PRICING_PER_MTOK: dict[str, tuple[Decimal, Decimal]] = {
    "grok-2": (Decimal("2.00"), Decimal("10.00")),
    "grok-beta": (Decimal("5.00"), Decimal("15.00")),
}
_DEFAULT_PRICING = (Decimal("5.00"), Decimal("15.00"))


def _pricing_for(model: str) -> tuple[Decimal, Decimal]:
    for prefix, pricing in _PRICING_PER_MTOK.items():
        if prefix in model:
            return pricing
    return _DEFAULT_PRICING


class GrokAdapter(GenericOpenAIAdapter):
    """xAI's Grok API is OpenAI-chat-completions-compatible
    (https://api.x.ai/v1), so this reuses GenericOpenAIAdapter's request
    plumbing wholesale rather than reimplementing it — but gets its own
    named class + real xAI pricing table, so the analyst configures it as
    "Grok" with correct cost tracking instead of an anonymous "custom"
    endpoint with $0 pricing.
    """

    def __init__(self, api_key: str, *, http_client: Any = None):
        super().__init__(api_key, base_url="https://api.x.ai/v1", http_client=http_client)

    def estimate_cost(self, input_tokens: int, output_tokens: int, model: str) -> Decimal:
        input_price, output_price = _pricing_for(model)
        return (Decimal(input_tokens) * input_price + Decimal(output_tokens) * output_price) / Decimal(
            1_000_000
        )
