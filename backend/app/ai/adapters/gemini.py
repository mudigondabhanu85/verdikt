from decimal import Decimal

import httpx

from app.ai.adapters.base import AgentResponse, AIProviderAdapter, Message

# USD per million tokens (input, output). Approximate — keep these current;
# they only drive the §10.5 budget guardrail, not billing.
_PRICING_PER_MTOK: dict[str, tuple[Decimal, Decimal]] = {
    "gemini-2.0-flash": (Decimal("0.10"), Decimal("0.40")),
    "gemini-1.5-flash": (Decimal("0.075"), Decimal("0.30")),
    "gemini-1.5-pro": (Decimal("1.25"), Decimal("5.00")),
}
_DEFAULT_PRICING = (Decimal("1.25"), Decimal("5.00"))


def _pricing_for(model: str) -> tuple[Decimal, Decimal]:
    for prefix, pricing in _PRICING_PER_MTOK.items():
        if prefix in model:
            return pricing
    return _DEFAULT_PRICING


class GeminiAdapter(AIProviderAdapter):
    """Google Gemini via the raw REST API (generativelanguage.googleapis.com)
    rather than the google-generativeai/google-genai SDK — avoids adding a
    new heavy dependency for what's a single JSON POST. Auth is the
    provider's own `?key=` query-param convention (not a header), so
    AIProviderConfig.auth_type is not consulted here — that field only
    matters for endpoints (custom/self-hosted) where the header shape is
    actually ambiguous.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "https://generativelanguage.googleapis.com",
        http_client: httpx.AsyncClient | None = None,
    ):
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._http_client = http_client

    async def complete(
        self, messages: list[Message], *, model: str, max_tokens: int = 1024
    ) -> AgentResponse:
        system_parts = [m.content for m in messages if m.role == "system"]
        contents = [
            {
                "role": "model" if m.role == "assistant" else "user",
                "parts": [{"text": m.content}],
            }
            for m in messages
            if m.role != "system"
        ]
        payload: dict = {
            "contents": contents,
            # See ClaudeAdapter.complete's identical rationale: every
            # prompt here is a structured classification, not open-ended
            # generation, so deterministic output is correct.
            "generationConfig": {"temperature": 0, "maxOutputTokens": max_tokens},
        }
        if system_parts:
            payload["systemInstruction"] = {"parts": [{"text": "\n".join(system_parts)}]}

        url = f"{self._base_url}/v1beta/models/{model}:generateContent"
        client = self._http_client or httpx.AsyncClient()
        try:
            response = await client.post(url, params={"key": self._api_key}, json=payload, timeout=60.0)
            response.raise_for_status()
        finally:
            if self._http_client is None:
                await client.aclose()

        data = response.json()
        candidate = data["candidates"][0]
        content = "".join(part.get("text", "") for part in candidate["content"]["parts"])
        usage = data.get("usageMetadata", {})
        return AgentResponse(
            content=content,
            input_tokens=usage.get("promptTokenCount", 0),
            output_tokens=usage.get("candidatesTokenCount", 0),
            model=model,
        )

    def estimate_cost(self, input_tokens: int, output_tokens: int, model: str) -> Decimal:
        input_price, output_price = _pricing_for(model)
        return (Decimal(input_tokens) * input_price + Decimal(output_tokens) * output_price) / Decimal(
            1_000_000
        )
