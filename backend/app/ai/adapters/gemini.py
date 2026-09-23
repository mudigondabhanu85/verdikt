import uuid
from decimal import Decimal

import httpx

from app.ai.adapters.base import (
    AgentResponse,
    AIProviderAdapter,
    ConversationTurn,
    Message,
    ToolCall,
    ToolCallResponse,
    ToolSpec,
)

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


def _build_gemini_contents(turns: list[ConversationTurn]) -> list[dict]:
    """Gemini's REST function-calling shape is a third, distinct wire
    format from both Claude's and OpenAI's (see ConversationTurn's own
    docstring): the model's function-call turn uses role="model" with
    `functionCall` parts; the result goes back as role="user" with
    `functionResponse` parts — there is no dedicated "tool"/"function"
    role in the v1beta REST API's Content.role enum (verified against
    Google's own generateContent reference and function-calling guide;
    older client libraries used a "function" role that the raw REST API
    itself does not accept). Like Claude's own _build_claude_messages,
    multiple function results answering one model turn's multiple
    function calls fold into ONE user Content with multiple parts, not
    separate Content entries.

    Gemini's FunctionResponse is matched to its FunctionCall by name
    (and, when present, an optional call id) — but ConversationTurn's
    own tool-role turns only carry ToolCall.id, not the tool's name (see
    that dataclass's own comment), so the name is recovered here by
    scanning every assistant turn's tool_calls up front. The id itself
    is never sent to Gemini (see complete_with_tools's own comment on
    why) — it's purely this adapter's internal correlation key.
    """
    tool_name_by_call_id: dict[str, str] = {}
    for turn in turns:
        if turn.role == "assistant":
            for call in turn.tool_calls or []:
                tool_name_by_call_id[call.id] = call.name

    contents: list[dict] = []
    pending_function_responses: list[dict] = []

    def _flush() -> None:
        if pending_function_responses:
            contents.append({"role": "user", "parts": pending_function_responses.copy()})
            pending_function_responses.clear()

    for turn in turns:
        if turn.role == "tool":
            tool_name = tool_name_by_call_id.get(turn.tool_call_id or "", "unknown_tool")
            pending_function_responses.append(
                {"functionResponse": {"name": tool_name, "response": {"result": turn.content or ""}}}
            )
            continue
        _flush()
        if turn.role == "user":
            contents.append({"role": "user", "parts": [{"text": turn.content or ""}]})
        elif turn.role == "assistant":
            parts: list[dict] = []
            if turn.content:
                parts.append({"text": turn.content})
            for call in turn.tool_calls or []:
                parts.append({"functionCall": {"name": call.name, "args": call.arguments}})
            contents.append({"role": "model", "parts": parts})
    _flush()
    return contents


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

    async def complete_with_tools(
        self,
        *,
        system: str,
        turns: list[ConversationTurn],
        model: str,
        tools: list[ToolSpec],
        max_tokens: int = 2048,
    ) -> ToolCallResponse:
        contents = _build_gemini_contents(turns)
        # `parameters` takes an OpenAPI 3.0 Schema Object, not raw JSON
        # Schema — the two diverge on some keywords, but every ToolSpec
        # this codebase defines today (shell_exec, read_file — see
        # app.agents.autonomous_pentest.runner) only uses the common
        # subset (type/properties/required/description), which is valid
        # under both, so no translation layer exists here yet. Revisit
        # if a future tool's schema needs something OpenAPI-specific.
        payload: dict = {
            "contents": contents,
            "tools": [
                {
                    "functionDeclarations": [
                        {"name": t.name, "description": t.description, "parameters": t.input_schema}
                        for t in tools
                    ]
                }
            ],
            # Same determinism rationale as complete() above.
            "generationConfig": {"temperature": 0, "maxOutputTokens": max_tokens},
        }
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}

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
        parts = candidate.get("content", {}).get("parts", [])
        content_text = "".join(part["text"] for part in parts if "text" in part) or None
        tool_calls = [
            # A globally-unique id per call, not a per-response index —
            # _build_gemini_contents' tool_name_by_call_id map is built
            # by scanning the ENTIRE turn history on every call, so a
            # colliding id reused across two different assistant turns
            # (e.g. every response's first call named "call_0") would
            # let the later turn's mapping silently clobber the earlier
            # one before the earlier turn's own tool-result is ever
            # looked up. Gemini itself never sees this id (see
            # _build_gemini_contents' own docstring) — it exists purely
            # for this adapter's own bookkeeping, so nothing about
            # Gemini's wire format constrains its shape.
            ToolCall(id=f"call_{uuid.uuid4().hex[:12]}", name=part["functionCall"]["name"], arguments=part["functionCall"].get("args", {}))
            for part in parts
            if "functionCall" in part
        ]
        usage = data.get("usageMetadata", {})
        return ToolCallResponse(
            content=content_text,
            tool_calls=tool_calls,
            stop_reason=candidate.get("finishReason", "STOP"),
            input_tokens=usage.get("promptTokenCount", 0),
            output_tokens=usage.get("candidatesTokenCount", 0),
        )

    def estimate_cost(self, input_tokens: int, output_tokens: int, model: str) -> Decimal:
        input_price, output_price = _pricing_for(model)
        return (Decimal(input_tokens) * input_price + Decimal(output_tokens) * output_price) / Decimal(
            1_000_000
        )
