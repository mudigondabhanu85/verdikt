from decimal import Decimal

from anthropic import AsyncAnthropic

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


def _build_claude_messages(turns: list[ConversationTurn]) -> list[dict]:
    """Claude's own wire-format constraint (not this codebase's choice):
    every tool_result for a given assistant tool_use turn must arrive
    together, as multiple content blocks inside ONE subsequent user
    message — not as separate messages the way OpenAI's role="tool"
    messages work. ConversationTurn's own list is flat (one role="tool"
    turn per result) precisely so it stays adapter-agnostic (see that
    dataclass's docstring); this is where that flat list gets folded
    back into consecutive-run groups to satisfy Claude's shape.
    """
    messages: list[dict] = []
    pending_tool_results: list[dict] = []

    def _flush_tool_results() -> None:
        if pending_tool_results:
            messages.append({"role": "user", "content": pending_tool_results.copy()})
            pending_tool_results.clear()

    for turn in turns:
        if turn.role == "tool":
            pending_tool_results.append(
                {"type": "tool_result", "tool_use_id": turn.tool_call_id, "content": turn.content or ""}
            )
            continue
        _flush_tool_results()
        if turn.role == "user":
            messages.append({"role": "user", "content": turn.content or ""})
        elif turn.role == "assistant":
            blocks: list[dict] = []
            if turn.content:
                blocks.append({"type": "text", "text": turn.content})
            for call in turn.tool_calls or []:
                blocks.append({"type": "tool_use", "id": call.id, "name": call.name, "input": call.arguments})
            messages.append({"role": "assistant", "content": blocks})
    _flush_tool_results()
    return messages


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

    async def complete_with_tools(
        self,
        *,
        system: str,
        turns: list[ConversationTurn],
        model: str,
        tools: list[ToolSpec],
        max_tokens: int = 2048,
    ) -> ToolCallResponse:
        messages = _build_claude_messages(turns)
        claude_tools = [{"name": t.name, "description": t.description, "input_schema": t.input_schema} for t in tools]

        response = await self._client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
            tools=claude_tools,
            # Same determinism rationale as complete() above — a
            # tool-calling agentic loop is even more sensitive to
            # non-determinism than a one-shot verdict, since a flaky
            # decision here compounds turn over turn.
            temperature=0,
        )

        content_text = "".join(block.text for block in response.content if block.type == "text") or None
        tool_calls = [
            ToolCall(id=block.id, name=block.name, arguments=block.input)
            for block in response.content
            if block.type == "tool_use"
        ]
        return ToolCallResponse(
            content=content_text,
            tool_calls=tool_calls,
            stop_reason=response.stop_reason,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
        )

    def estimate_cost(self, input_tokens: int, output_tokens: int, model: str) -> Decimal:
        input_price, output_price = _pricing_for(model)
        return (Decimal(input_tokens) * input_price + Decimal(output_tokens) * output_price) / Decimal(
            1_000_000
        )
