from collections.abc import Callable
from decimal import Decimal

from app.ai.adapters.base import (
    AgentResponse,
    AIProviderAdapter,
    ConversationTurn,
    Message,
    ToolCall,
    ToolCallResponse,
    ToolSpec,
)


class ScriptedAIProviderAdapter(AIProviderAdapter):
    """Test double for AIProviderAdapter. Drives agent triage/validation
    logic deterministically, without network or API cost, via either a
    fixed queue of response strings (cycling the last one once exhausted)
    or a callable given the full message list — useful when a test needs
    different verdicts for triage vs. adversarial-validation calls.
    """

    def __init__(
        self,
        responses: list[str] | None = None,
        respond_fn: Callable[[list[Message]], str] | None = None,
        cost_per_call: Decimal = Decimal("0.001"),
    ):
        if not responses and not respond_fn:
            raise ValueError("Provide either responses or respond_fn")
        self._responses = list(responses) if responses else None
        self._respond_fn = respond_fn
        self._cost_per_call = cost_per_call
        self.calls: list[list[Message]] = []
        # Which model each call in `calls` (same index) actually requested
        # — lets a test verify per-task model tiering (app.ai.model_tiers)
        # without needing to inspect anything beyond this fake.
        self.models: list[str] = []

    @classmethod
    def from_responses(cls, *responses: str) -> "ScriptedAIProviderAdapter":
        return cls(responses=list(responses))

    async def complete(
        self, messages: list[Message], *, model: str, max_tokens: int = 1024
    ) -> AgentResponse:
        self.calls.append(messages)
        self.models.append(model)
        if self._respond_fn is not None:
            content = self._respond_fn(messages)
        else:
            assert self._responses is not None
            content = self._responses.pop(0) if len(self._responses) > 1 else self._responses[0]
        return AgentResponse(content=content, input_tokens=10, output_tokens=10, model=model)

    async def complete_with_tools(
        self,
        *,
        system: str,
        turns: list[ConversationTurn],
        model: str,
        tools: list[ToolSpec],
        max_tokens: int = 2048,
    ) -> ToolCallResponse:
        # This fake predates tool-calling and every existing test using
        # it only ever calls complete() — this exists purely so the
        # class stays instantiable now that AIProviderAdapter makes
        # complete_with_tools abstract (Python requires every abstract
        # method to have *some* concrete override, even a stub, or the
        # class can't be constructed at all). A test that actually needs
        # a tool-calling fake should use ScriptedToolCallingAdapter
        # below instead.
        raise NotImplementedError(
            "ScriptedAIProviderAdapter has no tool-calling behavior — use ScriptedToolCallingAdapter"
        )

    def estimate_cost(self, input_tokens: int, output_tokens: int, model: str) -> Decimal:
        return self._cost_per_call


class ScriptedToolCallingAdapter(AIProviderAdapter):
    """Test double for the multi-turn tool-calling path
    (app.agents.autonomous_pentest.runner) — drives a scripted sequence
    of ToolCallResponse turns deterministically, without a real
    provider. `turns` is a plain list of ToolCallResponse consumed one
    per complete_with_tools() call, in order; the last one repeats once
    exhausted (same "cycle the last response" convenience as
    ScriptedAIProviderAdapter above).
    """

    def __init__(self, turns: list[ToolCallResponse], cost_per_call: Decimal = Decimal("0.001")):
        if not turns:
            raise ValueError("Provide at least one ToolCallResponse turn")
        self._turns = list(turns)
        self._cost_per_call = cost_per_call
        self.calls: list[list[ConversationTurn]] = []

    async def complete(
        self, messages: list[Message], *, model: str, max_tokens: int = 1024
    ) -> AgentResponse:
        raise NotImplementedError("ScriptedToolCallingAdapter only implements complete_with_tools")

    async def complete_with_tools(
        self,
        *,
        system: str,
        turns: list[ConversationTurn],
        model: str,
        tools: list[ToolSpec],
        max_tokens: int = 2048,
    ) -> ToolCallResponse:
        self.calls.append(turns)
        return self._turns.pop(0) if len(self._turns) > 1 else self._turns[0]

    def estimate_cost(self, input_tokens: int, output_tokens: int, model: str) -> Decimal:
        return self._cost_per_call


def tool_call_turn(*, content: str | None = None, calls: list[tuple[str, dict]]) -> ToolCallResponse:
    """Convenience builder for a ToolCallResponse that requests one or
    more tool calls — `calls` is a list of (tool_name, arguments) pairs;
    ids are auto-assigned so tests don't need to invent unique call ids
    by hand."""
    return ToolCallResponse(
        content=content,
        tool_calls=[ToolCall(id=f"call_{i}", name=name, arguments=args) for i, (name, args) in enumerate(calls)],
        stop_reason="tool_use",
        input_tokens=10,
        output_tokens=10,
    )


def end_turn(content: str) -> ToolCallResponse:
    """Convenience builder for a ToolCallResponse the model uses to stop
    the loop (no tool calls) — either a plain summary or a Finding
    proposal, depending on what `content` holds."""
    return ToolCallResponse(content=content, tool_calls=[], stop_reason="end_turn", input_tokens=10, output_tokens=10)
