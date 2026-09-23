from decimal import Decimal

from app.ai.adapters.base import (
    AgentResponse,
    AIProviderAdapter,
    ConversationTurn,
    Message,
    ToolCallResponse,
    ToolSpec,
)


class NullAIProviderAdapter(AIProviderAdapter):
    """The default adapter (settings.ai_provider == "fake"). Always
    returns a "not vulnerable" verdict at zero cost. This is what makes a
    fresh checkout with no API keys configured safe to run: LLM-dependent
    agents (injection/xss/access-control triage+validation) simply confirm
    nothing rather than crashing or silently using a real paid API.
    """

    _NOT_VULNERABLE_JSON = (
        '{"vulnerable": false, "confidence": "low", '
        '"reasoning": "No AI provider configured (settings.ai_provider=\\"fake\\")."}'
    )

    async def complete(
        self, messages: list[Message], *, model: str, max_tokens: int = 1024
    ) -> AgentResponse:
        return AgentResponse(
            content=self._NOT_VULNERABLE_JSON, input_tokens=0, output_tokens=0, model="fake"
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
        # Same "safe fresh checkout" philosophy as complete() above: no
        # tool calls at all, so app.agents.autonomous_pentest.runner's
        # loop ends immediately on turn one instead of ever touching a
        # real sandbox — a session started with no AI provider
        # configured is a no-op, not a crash or a silent real-API call.
        return ToolCallResponse(
            content="No AI provider configured (settings.ai_provider=\"fake\") — nothing to do.",
            tool_calls=[],
            stop_reason="end_turn",
            input_tokens=0,
            output_tokens=0,
        )

    def estimate_cost(self, input_tokens: int, output_tokens: int, model: str) -> Decimal:
        return Decimal(0)
