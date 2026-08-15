from collections.abc import Callable
from decimal import Decimal

from app.ai.adapters.base import AgentResponse, AIProviderAdapter, Message


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

    @classmethod
    def from_responses(cls, *responses: str) -> "ScriptedAIProviderAdapter":
        return cls(responses=list(responses))

    async def complete(
        self, messages: list[Message], *, model: str, max_tokens: int = 1024
    ) -> AgentResponse:
        self.calls.append(messages)
        if self._respond_fn is not None:
            content = self._respond_fn(messages)
        else:
            assert self._responses is not None
            content = self._responses.pop(0) if len(self._responses) > 1 else self._responses[0]
        return AgentResponse(content=content, input_tokens=10, output_tokens=10, model=model)

    def estimate_cost(self, input_tokens: int, output_tokens: int, model: str) -> Decimal:
        return self._cost_per_call
