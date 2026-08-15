from abc import ABC, abstractmethod
from dataclasses import dataclass
from decimal import Decimal
from typing import Literal

Role = Literal["system", "user", "assistant"]


@dataclass
class Message:
    role: Role
    content: str


@dataclass
class AgentResponse:
    content: str
    input_tokens: int
    output_tokens: int
    model: str


class AIProviderAdapter(ABC):
    """One adapter per LLM provider. The orchestrator/agents select a
    provider+model per call through get_ai_provider() (app.ai.provider) —
    application code never talks to a provider SDK directly.
    """

    @abstractmethod
    async def complete(
        self, messages: list[Message], *, model: str, max_tokens: int = 1024
    ) -> AgentResponse: ...

    @abstractmethod
    def estimate_cost(self, input_tokens: int, output_tokens: int, model: str) -> Decimal: ...
