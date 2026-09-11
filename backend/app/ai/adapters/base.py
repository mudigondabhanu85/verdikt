from abc import ABC, abstractmethod
from dataclasses import dataclass
from decimal import Decimal
from typing import Literal

Role = Literal["system", "user", "assistant"]

# ~4 chars/token is the standard rough estimate for English text with
# GPT-style tokenizers — used by any adapter whose provider's response
# doesn't include real `usage` data. Never exact, but far more honest
# for budget/usage visibility than a flat 0, which reads as "the AI
# didn't run" for a call that demonstrably did.
_CHARS_PER_TOKEN_ESTIMATE = 4


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // _CHARS_PER_TOKEN_ESTIMATE) if text else 0


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
