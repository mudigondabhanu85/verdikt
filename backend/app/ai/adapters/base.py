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


@dataclass
class ToolSpec:
    """One tool the model may call — translated by each adapter into its
    own provider's wire format (Claude's `tools` param shape differs from
    OpenAI's `{"type": "function", "function": {...}}` wrapper, but both
    reduce to the same three fields)."""

    name: str
    description: str
    input_schema: dict  # JSON schema for the tool's arguments object


@dataclass
class ToolCall:
    id: str  # the provider's own call id — echoed back in the matching ConversationTurn(role="tool") so the provider can correlate a result to the call that produced it
    name: str
    arguments: dict


@dataclass
class ConversationTurn:
    """A single, provider-agnostic turn in a multi-turn tool-use
    conversation (app.agents.autonomous_pentest.runner's loop, Phase 2).
    Deliberately NOT reusing the plain Message dataclass above — that
    type is shared by every existing single-turn triage/validation call
    site (~50+), and Claude's and OpenAI's tool-calling wire formats are
    irreducibly different (Claude nests tool_use/tool_result as content
    *blocks* inside a handful of user/assistant messages; OpenAI uses
    separate role="tool" messages per result) — asking every adapter to
    translate a single generic turn list, rather than forcing one
    provider's wire shape onto the other, keeps that translation inside
    each adapter instead of leaking a provider-specific shape into the
    runner that has to stay adapter-agnostic.
    """

    role: Literal["user", "assistant", "tool"]
    content: str | None = None
    tool_calls: list[ToolCall] | None = None  # only meaningful on role="assistant"
    tool_call_id: str | None = None  # only meaningful on role="tool" — correlates to a ToolCall.id


@dataclass
class ToolCallResponse:
    content: str | None
    tool_calls: list[ToolCall]
    stop_reason: str
    input_tokens: int
    output_tokens: int


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
    async def complete_with_tools(
        self,
        *,
        system: str,
        turns: list[ConversationTurn],
        model: str,
        tools: list[ToolSpec],
        max_tokens: int = 2048,
    ) -> ToolCallResponse: ...

    @abstractmethod
    def estimate_cost(self, input_tokens: int, output_tokens: int, model: str) -> Decimal: ...
