"""Shared OpenAI-chat-completions-shaped tool-calling translation, used
by both OpenAIAdapter and GenericOpenAIAdapter (most self-hosted
OpenAI-compatible gateways — vLLM, TGI, Ollama — already speak this same
function-calling wire format, so GenericOpenAIAdapter gets tool-calling
support "for free" through this same code path rather than needing its
own copy). Not shared with ClaudeAdapter's translation — the two
providers' wire shapes are irreducibly different; see
ConversationTurn's own docstring in base.py.
"""

import json
from typing import Any

from app.ai.adapters.base import ConversationTurn, ToolCall, ToolCallResponse, ToolSpec


def build_openai_tools(tools: list[ToolSpec]) -> list[dict]:
    return [
        {"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.input_schema}}
        for t in tools
    ]


def build_openai_messages(system: str, turns: list[ConversationTurn]) -> list[dict]:
    messages: list[dict] = [{"role": "system", "content": system}]
    for turn in turns:
        if turn.role == "user":
            messages.append({"role": "user", "content": turn.content or ""})
        elif turn.role == "assistant":
            message: dict[str, Any] = {"role": "assistant", "content": turn.content}
            if turn.tool_calls:
                message["tool_calls"] = [
                    {
                        "id": call.id,
                        "type": "function",
                        "function": {"name": call.name, "arguments": json.dumps(call.arguments)},
                    }
                    for call in turn.tool_calls
                ]
            messages.append(message)
        elif turn.role == "tool":
            # Unlike Claude (which requires every tool_result for one
            # assistant turn folded into a single subsequent user
            # message — see claude.py's _build_claude_messages), OpenAI
            # wants one separate role="tool" message per result, keyed
            # by tool_call_id. ConversationTurn's flat one-turn-per-
            # result shape already matches this directly, no grouping
            # needed.
            messages.append({"role": "tool", "tool_call_id": turn.tool_call_id, "content": turn.content or ""})
    return messages


def parse_openai_tool_response(message, *, usage, model: str) -> ToolCallResponse:
    tool_calls = [
        ToolCall(id=tc.id, name=tc.function.name, arguments=json.loads(tc.function.arguments or "{}"))
        for tc in (message.tool_calls or [])
    ]
    return ToolCallResponse(
        content=message.content,
        tool_calls=tool_calls,
        stop_reason="tool_use" if tool_calls else "end_turn",
        input_tokens=usage.prompt_tokens if usage else 0,
        output_tokens=usage.completion_tokens if usage else 0,
    )
