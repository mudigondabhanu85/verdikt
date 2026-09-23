"""Tests for the tool-calling translation layer added for the AI-driven
autonomous pentest mode (app.agents.autonomous_pentest). ClaudeAdapter's
and OpenAIAdapter's own SDK clients aren't mocked anywhere in this
codebase (see test_ai_provider_resolution.py — only isinstance() checks,
never a real complete() call); consistent with that, this file tests the
pure translation functions directly (the real risk surface — a malformed
correlation between a tool_use/tool_result pair would silently corrupt a
live agentic loop) plus one full end-to-end mocked call through
GenericOpenAIAdapter, which does support transport injection.
"""

import json

import httpx2

from app.ai.adapters._openai_tools import build_openai_messages, build_openai_tools, parse_openai_tool_response
from app.ai.adapters.base import ConversationTurn, ToolCall, ToolSpec
from app.ai.adapters.claude import _build_claude_messages
from app.ai.adapters.generic_openai import GenericOpenAIAdapter


def test_claude_plain_user_turn_becomes_a_simple_user_message():
    messages = _build_claude_messages([ConversationTurn(role="user", content="find sqli")])
    assert messages == [{"role": "user", "content": "find sqli"}]


def test_claude_assistant_tool_call_turn_becomes_text_plus_tool_use_blocks():
    turn = ConversationTurn(
        role="assistant",
        content="I'll check for SQLi.",
        tool_calls=[ToolCall(id="call_1", name="shell_exec", arguments={"command": "curl -s target"})],
    )
    messages = _build_claude_messages([turn])
    assert messages == [
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "I'll check for SQLi."},
                {"type": "tool_use", "id": "call_1", "name": "shell_exec", "input": {"command": "curl -s target"}},
            ],
        }
    ]


def test_claude_consecutive_tool_results_are_folded_into_one_user_message():
    """Claude's own wire-format requirement (not this codebase's design
    choice): every tool_result for one assistant turn must arrive
    together as multiple content blocks in a single following user
    message, not as separate messages — a real, load-bearing constraint
    a naive one-turn-per-message translation would silently violate."""
    turns = [
        ConversationTurn(role="tool", tool_call_id="call_1", content="200"),
        ConversationTurn(role="tool", tool_call_id="call_2", content="404"),
    ]
    messages = _build_claude_messages(turns)
    assert len(messages) == 1
    assert messages[0]["role"] == "user"
    assert messages[0]["content"] == [
        {"type": "tool_result", "tool_use_id": "call_1", "content": "200"},
        {"type": "tool_result", "tool_use_id": "call_2", "content": "404"},
    ]


def test_claude_tool_results_flush_before_the_next_real_turn():
    turns = [
        ConversationTurn(role="tool", tool_call_id="call_1", content="200"),
        ConversationTurn(role="user", content="keep going"),
    ]
    messages = _build_claude_messages(turns)
    assert len(messages) == 2
    assert messages[0]["content"][0]["tool_use_id"] == "call_1"
    assert messages[1] == {"role": "user", "content": "keep going"}


def test_openai_tool_results_are_separate_messages_not_folded():
    """The opposite of Claude's requirement — OpenAI wants one distinct
    role="tool" message per result, keyed by tool_call_id."""
    turns = [
        ConversationTurn(role="tool", tool_call_id="call_1", content="200"),
        ConversationTurn(role="tool", tool_call_id="call_2", content="404"),
    ]
    messages = build_openai_messages("system prompt", turns)
    tool_messages = [m for m in messages if m["role"] == "tool"]
    assert len(tool_messages) == 2
    assert tool_messages[0] == {"role": "tool", "tool_call_id": "call_1", "content": "200"}
    assert tool_messages[1] == {"role": "tool", "tool_call_id": "call_2", "content": "404"}


def test_openai_system_prompt_is_the_first_message():
    messages = build_openai_messages("be a pentest agent", [ConversationTurn(role="user", content="go")])
    assert messages[0] == {"role": "system", "content": "be a pentest agent"}


def test_openai_tool_spec_translates_to_function_wrapper():
    spec = ToolSpec(name="shell_exec", description="run a command", input_schema={"type": "object"})
    built = build_openai_tools([spec])
    assert built == [
        {"type": "function", "function": {"name": "shell_exec", "description": "run a command", "parameters": {"type": "object"}}}
    ]


def test_parse_openai_tool_response_extracts_calls_and_arguments():
    class _FakeFunction:
        name = "shell_exec"
        arguments = '{"command": "nmap -p 80 target"}'

    class _FakeToolCall:
        id = "call_1"
        function = _FakeFunction()

    class _FakeMessage:
        content = "Running a port scan."
        tool_calls = [_FakeToolCall()]

    class _FakeUsage:
        prompt_tokens = 100
        completion_tokens = 20

    result = parse_openai_tool_response(_FakeMessage(), usage=_FakeUsage(), model="gpt-4o")
    assert result.content == "Running a port scan."
    assert result.stop_reason == "tool_use"
    assert result.tool_calls == [ToolCall(id="call_1", name="shell_exec", arguments={"command": "nmap -p 80 target"})]
    assert result.input_tokens == 100
    assert result.output_tokens == 20


def test_parse_openai_tool_response_with_no_tool_calls_is_end_turn():
    class _FakeMessage:
        content = "No further testing needed."
        tool_calls = None

    result = parse_openai_tool_response(_FakeMessage(), usage=None, model="gpt-4o")
    assert result.stop_reason == "end_turn"
    assert result.tool_calls == []


def _openai_tool_call_handler(request: httpx2.Request) -> httpx2.Response:
    body = json.loads(request.content.decode())
    assert body["tools"][0]["function"]["name"] == "shell_exec"
    return httpx2.Response(
        200,
        json={
            "id": "chatcmpl-tool",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Checking the login endpoint for SQLi.",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "shell_exec",
                                    "arguments": '{"command": "curl -s target/login", "timeout_seconds": 30}',
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
            "usage": {"prompt_tokens": 55, "completion_tokens": 12, "total_tokens": 67},
        },
    )


async def test_generic_openai_adapter_complete_with_tools_end_to_end():
    adapter = GenericOpenAIAdapter(
        "unused-key",
        base_url="http://localhost:11434/v1",
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(_openai_tool_call_handler)),
    )
    tool = ToolSpec(
        name="shell_exec",
        description="Run a shell command in the sandbox.",
        input_schema={
            "type": "object",
            "properties": {"command": {"type": "string"}, "timeout_seconds": {"type": "integer"}},
            "required": ["command"],
        },
    )

    result = await adapter.complete_with_tools(
        system="You are a pentest agent.",
        turns=[ConversationTurn(role="user", content="Find SQL injection.")],
        model="llama3.1:8b",
        tools=[tool],
    )

    assert result.content == "Checking the login endpoint for SQLi."
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].name == "shell_exec"
    assert result.tool_calls[0].arguments == {"command": "curl -s target/login", "timeout_seconds": 30}
    assert result.input_tokens == 55
    assert result.output_tokens == 12
