import asyncio
from decimal import Decimal

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.adapters.base import (
    AgentResponse,
    AIProviderAdapter,
    ConversationTurn,
    Message,
    ToolCallResponse,
    ToolSpec,
)
from app.config import get_settings
from app.models.scan import ScanRun

_TRANSIENT_HTTPX_ERRORS = (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError)
_TRANSIENT_SDK_EXCEPTION_NAMES = frozenset({"APIConnectionError", "APITimeoutError"})


def _is_transient_provider_error(exc: Exception) -> bool:
    """Genuinely transient failures (network blips, timeouts, provider-side
    5xx, rate limiting) should degrade a scan gracefully via
    ProviderUnavailableError. Permanent failures (a bad API key, a
    malformed request, an adapter bug) must propagate as themselves so
    they're visible and actionable — silently absorbing them as "the
    provider is down" hides exactly the errors an analyst most needs to see.

    Duck-typed against the anthropic/openai SDKs' shared exception shape
    (both stainless-generated, same class names/attributes) rather than
    importing either SDK here — every adapter's own errors are handled
    identically regardless of which one fired, so budget.py doesn't need
    a hard dependency on any specific provider SDK to classify them.
    """
    # Builtin socket-level errors (ConnectionError and its subclasses
    # ConnectionRefusedError/ConnectionResetError/BrokenPipeError,
    # builtin TimeoutError) — genuine OS/network-level transience, not
    # an application error, regardless of which adapter/SDK is in play.
    if isinstance(exc, (ConnectionError, TimeoutError)):
        return True
    if isinstance(exc, _TRANSIENT_HTTPX_ERRORS):
        return True
    # APIStatusError subclasses (anthropic/openai SDKs) carry a real
    # status_code directly; httpx.HTTPStatusError (raised by
    # GeminiAdapter's response.raise_for_status()) carries it one level
    # down on .response instead. Either way: 429 (rate limited) and 5xx
    # (provider-side failure) are retryable/transient; every other 4xx
    # (bad key, bad request, no such model/deployment) is a permanent
    # misconfiguration, not an outage.
    status_code = getattr(exc, "status_code", None)
    if status_code is None and isinstance(exc, httpx.HTTPStatusError):
        status_code = exc.response.status_code
    if isinstance(status_code, int):
        return status_code == 429 or status_code >= 500
    # APIConnectionError/APITimeoutError carry no status_code at all (no
    # HTTP response was ever received) — always transient.
    return type(exc).__name__ in _TRANSIENT_SDK_EXCEPTION_NAMES


class BudgetExceededError(Exception):
    """Raised when a ScanRun's estimated LLM spend would exceed
    settings.max_llm_cost_usd_per_scan. Callers should catch this and mark
    the current AgentJob as skipped rather than letting it propagate as a
    generic failure — running out of budget is an expected, visible stop
    condition (§10.5), not a bug.
    """


class ProviderUnavailableError(Exception):
    """Raised when the LLM provider call itself fails (network blip,
    DNS hiccup, provider-side 5xx, timeout — anything transient, not a
    programming bug) — real incident: a scan-crashing "Connection
    error." reaching a custom/self-hosted provider from inside
    request_smuggling's AI triage, because guarded_complete previously let ANY exception from the
    provider call propagate raw, and none of the ~9 call sites across
    app/agents/ catch anything but BudgetExceededError. A transient
    provider outage should degrade exactly the same way running out of
    budget does — skip the rest of this agent's LLM-dependent work,
    keep whatever it already found, don't take the whole scan down —
    so every existing `except BudgetExceededError:` handler should
    catch this too.
    """


class BudgetGuard:
    """Tracks and enforces the §10.5 per-scan-run LLM cost cap. One
    instance per ScanRun, shared across every agent node that makes LLM
    calls during that run — including several running truly concurrently
    under Phase 2's LangGraph orchestrator, so both the shared AsyncSession
    write and the check-then-increment spend accounting need to be atomic.
    `lock` should be the same asyncio.Lock passed to the scan's
    ScopedHttpClient (see runner.py) so every write to the shared session
    serializes through one lock, not several independent ones. This does
    mean concurrent agents' LLM calls end up serialized too — an accepted
    tradeoff for correct budget accounting over raw throughput.
    """

    def __init__(
        self,
        scan_run: ScanRun,
        session: AsyncSession,
        provider: AIProviderAdapter,
        lock: asyncio.Lock | None = None,
    ):
        self._scan_run = scan_run
        self._session = session
        self._provider = provider
        self._cap = get_settings().max_llm_cost_usd_per_scan
        self._lock = lock or asyncio.Lock()

    @property
    def spent(self) -> Decimal:
        return self._scan_run.llm_cost_usd or Decimal(0)

    @property
    def provider(self) -> AIProviderAdapter:
        return self._provider

    async def guarded_complete(
        self, messages: list[Message], *, model: str, max_tokens: int = 1024
    ) -> AgentResponse:
        async with self._lock:
            if self.spent >= self._cap:
                raise BudgetExceededError(
                    f"LLM budget exhausted for scan run {self._scan_run.id}: "
                    f"${self.spent} spent of ${self._cap} cap"
                )

            try:
                response = await self._provider.complete(messages, model=model, max_tokens=max_tokens)
            except BudgetExceededError:
                raise
            except Exception as exc:
                if not _is_transient_provider_error(exc):
                    raise
                raise ProviderUnavailableError(str(exc)) from exc
            cost = self._provider.estimate_cost(response.input_tokens, response.output_tokens, model)
            self._scan_run.llm_cost_usd = self.spent + cost
            self._scan_run.llm_input_tokens = (self._scan_run.llm_input_tokens or 0) + response.input_tokens
            self._scan_run.llm_output_tokens = (self._scan_run.llm_output_tokens or 0) + response.output_tokens
            await self._session.commit()
            return response

    async def guarded_complete_with_tools(
        self,
        *,
        system: str,
        turns: list[ConversationTurn],
        model: str,
        tools: list[ToolSpec],
        max_tokens: int = 2048,
    ) -> ToolCallResponse:
        """Tool-calling counterpart to guarded_complete — same cost-cap
        check, same transient-vs-permanent error classification, same
        atomic-under-lock spend accounting. Used by
        app.agents.autonomous_pentest.runner's multi-turn loop instead of
        guarded_complete, which only ever does a single-shot text
        completion."""
        async with self._lock:
            if self.spent >= self._cap:
                raise BudgetExceededError(
                    f"LLM budget exhausted for scan run {self._scan_run.id}: "
                    f"${self.spent} spent of ${self._cap} cap"
                )

            try:
                response = await self._provider.complete_with_tools(
                    system=system, turns=turns, model=model, tools=tools, max_tokens=max_tokens
                )
            except BudgetExceededError:
                raise
            except Exception as exc:
                if not _is_transient_provider_error(exc):
                    raise
                raise ProviderUnavailableError(str(exc)) from exc
            cost = self._provider.estimate_cost(response.input_tokens, response.output_tokens, model)
            self._scan_run.llm_cost_usd = self.spent + cost
            self._scan_run.llm_input_tokens = (self._scan_run.llm_input_tokens or 0) + response.input_tokens
            self._scan_run.llm_output_tokens = (self._scan_run.llm_output_tokens or 0) + response.output_tokens
            await self._session.commit()
            return response


def budget_stop_error(agent) -> str | None:
    """agent.budget_exceeded covers two genuinely different stop
    conditions — a real spend-cap hit vs. a transient LLM-provider
    failure (network/timeout/5xx, see ProviderUnavailableError above).
    Reporting both as a flat "budget exceeded" is actively misleading: a
    real incident showed this exact label on a scan using a custom/
    self-hosted provider where estimate_cost() always returns $0, making
    a genuine budget-cap hit structurally impossible — the actual cause
    was a provider connection error, not spend. Shared by every graph
    node (app.agents.graph) and the post-graph chain-analysis step
    (app.agents.runner._run_chain_analysis) so the two can't drift back
    out of sync with each other.
    """
    if not agent.budget_exceeded:
        return None
    if getattr(agent, "budget_stop_reason", None) == "provider_unavailable":
        return "LLM provider unavailable (network/connection error) — not a budget issue"
    return "budget exceeded"
