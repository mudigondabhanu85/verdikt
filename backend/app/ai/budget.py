import asyncio
from decimal import Decimal

from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.adapters.base import AgentResponse, AIProviderAdapter, Message
from app.config import get_settings
from app.models.scan import ScanRun


class BudgetExceededError(Exception):
    """Raised when a ScanRun's estimated LLM spend would exceed
    settings.max_llm_cost_usd_per_scan. Callers should catch this and mark
    the current AgentJob as skipped rather than letting it propagate as a
    generic failure — running out of budget is an expected, visible stop
    condition (§10.5), not a bug.
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

            response = await self._provider.complete(messages, model=model, max_tokens=max_tokens)
            cost = self._provider.estimate_cost(response.input_tokens, response.output_tokens, model)
            self._scan_run.llm_cost_usd = self.spent + cost
            await self._session.commit()
            return response
