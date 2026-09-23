import uuid
from decimal import Decimal

import pytest

from app.ai.budget import BudgetExceededError, BudgetGuard
from app.config import get_settings
from app.models.scan import ScanRun
from tests.conftest import session_scope
from tests.fakes import ScriptedAIProviderAdapter


async def test_budget_guard_tracks_spend_and_stops_at_cap(db_adapter, monkeypatch):
    monkeypatch.setattr(get_settings(), "max_llm_cost_usd_per_scan", Decimal("0.002"))

    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        provider = ScriptedAIProviderAdapter.from_responses("ok")
        guard = BudgetGuard(scan_run, session, provider)

        from app.ai.adapters.base import Message

        await guard.guarded_complete([Message("user", "hi")], model="fake-model")
        assert guard.spent == Decimal("0.001")

        await guard.guarded_complete([Message("user", "hi")], model="fake-model")
        assert guard.spent == Decimal("0.002")

        with pytest.raises(BudgetExceededError):
            await guard.guarded_complete([Message("user", "hi")], model="fake-model")

        # The third call must not have happened — provider only saw 2 calls.
        assert len(provider.calls) == 2


async def test_budget_guard_accumulates_token_usage_on_scan_run(db_adapter):
    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        provider = ScriptedAIProviderAdapter.from_responses("ok")  # 10 input / 10 output tokens per call
        guard = BudgetGuard(scan_run, session, provider)

        from app.ai.adapters.base import Message

        await guard.guarded_complete([Message("user", "hi")], model="fake-model")
        assert scan_run.llm_input_tokens == 10
        assert scan_run.llm_output_tokens == 10

        await guard.guarded_complete([Message("user", "hi")], model="fake-model")
        assert scan_run.llm_input_tokens == 20
        assert scan_run.llm_output_tokens == 20


async def test_guarded_complete_wraps_provider_connection_errors(db_adapter):
    """Real incident this guards against: a transient network failure
    reaching a custom/self-hosted LLM provider propagated as a raw, unhandled
    exception from a deep-in-the-stack agent (request_smuggling's AI
    triage), crashing the entire scan with a bare "Connection error."
    message — none of the ~10 call sites across app/agents/ catch
    anything but BudgetExceededError. guarded_complete must translate a
    genuinely transient provider-call failure like this one into
    ProviderUnavailableError so those existing
    `except (BudgetExceededError, ProviderUnavailableError):` handlers
    catch it too, same as running out of budget — permanent failures
    (bad credentials, malformed requests) are a separate case that must
    propagate as themselves instead, see _is_transient_provider_error.
    """
    from app.ai.adapters.base import AIProviderAdapter, Message
    from app.ai.budget import ProviderUnavailableError

    class _FlakyProvider(AIProviderAdapter):
        async def complete(self, messages, *, model, max_tokens=1024):
            raise ConnectionError("Connection error.")

        async def complete_with_tools(self, *, system, turns, model, tools, max_tokens=2048):
            raise ConnectionError("Connection error.")

        def estimate_cost(self, input_tokens, output_tokens, model):
            return Decimal(0)

    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        guard = BudgetGuard(scan_run, session, _FlakyProvider())

        with pytest.raises(ProviderUnavailableError):
            await guard.guarded_complete([Message("user", "hi")], model="fake-model")


async def test_guarded_complete_does_not_double_wrap_budget_exceeded(db_adapter, monkeypatch):
    # A real BudgetExceededError must still surface as itself, not get
    # relabeled as a ProviderUnavailableError just because it's raised
    # from the same try block as the provider call.
    monkeypatch.setattr(get_settings(), "max_llm_cost_usd_per_scan", Decimal("0"))

    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        provider = ScriptedAIProviderAdapter.from_responses("ok")
        guard = BudgetGuard(scan_run, session, provider)

        from app.ai.adapters.base import Message

        with pytest.raises(BudgetExceededError):
            await guard.guarded_complete([Message("user", "hi")], model="fake-model")
        assert provider.calls == []  # never even reached the provider — budget check comes first


async def test_guarded_complete_does_not_mask_permanent_failures(db_adapter):
    """A bad API key, a malformed request, or an adapter bug is not
    "the provider is unavailable" — it's a permanent, actionable problem
    that must surface as itself so an analyst can actually fix it,
    rather than getting silently absorbed into a vague
    ProviderUnavailableError and having the rest of the scan's LLM work
    quietly skip itself with no clear explanation why.
    """
    from app.ai.adapters.base import AIProviderAdapter, Message
    from app.ai.budget import ProviderUnavailableError

    class _AuthError(Exception):
        """Stands in for a real SDK's APIStatusError subclass (e.g.
        openai.AuthenticationError/anthropic.AuthenticationError) —
        same shape (a real .status_code), no SDK dependency needed here.
        """

        status_code = 401

    class _BadCredentialsProvider(AIProviderAdapter):
        async def complete(self, messages, *, model, max_tokens=1024):
            raise _AuthError("Incorrect API key provided")

        async def complete_with_tools(self, *, system, turns, model, tools, max_tokens=2048):
            raise _AuthError("Incorrect API key provided")

        def estimate_cost(self, input_tokens, output_tokens, model):
            return Decimal(0)

    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        guard = BudgetGuard(scan_run, session, _BadCredentialsProvider())

        with pytest.raises(_AuthError):
            await guard.guarded_complete([Message("user", "hi")], model="fake-model")
        # Specifically NOT wrapped as ProviderUnavailableError.
        try:
            await guard.guarded_complete([Message("user", "hi")], model="fake-model")
        except ProviderUnavailableError:
            pytest.fail("a permanent 401 must not be reported as a transient provider outage")
        except _AuthError:
            pass
