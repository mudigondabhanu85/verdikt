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
