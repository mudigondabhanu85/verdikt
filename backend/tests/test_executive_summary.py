import uuid

from app.ai.budget import BudgetGuard
from app.models.finding import Finding
from app.models.scan import ScanRun
from app.reporting.executive_summary import generate_executive_summary
from app.schemas.scan import ScanRunDetail
from tests.conftest import session_scope
from tests.fakes import ScriptedAIProviderAdapter


class _FakeSettings:
    def __init__(self, ai_provider: str, max_llm_cost_usd_per_scan=None):
        self.ai_provider = ai_provider
        if max_llm_cost_usd_per_scan is not None:
            self.max_llm_cost_usd_per_scan = max_llm_cost_usd_per_scan


def _detail(*, status="completed", counts=None) -> ScanRunDetail:
    counts = counts or {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    return ScanRunDetail(
        id=uuid.uuid4(),
        version_id=uuid.uuid4(),
        status=status,
        started_at=None,
        completed_at=None,
        error=None,
        agent_jobs=[],
        finding_counts_by_severity=counts,
    )


def _finding(**overrides) -> Finding:
    defaults = dict(
        scan_run_id=uuid.uuid4(),
        agent_job_id=uuid.uuid4(),
        check_id="xss-reflected",
        title="Reflected XSS",
        severity="High",
        owasp_2025_category="A05 Injection",
        cwe_id="CWE-79",
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=6.1,
        affected_endpoints=["http://site.test/search"],
        plain_language_summary="plain",
        technical_description="technical",
        steps_to_reproduce=["1. do it"],
        remediation="fix it",
        references=[],
    )
    defaults.update(overrides)
    return Finding(**defaults)


async def test_fallback_used_when_no_real_provider_configured(db_adapter, monkeypatch):
    monkeypatch.setattr(
        "app.reporting.executive_summary.get_settings", lambda: _FakeSettings("fake")
    )
    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.uuid4(), status="completed", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        provider = ScriptedAIProviderAdapter.from_responses("should never be called")
        guard = BudgetGuard(scan_run, session, provider)

        findings = [_finding()]
        summary = await generate_executive_summary(
            scan_run=_detail(counts={"Critical": 0, "High": 1, "Medium": 0, "Low": 0}),
            findings=findings,
            budget_guard=guard,
            ai_model="fake-model",
        )

        assert provider.calls == []
        assert "1 finding" in summary
        assert "Reflected XSS" in summary


async def test_fallback_no_findings_message(db_adapter, monkeypatch):
    monkeypatch.setattr(
        "app.reporting.executive_summary.get_settings", lambda: _FakeSettings("fake")
    )
    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.uuid4(), status="completed", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        provider = ScriptedAIProviderAdapter.from_responses("should never be called")
        guard = BudgetGuard(scan_run, session, provider)

        summary = await generate_executive_summary(
            scan_run=_detail(), findings=[], budget_guard=guard, ai_model="fake-model"
        )
        assert "No confirmed findings" in summary


async def test_llm_narrative_used_when_real_provider_configured(db_adapter, monkeypatch):
    from decimal import Decimal

    monkeypatch.setattr(
        "app.reporting.executive_summary.get_settings",
        lambda: _FakeSettings("claude", max_llm_cost_usd_per_scan=Decimal("2.00")),
    )
    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.uuid4(), status="completed", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        provider = ScriptedAIProviderAdapter.from_responses(
            "Overall risk is moderate; one high-severity XSS issue needs prompt remediation."
        )
        guard = BudgetGuard(scan_run, session, provider)

        summary = await generate_executive_summary(
            scan_run=_detail(counts={"Critical": 0, "High": 1, "Medium": 0, "Low": 0}),
            findings=[_finding()],
            budget_guard=guard,
            ai_model="fake-model",
        )

        assert len(provider.calls) == 1
        assert summary == "Overall risk is moderate; one high-severity XSS issue needs prompt remediation."


async def test_falls_back_when_budget_already_exhausted(db_adapter, monkeypatch):
    from decimal import Decimal

    monkeypatch.setattr(
        "app.reporting.executive_summary.get_settings",
        lambda: _FakeSettings("claude", max_llm_cost_usd_per_scan=Decimal("0.00")),
    )
    # BudgetGuard reads the cap via its own imported get_settings
    # (app.ai.budget), independent of executive_summary's — patch both so
    # the guard actually starts out already at its (zero) cap.
    monkeypatch.setattr(
        "app.ai.budget.get_settings",
        lambda: _FakeSettings("claude", max_llm_cost_usd_per_scan=Decimal("0.00")),
    )
    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(
            version_id=uuid.uuid4(),
            status="completed",
            requested_by=uuid.uuid4(),
            llm_cost_usd=Decimal("0.00"),
        )
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        provider = ScriptedAIProviderAdapter.from_responses("should not be reachable either")
        guard = BudgetGuard(scan_run, session, provider)

        summary = await generate_executive_summary(
            scan_run=_detail(), findings=[], budget_guard=guard, ai_model="fake-model"
        )
        assert "No confirmed findings" in summary
        assert provider.calls == []
