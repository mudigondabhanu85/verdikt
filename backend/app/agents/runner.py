import asyncio
import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from app.agents.chain_analysis import ChainAnalysisAgent
from app.agents.graph import build_graph
from app.agents.http_client import ScopedHttpClient, install_commit_backstop
from app.ai import provider as ai_provider
from app.ai.budget import BudgetGuard
from app.ai.model_routing import ModelRouter
from app.db import session as db_session
from app.models.business_rule import BusinessRule
from app.models.credential import CredentialSet
from app.models.finding import Finding
from app.models.project import ScopeEntry
from app.models.scan import AgentJob, ScanRun
from app.models.target import Target
from app.notifications.scan_notifications import notify_scan_completed
from app.notifications.vgs_push import push_findings_to_vgs


async def _run_chain_analysis(
    session, *, scan_run: ScanRun, budget_guard: BudgetGuard, model_router: ModelRouter
) -> None:
    """§2's Chain Analysis Agent runs after every other agent has fully
    finished (not as a graph fan-in node — LangGraph's join semantics
    fire a node once per superstep in which *any* predecessor completes,
    not once all of them have, so nodes converging from branches of
    different depths (e.g. header_config, 2 hops from recon, vs.
    injection, 3 hops through login) fire the join multiple times,
    racing each other over the shared AsyncSession. Running this as a
    plain sequential step here, after `graph.ainvoke()` has already
    returned, sidesteps that entirely — by construction nothing else is
    still writing to the session at this point) — matches the spec's own
    framing: "run after validation, before reporting."
    """
    job = AgentJob(
        scan_run_id=scan_run.id,
        agent_type="chain_analysis",
        status="running",
        started_at=datetime.now(timezone.utc),
    )
    session.add(job)
    await session.commit()
    await session.refresh(job)

    findings = list(
        (await session.execute(select(Finding).where(Finding.scan_run_id == scan_run.id))).scalars()
    )
    agent = ChainAnalysisAgent(
        scan_run_id=scan_run.id,
        agent_job_id=job.id,
        db_session=session,
        budget_guard=budget_guard,
        ai_model=model_router.for_role("chain_analysis"),
    )
    try:
        chains = await agent.run(findings)
    except Exception as exc:  # noqa: BLE001 — a failed chain-analysis pass shouldn't fail the scan
        job.status = "failed"
        job.error = str(exc)
        job.completed_at = datetime.now(timezone.utc)
        await session.commit()
        return

    job.status = "skipped" if agent.budget_exceeded else "completed"
    job.stats = {"chains_confirmed": len(chains)}
    job.error = "budget exceeded" if agent.budget_exceeded else None
    job.completed_at = datetime.now(timezone.utc)
    await session.commit()


_ZERO_ENDPOINTS_WARNING = (
    "Recon discovered 0 endpoints — nothing was crawled, so this scan's results "
    "are not meaningful. This usually means the Target's host doesn't exactly "
    "match an in-scope entry (Scope enforces an exact host string match), or "
    "there's no Target configured at all. Check the Scope and Targets tabs, "
    "then rerun."
)


async def _endpoints_discovered_total(session, scan_run_id: uuid.UUID) -> int:
    result = await session.execute(
        select(AgentJob.stats).where(
            AgentJob.scan_run_id == scan_run_id,
            AgentJob.agent_type.in_(("recon", "authenticated_recon")),
        )
    )
    return sum((stats or {}).get("endpoints_discovered", 0) for (stats,) in result.all())


async def execute_scan_run(scan_run_id: uuid.UUID) -> None:
    """Builds the Phase-2 agent graph (app.agents.graph) for one ScanRun
    and runs it to completion. Invoked by FastAPI BackgroundTasks. Opens
    its own DB session since there's no request context in a background
    task.

    Looks up the adapter/AI provider via module attribute access (not
    `from ... import get_adapter`/`get_ai_provider`) so tests can
    monkeypatch `app.db.session.get_adapter` / `app.ai.provider.get_ai_provider`
    and have it take effect here too — BackgroundTasks run outside
    FastAPI's dependency-override system.
    """
    adapter = db_session.get_adapter()
    async with db_session.session_scope(adapter) as session:
        install_commit_backstop(session)
        scan_run = await session.get(ScanRun, scan_run_id)
        if scan_run is None:
            return

        scan_run.status = "running"
        scan_run.started_at = datetime.now(timezone.utc)
        await session.commit()

        client: ScopedHttpClient | None = None
        try:
            scope_entries = list(
                (
                    await session.execute(
                        select(ScopeEntry).where(ScopeEntry.version_id == scan_run.version_id)
                    )
                ).scalars()
            )
            targets = list(
                (await session.execute(select(Target).where(Target.version_id == scan_run.version_id))).scalars()
            )
            credential_sets = list(
                (
                    await session.execute(
                        select(CredentialSet).where(CredentialSet.version_id == scan_run.version_id)
                    )
                ).scalars()
            )
            business_rules = list(
                (
                    await session.execute(
                        select(BusinessRule).where(BusinessRule.version_id == scan_run.version_id)
                    )
                ).scalars()
            )

            # One lock for every write to this shared AsyncSession across
            # the whole scan run — Phase 2's LangGraph orchestrator runs
            # several agents truly concurrently, all sharing this one
            # client/session (see ScopedHttpClient.session_lock).
            session_lock = asyncio.Lock()
            client = ScopedHttpClient(
                version_id=scan_run.version_id,
                scope_entries=scope_entries,
                db_session=session,
                session_lock=session_lock,
            )
            provider, model_router = await ai_provider.resolve_provider_and_model(session, scan_run)
            budget_guard = BudgetGuard(scan_run, session, provider, lock=session_lock)

            graph = build_graph(
                client=client,
                session=session,
                scan_run_id=scan_run.id,
                version_id=scan_run.version_id,
                targets=targets,
                credential_sets=credential_sets,
                business_rules=business_rules,
                budget_guard=budget_guard,
                model_router=model_router,
                scope_entries=scope_entries,
            )
            await graph.ainvoke({})
            await _run_chain_analysis(
                session, scan_run=scan_run, budget_guard=budget_guard, model_router=model_router
            )

            scan_run.status = "completed"
            if await _endpoints_discovered_total(session, scan_run.id) == 0:
                scan_run.warning = _ZERO_ENDPOINTS_WARNING
        except asyncio.CancelledError:
            # A user-requested cancel (app.api.routes.scans' cancel
            # endpoint, via app.agents.task_registry) reaches this task
            # as a real asyncio cancellation at its next await point —
            # record it as a distinct outcome, not a failure, then
            # re-raise: never silently swallow CancelledError.
            scan_run.status = "cancelled"
            raise
        except Exception as exc:  # noqa: BLE001 — surfaced on the ScanRun, not swallowed
            scan_run.status = "failed"
            scan_run.error = str(exc)
        finally:
            if client is not None:
                await client.aclose()
            scan_run.completed_at = datetime.now(timezone.utc)
            await session.commit()
            await notify_scan_completed(session, scan_run)
            await push_findings_to_vgs(session, scan_run)
