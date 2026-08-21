import asyncio
import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from app.agents.graph import build_graph
from app.agents.http_client import ScopedHttpClient
from app.ai import provider as ai_provider
from app.ai.budget import BudgetGuard
from app.db import session as db_session
from app.models.business_rule import BusinessRule
from app.models.credential import CredentialSet
from app.models.project import ScopeEntry
from app.models.scan import ScanRun
from app.models.target import Target
from app.notifications.scan_notifications import notify_scan_completed


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
            provider, ai_model = await ai_provider.resolve_provider_and_model(session, scan_run)
            budget_guard = BudgetGuard(scan_run, session, provider, lock=session_lock)

            graph = build_graph(
                client=client,
                session=session,
                scan_run_id=scan_run.id,
                targets=targets,
                credential_sets=credential_sets,
                business_rules=business_rules,
                budget_guard=budget_guard,
                ai_model=ai_model,
                scope_entries=scope_entries,
            )
            await graph.ainvoke({})

            scan_run.status = "completed"
        except Exception as exc:  # noqa: BLE001 — surfaced on the ScanRun, not swallowed
            scan_run.status = "failed"
            scan_run.error = str(exc)
        finally:
            if client is not None:
                await client.aclose()
            scan_run.completed_at = datetime.now(timezone.utc)
            await session.commit()
            await notify_scan_completed(session, scan_run)
