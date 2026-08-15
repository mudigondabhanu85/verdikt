import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from app.agents.header_config import HeaderConfigAgent
from app.agents.http_client import ScopedHttpClient
from app.agents.recon import ReconAgent
from app.db import session as db_session
from app.models.project import ScopeEntry
from app.models.scan import AgentJob, ScanRun
from app.models.target import Target


async def execute_scan_run(scan_run_id: uuid.UUID) -> None:
    """Runs recon -> header/config sequentially for one ScanRun. Invoked by
    FastAPI BackgroundTasks (no orchestrator yet — that's Phase 2's real
    parallel fan-out). Opens its own DB session since there's no request
    context in a background task.

    Looks up the adapter via `db_session.get_adapter()` (module attribute
    access, not a `from ... import get_adapter`) so tests can monkeypatch
    `app.db.session.get_adapter` and have it take effect here too —
    BackgroundTasks run outside FastAPI's dependency-override system, so
    without this a background task would silently fall back to the real
    production DATABASE_URL instead of a test database.
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
                (
                    await session.execute(
                        select(Target).where(Target.version_id == scan_run.version_id)
                    )
                ).scalars()
            )

            client = ScopedHttpClient(
                version_id=scan_run.version_id, scope_entries=scope_entries, db_session=session
            )

            endpoints = await _run_agent_job(
                session, scan_run, "recon", lambda job: ReconAgent(client, targets).run()
            )

            await _run_agent_job(
                session,
                scan_run,
                "header_config",
                lambda job: HeaderConfigAgent(
                    client, scan_run_id=scan_run.id, agent_job_id=job.id, db_session=session
                ).run(endpoints),
                stats_key="findings_confirmed",
            )

            scan_run.status = "completed"
        except Exception as exc:  # noqa: BLE001 — surfaced on the ScanRun, not swallowed
            scan_run.status = "failed"
            scan_run.error = str(exc)
        finally:
            if client is not None:
                await client.aclose()
            scan_run.completed_at = datetime.now(timezone.utc)
            await session.commit()


async def _run_agent_job(session, scan_run: ScanRun, agent_type: str, run_fn, *, stats_key: str = "endpoints_discovered"):
    job = AgentJob(
        scan_run_id=scan_run.id,
        agent_type=agent_type,
        status="running",
        started_at=datetime.now(timezone.utc),
    )
    session.add(job)
    await session.commit()
    await session.refresh(job)

    try:
        result = await run_fn(job)
    except Exception as exc:
        job.status = "failed"
        job.error = str(exc)
        job.completed_at = datetime.now(timezone.utc)
        await session.commit()
        raise

    job.status = "completed"
    job.completed_at = datetime.now(timezone.utc)
    job.stats = {stats_key: len(result)}
    await session.commit()
    return result
