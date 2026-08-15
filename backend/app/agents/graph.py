import operator
import uuid
from datetime import datetime, timezone
from typing import Annotated, TypedDict

from langgraph.graph import END, StateGraph
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.access_control import AccessControlAgent
from app.agents.auth_agent import AuthAgent
from app.agents.header_config import HeaderConfigAgent
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.agents.injection import InjectionAgent
from app.agents.login import SessionManager
from app.agents.recon import DiscoveredParameter, FormInfo, ReconAgent
from app.agents.xss import XSSAgent
from app.ai.budget import BudgetGuard
from app.models.credential import CredentialSet
from app.models.finding import Finding
from app.models.review_candidate import ReviewCandidate
from app.models.scan import AgentJob
from app.models.target import Target


class ScanState(TypedDict, total=False):
    discovered_endpoints: list[str]
    discovered_parameters: list[DiscoveredParameter]
    discovered_forms: list[FormInfo]
    sessions: dict[uuid.UUID, AuthenticatedSession]
    findings: Annotated[list[Finding], operator.add]
    review_candidates: Annotated[list[ReviewCandidate], operator.add]


def build_graph(
    *,
    client: ScopedHttpClient,
    session: AsyncSession,
    scan_run_id: uuid.UUID,
    targets: list[Target],
    credential_sets: list[CredentialSet],
    budget_guard: BudgetGuard,
    ai_model: str,
):
    """Wires the Phase-2 agent graph: recon fans out to [header_config,
    login] in parallel; once login has sessions established, it fans out
    to [injection, xss, auth, access_control] in parallel too (§10.2's
    "single biggest lever" — real parallel fan-out, not Phase 1's
    sequential loop). header_config only depends on recon's endpoint
    list, so it runs fully concurrently with the whole second wave, not
    just the first.

    Each node still creates/updates its own AgentJob row (recon/
    header_config/login/injection/xss/auth/access_control) — orchestration
    engine changed, the audit trail shape didn't.
    """

    credential_labels = {c.id: c.label for c in credential_sets}

    async def _start_job(agent_type: str) -> AgentJob:
        job = AgentJob(
            scan_run_id=scan_run_id,
            agent_type=agent_type,
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        async with client.session_lock:
            session.add(job)
            await session.commit()
            await session.refresh(job)
        return job

    async def _finish_job(
        job: AgentJob, *, status: str, stats: dict | None = None, error: str | None = None
    ) -> None:
        job.status = status
        job.completed_at = datetime.now(timezone.utc)
        job.stats = stats
        job.error = error
        async with client.session_lock:
            await session.commit()

    async def recon_node(_state: ScanState) -> dict:
        job = await _start_job("recon")
        agent = ReconAgent(client, targets)
        try:
            endpoints = await agent.run()
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"endpoints_discovered": len(endpoints)})
        return {
            "discovered_endpoints": endpoints,
            "discovered_parameters": agent.discovered_parameters,
            "discovered_forms": agent.discovered_forms,
        }

    async def header_config_node(state: ScanState) -> dict:
        job = await _start_job("header_config")
        agent = HeaderConfigAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(state.get("discovered_endpoints", []))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def login_node(state: ScanState) -> dict:
        job = await _start_job("login")
        manager = SessionManager(client)
        forms = state.get("discovered_forms", [])
        sessions: dict[uuid.UUID, AuthenticatedSession] = {}
        try:
            for credential_set in credential_sets:
                auth_session = await manager.login(credential_set, forms)
                if auth_session is not None:
                    sessions[credential_set.id] = auth_session
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"sessions_established": len(sessions)})
        return {"sessions": sessions}

    async def injection_node(state: ScanState) -> dict:
        job = await _start_job("injection")
        agent = InjectionAgent(
            client,
            scan_run_id=scan_run_id,
            agent_job_id=job.id,
            db_session=session,
            budget_guard=budget_guard,
            ai_model=ai_model,
        )
        try:
            findings = await agent.run(state.get("discovered_parameters", []), state.get("discovered_forms", []))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        status = "skipped" if agent.budget_exceeded else "completed"
        await _finish_job(
            job,
            status=status,
            stats={"findings_confirmed": len(findings)},
            error="budget exceeded" if agent.budget_exceeded else None,
        )
        return {"findings": findings}

    async def xss_node(state: ScanState) -> dict:
        job = await _start_job("xss")
        agent = XSSAgent(
            client,
            scan_run_id=scan_run_id,
            agent_job_id=job.id,
            db_session=session,
            budget_guard=budget_guard,
            ai_model=ai_model,
        )
        try:
            candidates = await agent.run(state.get("discovered_parameters", []), state.get("discovered_forms", []))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        status = "skipped" if agent.budget_exceeded else "completed"
        await _finish_job(
            job,
            status=status,
            stats={"candidates_queued": len(candidates)},
            error="budget exceeded" if agent.budget_exceeded else None,
        )
        return {"review_candidates": candidates}

    async def auth_node(state: ScanState) -> dict:
        job = await _start_job("auth")
        agent = AuthAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(state.get("sessions", {}), state.get("discovered_endpoints", []))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def access_control_node(state: ScanState) -> dict:
        job = await _start_job("access_control")
        agent = AccessControlAgent(
            client,
            scan_run_id=scan_run_id,
            agent_job_id=job.id,
            db_session=session,
            budget_guard=budget_guard,
            ai_model=ai_model,
        )
        try:
            findings = await agent.run(
                state.get("discovered_endpoints", []), state.get("sessions", {}), credential_labels
            )
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        status = "skipped" if agent.budget_exceeded else "completed"
        await _finish_job(
            job,
            status=status,
            stats={"findings_confirmed": len(findings)},
            error="budget exceeded" if agent.budget_exceeded else None,
        )
        return {"findings": findings}

    graph = StateGraph(ScanState)
    graph.add_node("recon", recon_node)
    graph.add_node("header_config", header_config_node)
    graph.add_node("login", login_node)
    graph.add_node("injection", injection_node)
    graph.add_node("xss", xss_node)
    graph.add_node("auth", auth_node)
    graph.add_node("access_control", access_control_node)

    graph.set_entry_point("recon")
    graph.add_edge("recon", "header_config")
    graph.add_edge("recon", "login")
    graph.add_edge("login", "injection")
    graph.add_edge("login", "xss")
    graph.add_edge("login", "auth")
    graph.add_edge("login", "access_control")
    graph.add_edge("header_config", END)
    graph.add_edge("injection", END)
    graph.add_edge("xss", END)
    graph.add_edge("auth", END)
    graph.add_edge("access_control", END)

    return graph.compile()
