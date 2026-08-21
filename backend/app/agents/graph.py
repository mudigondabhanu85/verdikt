import operator
import uuid
from datetime import datetime, timezone
from typing import Annotated, TypedDict

import httpx
from langgraph.graph import END, StateGraph
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.access_control import AccessControlAgent
from app.agents.auth_agent import AuthAgent
from app.agents.business_logic import BusinessLogicAgent
from app.agents.clickjacking import ClickjackingAgent
from app.agents.cors import CorsAgent
from app.agents.csrf import CsrfAgent
from app.agents.deserialization import DeserializationAgent
from app.agents.dom_xss import DomXssAgent
from app.agents.file_upload import FileUploadAgent
from app.agents.fingerprint import FingerprintAgent
from app.agents.graphql import GraphQLAgent
from app.agents.header_config import HeaderConfigAgent
from app.agents.host_header import HostHeaderAgent
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.agents.injection import InjectionAgent
from app.agents.login import SessionManager
from app.agents.prototype_pollution import PrototypePollutionAgent
from app.agents.recon import DiscoveredParameter, FormInfo, ReconAgent
from app.agents.ssrf import SsrfAgent
from app.agents.stored_xss import StoredXssAgent
from app.agents.xss import XSSAgent
from app.agents.xxe import XxeAgent
from app.ai.budget import BudgetGuard
from app.models.business_rule import BusinessRule
from app.models.credential import CredentialSet
from app.models.finding import Finding
from app.models.review_candidate import ReviewCandidate
from app.models.scan import AgentJob, ScanRun
from app.models.target import Target


class ScanState(TypedDict, total=False):
    discovered_endpoints: list[str]
    discovered_parameters: list[DiscoveredParameter]
    discovered_forms: list[FormInfo]
    discovered_responses: dict[str, httpx.Response]
    tech_stack_fingerprint: dict
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
    business_rules: list[BusinessRule],
    budget_guard: BudgetGuard,
    ai_model: str,
):
    """Wires the agent graph: recon fans out to every check that only
    needs its output — [header_config, host_header, cors, clickjacking,
    xxe, graphql, deserialization, dom_xss, ssrf, login] — in parallel;
    once login has sessions established, it fans out to [injection, xss,
    auth, access_control, business_logic, csrf] in parallel too (§10.2's
    "single biggest lever" — real parallel fan-out, not Phase 1's
    sequential loop). csrf needs both discovered forms and established
    sessions, so unlike the other post-recon-only checks it waits on
    login like the other identity-aware agents.

    Each node still creates/updates its own AgentJob row — orchestration
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
        # The attribute mutations below must be inside the lock too, not
        # just the commit — `job` is already attached to the shared
        # AsyncSession (via _start_job's session.add()), so setting its
        # attributes touches the session's unit-of-work/dirty-tracking
        # state exactly like a write does. With enough concurrent nodes
        # under LangGraph's true parallel fan-out, mutating outside the
        # lock raced with another node's commit badly enough to silently
        # lose a status update entirely (a real, observed bug — a job
        # stuck at "running" forever with a SQLAlchemy warning about
        # discarded attribute history from a concurrent inner flush).
        async with client.session_lock:
            job.status = status
            job.completed_at = datetime.now(timezone.utc)
            job.stats = stats
            job.error = error
            await session.commit()

    async def recon_node(_state: ScanState) -> dict:
        job = await _start_job("recon")
        agent = ReconAgent(client, targets)
        try:
            endpoints = await agent.run()
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise

        # §10 smart scan: deterministic tech-stack fingerprint over the
        # pages recon already fetched — zero extra requests. Persisted on
        # the ScanRun itself (not just AgentJob.stats) so it survives
        # independently of this job row and is easy to surface in reports.
        fingerprint = FingerprintAgent().run(agent.discovered_responses).to_dict()
        async with client.session_lock:
            scan_run = await session.get(ScanRun, scan_run_id)
            scan_run.tech_stack_fingerprint = fingerprint
            await session.commit()

        await _finish_job(
            job,
            status="completed",
            stats={"endpoints_discovered": len(endpoints), "tech_stack_fingerprint": fingerprint},
        )
        return {
            "discovered_endpoints": endpoints,
            "discovered_parameters": agent.discovered_parameters,
            "discovered_forms": agent.discovered_forms,
            "discovered_responses": agent.discovered_responses,
            "tech_stack_fingerprint": fingerprint,
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

    async def host_header_node(state: ScanState) -> dict:
        job = await _start_job("host_header")
        agent = HostHeaderAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(state.get("discovered_endpoints", []))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def cors_node(state: ScanState) -> dict:
        job = await _start_job("cors")
        agent = CorsAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(state.get("discovered_endpoints", []))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def clickjacking_node(state: ScanState) -> dict:
        job = await _start_job("clickjacking")
        agent = ClickjackingAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(state.get("discovered_endpoints", []))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def csrf_node(state: ScanState) -> dict:
        job = await _start_job("csrf")
        agent = CsrfAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(state.get("discovered_forms", []), state.get("sessions", {}))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def stored_xss_node(state: ScanState) -> dict:
        job = await _start_job("stored_xss")
        agent = StoredXssAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(state.get("discovered_forms", []), state.get("discovered_endpoints", []))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def file_upload_node(state: ScanState) -> dict:
        job = await _start_job("file_upload")
        agent = FileUploadAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(state.get("discovered_forms", []))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def xxe_node(state: ScanState) -> dict:
        job = await _start_job("xxe")
        agent = XxeAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(state.get("discovered_forms", []))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def graphql_node(state: ScanState) -> dict:
        job = await _start_job("graphql")
        agent = GraphQLAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(state.get("discovered_endpoints", []))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def deserialization_node(state: ScanState) -> dict:
        job = await _start_job("deserialization")
        agent = DeserializationAgent(
            client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session
        )
        try:
            candidates = await agent.run(
                state.get("discovered_responses", {}), state.get("discovered_forms", [])
            )
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"candidates_queued": len(candidates)})
        return {"review_candidates": candidates}

    async def dom_xss_node(state: ScanState) -> dict:
        job = await _start_job("dom_xss")
        agent = DomXssAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(state.get("discovered_endpoints", []))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def ssrf_node(state: ScanState) -> dict:
        job = await _start_job("ssrf")
        agent = SsrfAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(state.get("discovered_parameters", []), state.get("discovered_forms", []))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def prototype_pollution_node(state: ScanState) -> dict:
        job = await _start_job("prototype_pollution")
        agent = PrototypePollutionAgent(
            client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session
        )
        try:
            findings = await agent.run(state.get("discovered_endpoints", []))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def login_node(state: ScanState) -> dict:
        job = await _start_job("login")
        manager = SessionManager(client, db_session=session)
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
            stats={"candidates_queued": len(candidates), "findings_confirmed": len(agent.findings)},
            error="budget exceeded" if agent.budget_exceeded else None,
        )
        return {"review_candidates": candidates, "findings": agent.findings}

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

    async def business_logic_node(state: ScanState) -> dict:
        job = await _start_job("business_logic")
        agent = BusinessLogicAgent(
            client,
            scan_run_id=scan_run_id,
            agent_job_id=job.id,
            db_session=session,
            budget_guard=budget_guard,
            ai_model=ai_model,
            sessions=state.get("sessions", {}),
            credential_labels=credential_labels,
        )
        try:
            findings = await agent.run(business_rules)
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
    graph.add_node("host_header", host_header_node)
    graph.add_node("cors", cors_node)
    graph.add_node("clickjacking", clickjacking_node)
    graph.add_node("xxe", xxe_node)
    graph.add_node("graphql", graphql_node)
    graph.add_node("deserialization", deserialization_node)
    graph.add_node("dom_xss", dom_xss_node)
    graph.add_node("ssrf", ssrf_node)
    graph.add_node("prototype_pollution", prototype_pollution_node)
    graph.add_node("login", login_node)
    graph.add_node("injection", injection_node)
    graph.add_node("xss", xss_node)
    graph.add_node("auth", auth_node)
    graph.add_node("access_control", access_control_node)
    graph.add_node("business_logic", business_logic_node)
    graph.add_node("csrf", csrf_node)
    graph.add_node("stored_xss", stored_xss_node)
    graph.add_node("file_upload", file_upload_node)

    graph.set_entry_point("recon")
    graph.add_edge("recon", "header_config")
    graph.add_edge("recon", "host_header")
    graph.add_edge("recon", "cors")
    graph.add_edge("recon", "clickjacking")
    graph.add_edge("recon", "xxe")
    graph.add_edge("recon", "graphql")
    graph.add_edge("recon", "deserialization")
    graph.add_edge("recon", "dom_xss")
    graph.add_edge("recon", "ssrf")
    graph.add_edge("recon", "prototype_pollution")
    graph.add_edge("recon", "login")
    graph.add_edge("login", "injection")
    graph.add_edge("login", "xss")
    graph.add_edge("login", "auth")
    graph.add_edge("login", "access_control")
    graph.add_edge("login", "business_logic")
    graph.add_edge("login", "csrf")
    graph.add_edge("login", "stored_xss")
    graph.add_edge("login", "file_upload")
    graph.add_edge("header_config", END)
    graph.add_edge("host_header", END)
    graph.add_edge("cors", END)
    graph.add_edge("clickjacking", END)
    graph.add_edge("xxe", END)
    graph.add_edge("graphql", END)
    graph.add_edge("deserialization", END)
    graph.add_edge("dom_xss", END)
    graph.add_edge("ssrf", END)
    graph.add_edge("prototype_pollution", END)
    graph.add_edge("injection", END)
    graph.add_edge("xss", END)
    graph.add_edge("auth", END)
    graph.add_edge("access_control", END)
    graph.add_edge("business_logic", END)
    graph.add_edge("stored_xss", END)
    graph.add_edge("file_upload", END)
    graph.add_edge("csrf", END)

    return graph.compile()
