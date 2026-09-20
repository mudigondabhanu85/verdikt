import operator
import uuid
from datetime import datetime, timezone
from typing import Annotated, TypedDict

import httpx
from langgraph.graph import END, StateGraph
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.access_control import AccessControlAgent
from app.agents.chatbot_injection import ChatbotInjectionAgent
from app.agents.auth_agent import AuthAgent
from app.agents.business_logic import BusinessLogicAgent
from app.agents.business_logic_planner import BusinessLogicPlannerAgent
from app.agents.cache_poisoning import CachePoisoningAgent
from app.agents.clickjacking import ClickjackingAgent
from app.agents.cors import CorsAgent
from app.agents.csp_bypass import CspBypassAgent
from app.agents.csrf import CsrfAgent
from app.agents.csv_injection import CsvInjectionAgent
from app.agents.deserialization import DeserializationAgent
from app.agents.dom_xss import DomXssAgent
from app.agents.file_upload import FileUploadAgent
from app.agents.fingerprint import FingerprintAgent
from app.agents.graphql import GraphQLAgent
from app.agents.header_config import HeaderConfigAgent
from app.agents.host_header import HostHeaderAgent
from app.agents.http_client import AuthenticatedSession, ScopedHttpClient
from app.agents.injection import InjectionAgent
from app.agents.login import SessionManager, pick_best_session
from app.agents.oauth import OAuthAgent
from app.agents.prototype_pollution import PrototypePollutionAgent
from app.agents.recon import DiscoveredParameter, FormInfo, ReconAgent
from app.agents.scope import filter_forms_out_login_only, filter_out_login_only, filter_parameters_out_login_only
from app.agents.recon_planner import run_planner_rounds
from app.agents.request_smuggling import RequestSmugglingAgent
from app.agents.session_invalidation import SessionInvalidationAgent
from app.agents.api_version import ApiVersionAgent
from app.agents.open_redirect import OpenRedirectAgent
from app.agents.ssrf import SsrfAgent
from app.agents.stored_xss import StoredXssAgent
from app.agents.traffic_seed import seed_from_imported_traffic
from app.agents.vulnerable_components import VulnerableComponentsAgent
from app.agents.weak_password_policy import WeakPasswordPolicyAgent
from app.agents.websocket_security import WebSocketAgent
from app.agents.xss import XSSAgent
from app.agents.xxe import XxeAgent
from app.ai.budget import BudgetGuard, budget_stop_error
from app.ai.model_tiers import resolve_tiered_model
from app.config import get_settings
from app.models.business_rule import BusinessRule
from app.models.chatbot_agency_probe import ChatbotAgencyProbe
from app.models.chatbot_target import ChatbotTarget
from app.models.credential import CredentialSet
from app.models.finding import Finding
from app.models.project import ScopeEntry
from app.models.review_candidate import ReviewCandidate
from app.models.scan import AgentJob, ScanRun
from app.models.target import Target


class ScanState(TypedDict, total=False):
    discovered_endpoints: list[str]
    discovered_parameters: list[DiscoveredParameter]
    discovered_forms: list[FormInfo]
    discovered_responses: dict[str, httpx.Response]
    discovered_websocket_endpoints: list[str]
    # Endpoints referenced only from a JS fetch()/XMLHttpRequest.open()
    # string literal, never any <a href>/<form> — see
    # app.agents.recon._JS_ENDPOINT_URL_RE.
    discovered_api_endpoints: list[str]
    # Logout links (see app.agents.recon._extract_links) — captured
    # separately from discovered_endpoints because a logout link is
    # deliberately never allowed into that list at all.
    discovered_logout_urls: list[str]
    # recon_node's own anonymous-crawl responses, preserved as-is and
    # never overwritten by authenticated_recon_node's merge into
    # discovered_responses — app.agents.session_invalidation needs a
    # genuinely pre-login baseline to compare a post-logout response
    # against, and discovered_responses stops being that the moment
    # authenticated_recon re-fetches the same URL while logged in.
    anonymous_responses: dict[str, httpx.Response]
    tech_stack_fingerprint: dict
    sessions: dict[uuid.UUID, AuthenticatedSession]
    findings: Annotated[list[Finding], operator.add]
    review_candidates: Annotated[list[ReviewCandidate], operator.add]
    # AI-proposed BusinessRule rows (app.agents.business_logic_planner) —
    # merged with the analyst-authored `business_rules` closure variable
    # by business_logic_node. Provenance-tagged (source="ai_generated")
    # but otherwise indistinguishable to the detection pipeline.
    ai_generated_business_rules: list[BusinessRule]


def build_graph(
    *,
    client: ScopedHttpClient,
    session: AsyncSession,
    scan_run_id: uuid.UUID,
    version_id: uuid.UUID,
    targets: list[Target],
    credential_sets: list[CredentialSet],
    business_rules: list[BusinessRule],
    chatbot_targets: list[ChatbotTarget],
    chatbot_agency_probes: list[ChatbotAgencyProbe],
    budget_guard: BudgetGuard,
    ai_model: str,
    scope_entries: list[ScopeEntry],
):
    """Wires the agent graph: recon fans out to every check that only
    needs its output — [header_config, host_header, cors, clickjacking,
    xxe, graphql, deserialization, dom_xss, ssrf, prototype_pollution,
    request_smuggling, oauth, cache_poisoning, login] — in parallel;
    once login has sessions established, authenticated_recon re-crawls,
    then recon_planner (one LLM call suggesting additional unlinked
    paths, each verified for real before being added anywhere — see
    app.agents.recon_planner) runs as a single gate before the big
    post-login fan-out to [injection, xss, auth, access_control,
    business_logic, csrf, stored_xss, file_upload, websocket] in
    parallel (§10.2's "single biggest lever" — real parallel fan-out,
    not Phase 1's sequential loop), so anything recon_planner confirms
    becomes real testing surface for every one of those, not just a
    UI-only suggestion. csrf/stored_xss/file_upload/websocket need both
    discovered forms/endpoints and established sessions, so unlike the
    other post-recon-only checks they wait on login like the other
    identity-aware agents.

    Each node still creates/updates its own AgentJob row — orchestration
    engine changed, the audit trail shape didn't.
    """

    credential_labels = {c.id: c.label for c in credential_sets}
    credential_ranks = {c.id: c.privilege_rank for c in credential_sets}

    # Automatic per-task model tiering (app.ai.model_tiers) — `ai_model`
    # itself stays the "default" tier, used unchanged by most nodes;
    # these two are only substituted for the specific nodes below whose
    # task is either much higher-volume/simpler (fast) or much more
    # complex/lower-volume (reasoning) than the family's balanced
    # default member. Computed once here rather than per-node: it's a
    # pure, cheap string lookup, not something worth recomputing per
    # call site.
    ai_model_fast = resolve_tiered_model(ai_model, "fast")
    ai_model_reasoning = resolve_tiered_model(ai_model, "reasoning")

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
        # §14 validation gap fix: previously-imported traffic (HAR/Burp/
        # manual/Zest) never fed into what a scan actually tests — this
        # is what makes a client-rendered SPA (whose real API surface
        # never shows up in a GET / response's static HTML) testable at
        # all. See app.agents.traffic_seed. Fetched *before* the crawl
        # (not just unioned in afterward) and passed in as extra crawl
        # seeds — the crawler actually explores links reachable *from*
        # a traffic-imported URL now, not just the URL itself.
        async with client.session_lock:
            seeded_endpoints, seeded_parameters, seeded_websocket_endpoints = (
                await seed_from_imported_traffic(session, version_id)
            )
        agent = ReconAgent(client, targets, extra_seed_urls=seeded_endpoints)
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

        # Safety-net union — a seeded URL that 404s or is out of scope
        # during the crawl's own fresh fetch still counts as discovered
        # (traffic import already proved it's real via a captured past
        # request/response), same as before this seeded-as-crawl-seed
        # change.
        all_endpoints = list(dict.fromkeys(endpoints + seeded_endpoints))
        all_parameters = agent.discovered_parameters + seeded_parameters
        all_websocket_endpoints = list(
            dict.fromkeys(agent.discovered_websocket_endpoints + seeded_websocket_endpoints)
        )

        # Site-map/coverage data (§7 UI) — previously only the *count* of
        # discovered endpoints survived past this node (in stats above);
        # the actual crawled tree, discovered forms, and parameters were
        # never persisted anywhere queryable after the scan finished,
        # even though every one of them is already sitting in memory
        # right here. Kept on this same AgentJob.stats JSON column
        # (already the established place scan-run-scoped structured
        # data lives) rather than a new table — one JSON blob per scan
        # run is simpler than a new table and doesn't need its own
        # migration.
        site_map = {
            "endpoints": [
                {"url": url, "status": agent.discovered_responses[url].status_code}
                for url in all_endpoints
                if url in agent.discovered_responses
            ]
            + [{"url": url, "status": None} for url in all_endpoints if url not in agent.discovered_responses],
            "forms": [
                {
                    "action_url": form.action_url,
                    "method": form.method,
                    "fields": [f.name for f in form.fields],
                }
                for form in agent.discovered_forms
            ],
            "parameters": [{"url": p.url, "name": p.name} for p in all_parameters],
            "websocket_endpoints": all_websocket_endpoints,
        }

        await _finish_job(
            job,
            status="completed",
            stats={
                "endpoints_discovered": len(endpoints),
                "endpoints_seeded_from_traffic": len(seeded_endpoints),
                "websocket_endpoints_seeded_from_traffic": len(seeded_websocket_endpoints),
                "tech_stack_fingerprint": fingerprint,
                "site_map": site_map,
            },
        )
        # §5 scope leak fix: site_map above intentionally still shows
        # everything crawled, including a login-only IdP host, for
        # transparency — but nothing downstream of this node (every
        # detection agent, old and new alike) should ever receive it as
        # testable surface. Filtered here, once, rather than trusting
        # every current and future agent to remember to check this
        # itself.
        fuzzable_endpoints = filter_out_login_only(all_endpoints, scope_entries)
        fuzzable_forms = filter_forms_out_login_only(agent.discovered_forms, scope_entries)
        fuzzable_parameters = filter_parameters_out_login_only(all_parameters, scope_entries)
        return {
            "discovered_endpoints": fuzzable_endpoints,
            "discovered_parameters": fuzzable_parameters,
            "discovered_forms": fuzzable_forms,
            "discovered_responses": agent.discovered_responses,
            "anonymous_responses": agent.discovered_responses,
            "discovered_websocket_endpoints": all_websocket_endpoints,
            "discovered_logout_urls": agent.discovered_logout_urls,
            "discovered_api_endpoints": agent.discovered_api_endpoints,
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
            findings = await agent.run(state.get("discovered_endpoints", []), state.get("sessions", {}))
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

    async def weak_password_policy_node(state: ScanState) -> dict:
        job = await _start_job("weak_password_policy")
        agent = WeakPasswordPolicyAgent(
            client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session
        )
        try:
            findings = await agent.run(
                state.get("discovered_forms", []), state.get("sessions", {}), credential_sets
            )
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def csv_injection_node(state: ScanState) -> dict:
        job = await _start_job("csv_injection")
        agent = CsvInjectionAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(
                state.get("discovered_forms", []),
                state.get("discovered_endpoints", []),
                state.get("sessions", {}),
            )
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def session_invalidation_node(state: ScanState) -> dict:
        job = await _start_job("session_invalidation")
        agent = SessionInvalidationAgent(
            client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session
        )
        try:
            findings = await agent.run(
                credential_sets,
                state.get("discovered_forms", []),
                state.get("discovered_logout_urls", []),
                targets,
                state.get("anonymous_responses", {}),
            )
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def vulnerable_components_node(state: ScanState) -> dict:
        job = await _start_job("vulnerable_components")
        agent = VulnerableComponentsAgent(
            client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session
        )
        try:
            findings = await agent.run(state.get("discovered_endpoints", []), state.get("sessions", {}))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def csp_bypass_node(state: ScanState) -> dict:
        job = await _start_job("csp_bypass")
        agent = CspBypassAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(state.get("discovered_responses", {}), state.get("sessions", {}))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def stored_xss_node(state: ScanState) -> dict:
        job = await _start_job("stored_xss")
        agent = StoredXssAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(
                state.get("discovered_forms", []),
                state.get("discovered_endpoints", []),
                state.get("sessions", {}),
            )
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def file_upload_node(state: ScanState) -> dict:
        job = await _start_job("file_upload")
        agent = FileUploadAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(state.get("discovered_forms", []), state.get("sessions", {}))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def websocket_node(state: ScanState) -> dict:
        job = await _start_job("websocket")
        agent = WebSocketAgent(
            client,
            scan_run_id=scan_run_id,
            agent_job_id=job.id,
            db_session=session,
            scope_entries=scope_entries,
        )
        try:
            findings = await agent.run(
                state.get("discovered_websocket_endpoints", []), state.get("sessions", {})
            )
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
            client,
            scan_run_id=scan_run_id,
            agent_job_id=job.id,
            db_session=session,
            budget_guard=budget_guard,
            ai_model=ai_model_fast,
        )
        try:
            candidates = await agent.run(
                state.get("discovered_responses", {}), state.get("discovered_forms", [])
            )
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        status = "skipped" if agent.budget_exceeded else "completed"
        await _finish_job(
            job,
            status=status,
            stats={"candidates_queued": len(candidates)},
            error=budget_stop_error(agent),
        )
        return {"review_candidates": candidates}

    async def dom_xss_node(state: ScanState) -> dict:
        job = await _start_job("dom_xss")
        agent = DomXssAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(
                state.get("discovered_endpoints", []),
                state.get("sessions", {}),
                state.get("discovered_forms", []),
                state.get("discovered_parameters", []),
            )
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

    async def open_redirect_node(state: ScanState) -> dict:
        job = await _start_job("open_redirect")
        agent = OpenRedirectAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(
                state.get("discovered_parameters", []), state.get("discovered_forms", [])
            )
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def api_version_node(state: ScanState) -> dict:
        job = await _start_job("api_version")
        agent = ApiVersionAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            endpoints = list(
                dict.fromkeys(
                    state.get("discovered_endpoints", []) + state.get("discovered_api_endpoints", [])
                )
            )
            findings = await agent.run(endpoints)
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

    async def request_smuggling_node(state: ScanState) -> dict:
        job = await _start_job("request_smuggling")
        agent = RequestSmugglingAgent(
            client,
            scan_run_id=scan_run_id,
            agent_job_id=job.id,
            db_session=session,
            budget_guard=budget_guard,
            ai_model=ai_model_fast,
        )
        try:
            candidates = await agent.run(state.get("discovered_endpoints", []))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        status = "skipped" if agent.budget_exceeded else "completed"
        await _finish_job(
            job,
            status=status,
            stats={"candidates_queued": len(candidates)},
            error=budget_stop_error(agent),
        )
        return {"review_candidates": candidates}

    async def oauth_node(state: ScanState) -> dict:
        job = await _start_job("oauth")
        agent = OAuthAgent(client, scan_run_id=scan_run_id, agent_job_id=job.id, db_session=session)
        try:
            findings = await agent.run(state.get("discovered_endpoints", []))
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        await _finish_job(job, status="completed", stats={"findings_confirmed": len(findings)})
        return {"findings": findings}

    async def cache_poisoning_node(state: ScanState) -> dict:
        job = await _start_job("cache_poisoning")
        agent = CachePoisoningAgent(
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

    async def authenticated_recon_node(state: ScanState) -> dict:
        """Re-runs the same crawl as recon_node, but as a logged-in user
        instead of an anonymous one — see ReconAgent's docstring for why:
        a purely pre-login crawl only ever sees the login page and public
        assets, missing virtually every form/endpoint an authenticated
        app actually exposes. Skipped (not failed) when no credential
        set produced a session — an unauthenticated target has nothing
        further to discover here.
        """
        job = await _start_job("authenticated_recon")
        sessions = state.get("sessions", {})
        if not sessions:
            await _finish_job(job, status="completed", stats={"endpoints_discovered": 0})
            return {}

        # One session is enough to crawl as — this is discovering the
        # app's *shape* (forms/endpoints/parameters), not testing
        # per-credential behavior differences (that's Access Control's
        # job, which already juggles every session itself). Picked via
        # pick_best_session, not "whichever's first" — see its docstring
        # for the real flakiness this avoids when one credential's
        # session came from a macro replay that didn't fully work.
        auth_session = pick_best_session(sessions)
        # Same extra_seed_urls treatment as recon_node — continue
        # exploring from every endpoint discovered so far (pre-login
        # crawl + traffic import), now with a session, so pages only
        # linked from one of those (rather than found by this crawl's
        # own link-following) still get discovered.
        agent = ReconAgent(
            client, targets, session=auth_session, extra_seed_urls=state.get("discovered_endpoints", [])
        )
        try:
            endpoints = await agent.run()
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise

        merged_endpoints = list(dict.fromkeys(state.get("discovered_endpoints", []) + endpoints))
        merged_responses = {**state.get("discovered_responses", {}), **agent.discovered_responses}
        merged_websocket_endpoints = list(
            dict.fromkeys(
                state.get("discovered_websocket_endpoints", []) + agent.discovered_websocket_endpoints
            )
        )

        # Same site_map shape as recon_node's — previously only the bare
        # *count* survived here, so the UI's "Discovered endpoints" view
        # only ever showed the pre-login crawl's handful of pages even
        # when the authenticated crawl (the one that actually sees the
        # app's real surface) found far more.
        site_map = {
            "endpoints": [
                {"url": url, "status": agent.discovered_responses[url].status_code}
                for url in endpoints
                if url in agent.discovered_responses
            ],
            "forms": [
                {
                    "action_url": form.action_url,
                    "method": form.method,
                    "fields": [f.name for f in form.fields],
                }
                for form in agent.discovered_forms
            ],
            "parameters": [{"url": p.url, "name": p.name} for p in agent.discovered_parameters],
        }

        await _finish_job(
            job,
            status="completed",
            stats={"endpoints_discovered": len(endpoints), "site_map": site_map},
        )
        merged_logout_urls = list(
            dict.fromkeys(state.get("discovered_logout_urls", []) + agent.discovered_logout_urls)
        )
        merged_api_endpoints = list(
            dict.fromkeys(state.get("discovered_api_endpoints", []) + agent.discovered_api_endpoints)
        )
        # Same §5 scope-leak filter as recon_node — this crawl can
        # discover *new* login-only-host URLs of its own (e.g. a
        # dashboard link to "manage your Okta account"), not just
        # re-encounter ones recon_node already filtered out of the seed
        # list it was handed.
        return {
            "discovered_endpoints": filter_out_login_only(merged_endpoints, scope_entries),
            "discovered_parameters": filter_parameters_out_login_only(
                state.get("discovered_parameters", []) + agent.discovered_parameters, scope_entries
            ),
            "discovered_forms": filter_forms_out_login_only(
                state.get("discovered_forms", []) + agent.discovered_forms, scope_entries
            ),
            "discovered_responses": merged_responses,
            "discovered_websocket_endpoints": merged_websocket_endpoints,
            "discovered_logout_urls": merged_logout_urls,
            "discovered_api_endpoints": merged_api_endpoints,
        }

    async def recon_planner_node(state: ScanState) -> dict:
        """AI-driven crawl-coverage loop
        (app.agents.recon_planner.run_planner_rounds): up to
        settings.recon_planner_max_rounds propose-then-crawl rounds,
        instead of a single one-shot suggestion pass. Each round's LLM
        call proposes unlinked-but-plausible paths against the
        *current* site map; every suggestion still has to actually
        resolve against the real target before it's added anywhere, so
        a wrong guess just 404s and is silently dropped, never
        fabricated into the site map. The part that's new: whatever
        does resolve is then handed to a fresh ReconAgent as a crawl
        seed (the same extra_seed_urls mechanism recon_node/
        authenticated_recon_node already use for traffic-imported
        URLs), so anything reachable *from* a confirmed AI-suggested
        page — an admin panel's own nav linking to /admin/users,
        /admin/settings, etc. — gets discovered too, not just the one
        suggested URL sitting alone as a leaf. Each round then feeds
        the next round's LLM call a bigger site map to reason over.
        Sits between authenticated_recon and every consumer of
        discovered_endpoints/parameters/forms, so anything confirmed
        here becomes real testing surface for injection/xss/
        access_control/etc., not just a UI-only suggestion list.
        """
        job = await _start_job("recon_planner")
        sessions = state.get("sessions", {})
        auth_session = pick_best_session(sessions)

        try:
            result = await run_planner_rounds(
                client,
                targets,
                budget_guard=budget_guard,
                ai_model=ai_model,
                session=auth_session,
                max_rounds=get_settings().recon_planner_max_rounds,
                discovered_endpoints=state.get("discovered_endpoints", []),
                discovered_forms=state.get("discovered_forms", []),
                discovered_parameters=state.get("discovered_parameters", []),
                discovered_responses=state.get("discovered_responses", {}),
                discovered_websocket_endpoints=state.get("discovered_websocket_endpoints", []),
                tech_stack_fingerprint=state.get("tech_stack_fingerprint"),
            )
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise

        status = "skipped" if result.budget_exceeded and result.endpoints_suggested_and_confirmed == 0 else "completed"
        await _finish_job(
            job,
            status=status,
            stats={
                "rounds_run": result.rounds_run,
                "endpoints_suggested_and_confirmed": result.endpoints_suggested_and_confirmed,
                "endpoints_discovered_from_suggestions": result.endpoints_discovered_from_suggestions,
            },
            error=result.error,
        )
        # Same §5 scope-leak filter as recon_node/authenticated_recon_node
        # — an AI-suggested path can resolve on a login-only host too
        # (or a confirmed suggestion's own crawl-from-seed can surface
        # new links there), and this is the last point before every
        # detection agent in the graph reads these lists.
        return {
            "discovered_endpoints": filter_out_login_only(result.discovered_endpoints, scope_entries),
            "discovered_parameters": filter_parameters_out_login_only(
                result.discovered_parameters, scope_entries
            ),
            "discovered_forms": filter_forms_out_login_only(result.discovered_forms, scope_entries),
            "discovered_responses": result.discovered_responses,
            "discovered_websocket_endpoints": result.discovered_websocket_endpoints,
        }

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
            findings = await agent.run(
                state.get("discovered_parameters", []),
                state.get("discovered_forms", []),
                state.get("sessions", {}),
                tech_stack_fingerprint=state.get("tech_stack_fingerprint"),
            )
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        status = "skipped" if agent.budget_exceeded else "completed"
        await _finish_job(
            job,
            status=status,
            stats={"findings_confirmed": len(findings)},
            error=budget_stop_error(agent),
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
            candidates = await agent.run(
                state.get("discovered_parameters", []),
                state.get("discovered_forms", []),
                state.get("sessions", {}),
                tech_stack_fingerprint=state.get("tech_stack_fingerprint"),
            )
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        status = "skipped" if agent.budget_exceeded else "completed"
        await _finish_job(
            job,
            status=status,
            stats={"candidates_queued": len(candidates), "findings_confirmed": len(agent.findings)},
            error=budget_stop_error(agent),
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
                state.get("discovered_endpoints", []),
                state.get("sessions", {}),
                credential_labels,
                credential_ranks,
            )
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        status = "skipped" if agent.budget_exceeded else "completed"
        await _finish_job(
            job,
            status=status,
            stats={"findings_confirmed": len(findings)},
            error=budget_stop_error(agent),
        )
        return {"findings": findings}

    async def chatbot_injection_node(state: ScanState) -> dict:
        job = await _start_job("chatbot_injection")
        agent = ChatbotInjectionAgent(
            client,
            scan_run_id=scan_run_id,
            agent_job_id=job.id,
            db_session=session,
            budget_guard=budget_guard,
            ai_model=ai_model,
        )
        try:
            findings = await agent.run(chatbot_targets, state.get("sessions", {}), chatbot_agency_probes)
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        status = "skipped" if agent.budget_exceeded else "completed"
        await _finish_job(
            job,
            status=status,
            stats={"findings_confirmed": len(findings)},
            error=budget_stop_error(agent),
        )
        return {"findings": findings}

    async def ai_business_logic_plan_node(state: ScanState) -> dict:
        """Proposes additional BusinessRule rows from the site map/tech
        stack (app.agents.business_logic_planner) so business_logic_node
        downstream has something to test even when the analyst never
        hand-wrote a single rule — an AI-widened testing surface, not an
        AI-widened confirmation surface: every proposal here still has
        to survive business_logic_node's unmodified deterministic-
        detector -> LLM-triage -> adversarial-validation gate.
        """
        job = await _start_job("ai_business_logic_plan")
        agent = BusinessLogicPlannerAgent(
            version_id=version_id,
            db_session=session,
            budget_guard=budget_guard,
            ai_model=ai_model_reasoning,
            session_lock=client.session_lock,
        )
        try:
            rules = await agent.run(
                discovered_endpoints=state.get("discovered_endpoints", []),
                discovered_forms=state.get("discovered_forms", []),
                discovered_parameters=state.get("discovered_parameters", []),
                tech_stack_fingerprint=state.get("tech_stack_fingerprint"),
            )
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        status = "skipped" if agent.budget_exceeded else "completed"
        await _finish_job(
            job,
            status=status,
            stats={"hypotheses_proposed": len(rules)},
            error=budget_stop_error(agent),
        )
        return {"ai_generated_business_rules": rules}

    async def business_logic_node(state: ScanState) -> dict:
        job = await _start_job("business_logic")
        agent = BusinessLogicAgent(
            client,
            scan_run_id=scan_run_id,
            agent_job_id=job.id,
            db_session=session,
            budget_guard=budget_guard,
            ai_model=ai_model_reasoning,
            sessions=state.get("sessions", {}),
            credential_labels=credential_labels,
        )
        all_rules = business_rules + state.get("ai_generated_business_rules", [])
        try:
            findings = await agent.run(all_rules)
        except Exception as exc:
            await _finish_job(job, status="failed", error=str(exc))
            raise
        status = "skipped" if agent.budget_exceeded else "completed"
        await _finish_job(
            job,
            status=status,
            stats={"findings_confirmed": len(findings)},
            error=budget_stop_error(agent),
        )
        return {"findings": findings}

    graph = StateGraph(ScanState)
    graph.add_node("recon", recon_node)
    graph.add_node("authenticated_recon", authenticated_recon_node)
    graph.add_node("recon_planner", recon_planner_node)
    graph.add_node("header_config", header_config_node)
    graph.add_node("host_header", host_header_node)
    graph.add_node("cors", cors_node)
    graph.add_node("clickjacking", clickjacking_node)
    graph.add_node("xxe", xxe_node)
    graph.add_node("graphql", graphql_node)
    graph.add_node("deserialization", deserialization_node)
    graph.add_node("dom_xss", dom_xss_node)
    graph.add_node("ssrf", ssrf_node)
    graph.add_node("open_redirect", open_redirect_node)
    graph.add_node("api_version", api_version_node)
    graph.add_node("prototype_pollution", prototype_pollution_node)
    graph.add_node("request_smuggling", request_smuggling_node)
    graph.add_node("oauth", oauth_node)
    graph.add_node("cache_poisoning", cache_poisoning_node)
    graph.add_node("login", login_node)
    graph.add_node("injection", injection_node)
    graph.add_node("xss", xss_node)
    graph.add_node("auth", auth_node)
    graph.add_node("access_control", access_control_node)
    graph.add_node("chatbot_injection", chatbot_injection_node)
    graph.add_node("ai_business_logic_plan", ai_business_logic_plan_node)
    graph.add_node("business_logic", business_logic_node)
    graph.add_node("csrf", csrf_node)
    graph.add_node("stored_xss", stored_xss_node)
    graph.add_node("file_upload", file_upload_node)
    graph.add_node("websocket", websocket_node)
    graph.add_node("weak_password_policy", weak_password_policy_node)
    graph.add_node("csv_injection", csv_injection_node)
    graph.add_node("session_invalidation", session_invalidation_node)
    graph.add_node("vulnerable_components", vulnerable_components_node)
    graph.add_node("csp_bypass", csp_bypass_node)

    graph.set_entry_point("recon")
    graph.add_edge("recon", "header_config")
    graph.add_edge("recon", "host_header")
    graph.add_edge("recon", "cors")
    graph.add_edge("recon", "xxe")
    graph.add_edge("recon", "graphql")
    graph.add_edge("recon", "deserialization")
    graph.add_edge("recon", "ssrf")
    graph.add_edge("recon", "prototype_pollution")
    graph.add_edge("recon", "request_smuggling")
    graph.add_edge("recon", "oauth")
    graph.add_edge("recon", "cache_poisoning")
    graph.add_edge("recon", "login")
    graph.add_edge("login", "authenticated_recon")
    graph.add_edge("authenticated_recon", "recon_planner")
    graph.add_edge("recon_planner", "dom_xss")
    # Moved here from a direct "recon" edge (§3 item 3): clickjacking now
    # tests a logged-in user's own view of the page, not just an
    # anonymous one — needs both the authenticated crawl's real endpoint
    # list and a populated `sessions` dict, neither of which exist yet
    # at the point "recon" itself finishes.
    graph.add_edge("recon_planner", "clickjacking")
    graph.add_edge("recon_planner", "injection")
    graph.add_edge("recon_planner", "xss")
    graph.add_edge("recon_planner", "auth")
    graph.add_edge("recon_planner", "access_control")
    graph.add_edge("recon_planner", "chatbot_injection")
    graph.add_edge("recon_planner", "ai_business_logic_plan")
    graph.add_edge("ai_business_logic_plan", "business_logic")
    graph.add_edge("recon_planner", "csrf")
    graph.add_edge("recon_planner", "stored_xss")
    graph.add_edge("recon_planner", "file_upload")
    graph.add_edge("recon_planner", "websocket")
    graph.add_edge("recon_planner", "weak_password_policy")
    graph.add_edge("recon_planner", "csv_injection")
    graph.add_edge("recon_planner", "session_invalidation")
    graph.add_edge("recon_planner", "vulnerable_components")
    graph.add_edge("recon_planner", "csp_bypass")
    graph.add_edge("recon_planner", "api_version")
    graph.add_edge("recon_planner", "open_redirect")
    graph.add_edge("header_config", END)
    graph.add_edge("host_header", END)
    graph.add_edge("cors", END)
    graph.add_edge("clickjacking", END)
    graph.add_edge("xxe", END)
    graph.add_edge("graphql", END)
    graph.add_edge("deserialization", END)
    graph.add_edge("dom_xss", END)
    graph.add_edge("ssrf", END)
    graph.add_edge("open_redirect", END)
    graph.add_edge("prototype_pollution", END)
    graph.add_edge("request_smuggling", END)
    graph.add_edge("oauth", END)
    graph.add_edge("cache_poisoning", END)
    graph.add_edge("websocket", END)
    graph.add_edge("injection", END)
    graph.add_edge("xss", END)
    graph.add_edge("auth", END)
    graph.add_edge("access_control", END)
    graph.add_edge("chatbot_injection", END)
    graph.add_edge("business_logic", END)
    graph.add_edge("stored_xss", END)
    graph.add_edge("file_upload", END)
    graph.add_edge("csrf", END)
    graph.add_edge("weak_password_policy", END)
    graph.add_edge("csv_injection", END)
    graph.add_edge("session_invalidation", END)
    graph.add_edge("vulnerable_components", END)
    graph.add_edge("csp_bypass", END)
    graph.add_edge("api_version", END)

    return graph.compile()
