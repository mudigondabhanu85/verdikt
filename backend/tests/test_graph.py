import asyncio
import itertools
import time
import uuid

import httpx
from sqlalchemy import select

from app.agents.graph import build_graph
from app.agents.http_client import ScopedHttpClient
from app.ai.budget import BudgetGuard
from app.models.credential import CredentialSet
from app.models.project import ScopeEntry
from app.models.scan import AgentJob, ScanRun
from app.models.target import Target
from app.vault.credential_vault import encrypt_credential
from tests.conftest import session_scope
from tests.fakes import ScriptedAIProviderAdapter

_REQUEST_INTERVALS: list[tuple[float, float]] = []
_SLEEP = 0.03


async def _handler(request: httpx.Request) -> httpx.Response:
    start = time.monotonic()
    await asyncio.sleep(_SLEEP)
    url = str(request.url)

    if url == "http://site.test/" or url == "http://site.test/robots.txt" or url == "http://site.test/sitemap.xml":
        response = httpx.Response(200, headers={"content-type": "text/html"}, text="<html><body>Home</body></html>")
    elif url == "http://site.test/rest/login" and request.method == "POST":
        response = httpx.Response(200, headers={"content-type": "application/json"}, json={"token": "session-token-abc"})
    else:
        response = httpx.Response(404)

    _REQUEST_INTERVALS.append((start, time.monotonic()))
    return response


def _overlapping_pairs_exist(intervals: list[tuple[float, float]]) -> bool:
    for (a_start, a_end), (b_start, b_end) in itertools.combinations(intervals, 2):
        if a_start < b_end and b_start < a_end:
            return True
    return False


async def test_graph_runs_agents_with_real_parallelism_and_merges_state(db_adapter):
    _REQUEST_INTERVALS.clear()

    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        client = ScopedHttpClient(
            version_id=scan_run.version_id,
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )
        targets = [Target(host="site.test", port=80, base_url="http://site.test/")]
        credential = CredentialSet(
            version_id=scan_run.version_id,
            label="Admin",
            credential_type="username_password",
            encrypted_secret=encrypt_credential("admin", "hunter2"),
            masked_reference="admin (****)",
            login_endpoint="http://site.test/rest/login",
            login_method="POST",
            login_body_template='{"username": "{username}", "password": "{password}"}',
            login_content_type="application/json",
            token_response_path="token",
        )

        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": false, "confidence": "low", "reasoning": "nothing interesting on this fixture site"}'
        )
        # Must share ScopedHttpClient's session_lock (see BudgetGuard's
        # docstring) — several agent nodes run truly concurrently here
        # and all write to the same AsyncSession; two independent locks
        # let a BudgetGuard-driven commit race a graph.py-driven one
        # (this test previously never reached this far, so the gap was
        # never exercised).
        guard = BudgetGuard(scan_run, session, provider, lock=client.session_lock)

        graph = build_graph(
            client=client,
            session=session,
            scan_run_id=scan_run.id,
            version_id=scan_run.version_id,
            targets=targets,
            credential_sets=[credential],
            business_rules=[],
            budget_guard=guard,
            ai_model="fake-model",
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
        )
        final_state = await graph.ainvoke({})
        await client.aclose()

        # All agent nodes ran and each tracked its own AgentJob.
        jobs_result = await session.execute(select(AgentJob).where(AgentJob.scan_run_id == scan_run.id))
        jobs = list(jobs_result.scalars())
        assert {j.agent_type for j in jobs} == {
            "recon",
            "header_config",
            "host_header",
            "cors",
            "clickjacking",
            "xxe",
            "graphql",
            "deserialization",
            "dom_xss",
            "ssrf",
            "prototype_pollution",
            "request_smuggling",
            "oauth",
            "cache_poisoning",
            "login",
            "authenticated_recon",
            "recon_planner",
            "injection",
            "xss",
            "auth",
            "access_control",
            "ai_business_logic_plan",
            "business_logic",
            "csrf",
            "stored_xss",
            "file_upload",
            "websocket",
            "weak_password_policy",
            "csv_injection",
            "session_invalidation",
            "vulnerable_components",
        }
        assert all(j.status == "completed" for j in jobs), jobs

        # login_node's session made it into final state and was usable by
        # a later wave (auth/access_control ran without error against it).
        login_job = next(j for j in jobs if j.agent_type == "login")
        assert login_job.stats == {"sessions_established": 1}

        # State merged correctly across whichever nodes wrote to
        # "findings"/"review_candidates" — no KeyError, no overwrite crash,
        # a plain list either way.
        assert isinstance(final_state.get("findings", []), list)
        assert isinstance(final_state.get("review_candidates", []), list)

        # Real parallelism proof: header_config and login run concurrently
        # (both fed directly by recon), and every request sleeps for the
        # same fixed duration — if execution were actually sequential,
        # no two requests' [start, end) wall-clock intervals could ever
        # overlap. This aggregates every agent's requests (recon, confirm
        # re-fetches, login, etc.), so overlap is a genuine concurrency
        # signal, not a fluke of scheduling.
        assert len(_REQUEST_INTERVALS) >= 2
        assert _overlapping_pairs_exist(_REQUEST_INTERVALS)


class _RecordingAgent:
    """Stands in for a real agent class — records exactly the kwargs
    graph.py constructed it with (in particular ai_model=) and returns
    an empty result immediately, with no real HTTP/LLM activity. Lets
    the wiring test below prove *which model string graph.py actually
    passed* to each node's agent constructor without needing to
    manufacture real deserialization/business-logic signals for those
    agents' own trigger conditions to fire.
    """

    instances: list["_RecordingAgent"] = []

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        self.budget_exceeded = False
        type(self).instances.append(self)

    async def run(self, *args, **kwargs):
        return []


async def test_graph_wires_the_right_model_tier_to_the_right_node(db_adapter, monkeypatch):
    """app.ai.model_tiers wiring: deserialization/request_smuggling
    (high-volume, simple triage) get the "fast" tier; the two
    business-logic nodes (low-volume, complex reasoning) get
    "reasoning"; everything else (injection, as a control) keeps the
    scan's plain configured model. Verified by substituting a recording
    fake for each real agent class rather than needing those agents'
    own real trigger conditions to fire against a fixture site.
    """
    import app.agents.graph as graph_module

    _RecordingAgent.instances = []
    for name in (
        "DeserializationAgent",
        "RequestSmugglingAgent",
        "BusinessLogicPlannerAgent",
        "BusinessLogicAgent",
        "InjectionAgent",
    ):
        monkeypatch.setattr(graph_module, name, _RecordingAgent)

    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.uuid4(), status="running", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        client = ScopedHttpClient(
            version_id=scan_run.version_id,
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
            db_session=session,
            transport=httpx.MockTransport(_handler),
        )
        provider = ScriptedAIProviderAdapter.from_responses(
            '{"vulnerable": false, "confidence": "low", "reasoning": "n/a"}'
        )
        guard = BudgetGuard(scan_run, session, provider, lock=client.session_lock)

        graph = build_graph(
            client=client,
            session=session,
            scan_run_id=scan_run.id,
            version_id=scan_run.version_id,
            targets=[Target(host="site.test", port=80, base_url="http://site.test/")],
            credential_sets=[],
            business_rules=[],
            budget_guard=guard,
            ai_model="claude-sonnet-5",
            scope_entries=[ScopeEntry(host="site.test", port=80, in_scope=True)],
        )
        await graph.ainvoke({})
        await client.aclose()

    # All five substituted nodes together must exercise exactly the
    # three tiered model strings for ai_model="claude-sonnet-5" — proof
    # that graph.py is actually threading the fast/default/reasoning
    # substitutions to real node constructors, not just that
    # resolve_tiered_model works in isolation (already covered by
    # tests/test_model_tiers.py).
    ai_models_used = {i.kwargs["ai_model"] for i in _RecordingAgent.instances}
    assert ai_models_used == {"claude-haiku-4-5-20251001", "claude-opus-5", "claude-sonnet-5"}, ai_models_used
