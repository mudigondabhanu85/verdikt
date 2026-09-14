"""AI-suggested additional endpoints (§3/§10 "more AI, not just narrower
triage") — after the deterministic crawl (app.agents.recon) finishes,
one LLM call reviews the discovered site map + tech-stack fingerprint
and proposes unlinked-but-plausible paths worth checking (an admin
panel the crawler never found a link to, a framework-conventional
diagnostics endpoint, etc.) — the same "propose, don't confirm" split
as app.agents.business_logic_planner: the LLM only ever proposes a
path to *try*; every suggestion still has to actually resolve
(status < 400) against the real target before it's added to the site
map at all, and resolving successfully doesn't make it a Finding by
itself either — it just becomes more surface for the deterministic
detectors and injection/xss to test, exactly like anything the crawler
found on its own. A suggestion that 404s (the common case for a wrong
guess) is silently dropped, never retried or reported.
"""

import asyncio
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx

from app.agents.http_client import AuthenticatedSession, ScopedHttpClient, ScopeViolationError
from app.agents.recon import DiscoveredParameter, FormInfo, ReconAgent, _extract_query_params
from app.ai.budget import BudgetExceededError, BudgetGuard, ProviderUnavailableError, budget_stop_error
from app.ai.prompts.loader import render_prompt
from app.ai.verdict import extract_json_objects
from app.models.target import Target

_MAX_ENDPOINTS_IN_PROMPT = 60
_MAX_FORMS_IN_PROMPT = 20
_MAX_SUGGESTIONS = 15
_FETCH_CONCURRENCY = 5


def _format_endpoints(endpoints: list[str]) -> str:
    if not endpoints:
        return "(none discovered)"
    shown = endpoints[:_MAX_ENDPOINTS_IN_PROMPT]
    lines = [f"- {url}" for url in shown]
    if len(endpoints) > len(shown):
        lines.append(f"... and {len(endpoints) - len(shown)} more, omitted for length")
    return "\n".join(lines)


def _format_forms(forms: list[FormInfo]) -> str:
    if not forms:
        return "(none discovered)"
    shown = forms[:_MAX_FORMS_IN_PROMPT]
    lines = [f"- {form.method} {form.action_url}" for form in shown]
    if len(forms) > len(shown):
        lines.append(f"... and {len(forms) - len(shown)} more, omitted for length")
    return "\n".join(lines)


def _format_tech_stack(fingerprint: dict[str, Any] | None) -> str:
    if not fingerprint:
        return "(not determined)"
    parts = []
    for key in ("server_software", "backend_languages", "frontend_frameworks", "cms"):
        values = fingerprint.get(key) or []
        if values:
            parts.append(f"{key}: {', '.join(values)}")
    return "; ".join(parts) if parts else "(not determined)"


def _parse_suggested_paths(raw_content: str) -> list[str]:
    for data in extract_json_objects(raw_content):
        paths = data.get("suggested_paths")
        if isinstance(paths, list):
            return [p for p in paths if isinstance(p, str) and p.startswith("/")]
    return []


class ReconPlannerAgent:
    """One LLM call per scan (like BusinessLogicPlannerAgent/
    ChainAnalysisAgent — a single reasoning pass over already-gathered
    context, not a per-URL loop), gated the same way: budget
    permitting, and only when there's a non-trivial site map to reason
    about at all.
    """

    def __init__(
        self,
        client: ScopedHttpClient,
        targets: list[Target],
        *,
        budget_guard: BudgetGuard,
        ai_model: str,
        session: AuthenticatedSession | None = None,
    ):
        self._client = client
        self._targets = targets
        self._budget_guard = budget_guard
        self._ai_model = ai_model
        self._session = session
        self.budget_exceeded = False
        self.budget_stop_reason: str | None = None
        self.discovered_parameters: list[DiscoveredParameter] = []

    async def run(
        self,
        *,
        discovered_endpoints: list[str],
        discovered_forms: list[FormInfo],
        tech_stack_fingerprint: dict[str, Any] | None,
    ) -> list[str]:
        if not discovered_endpoints or not self._targets:
            # Nothing to reason about yet, or nowhere to resolve a
            # suggested path against — don't spend a token (same
            # pre-filter discipline as business_logic_planner's).
            return []

        messages = render_prompt(
            "recon_endpoint_suggestions",
            endpoints=_format_endpoints(discovered_endpoints),
            forms=_format_forms(discovered_forms),
            tech_stack=_format_tech_stack(tech_stack_fingerprint),
        )
        try:
            response = await self._budget_guard.guarded_complete(
                messages, model=self._ai_model, max_tokens=512
            )
        except (BudgetExceededError, ProviderUnavailableError) as exc:
            self.budget_exceeded = True
            self.budget_stop_reason = (
                "provider_unavailable" if isinstance(exc, ProviderUnavailableError) else "budget_exceeded"
            )
            return []

        suggested_paths = _parse_suggested_paths(response.content)[:_MAX_SUGGESTIONS]
        if not suggested_paths:
            return []

        already_discovered = set(discovered_endpoints)
        candidate_urls: list[str] = []
        for target in self._targets:
            base = target.base_url or f"http://{target.host}:{target.port}/"
            for path in suggested_paths:
                url = urljoin(base if base.endswith("/") else base + "/", path.lstrip("/"))
                if url not in already_discovered:
                    candidate_urls.append(url)

        semaphore = asyncio.Semaphore(_FETCH_CONCURRENCY)
        responses = await asyncio.gather(*(self._verify(url, semaphore) for url in candidate_urls))

        confirmed: list[str] = []
        for url, response in zip(candidate_urls, responses):
            if response is not None and response.status_code < 400:
                confirmed.append(url)
                self.discovered_parameters.extend(_extract_query_params(url))
        return confirmed

    async def _verify(self, url: str, semaphore: asyncio.Semaphore) -> httpx.Response | None:
        async with semaphore:
            try:
                return await self._client.get(url, session=self._session)
            except (ScopeViolationError, httpx.HTTPError):
                return None


@dataclass
class ReconPlannerRoundsResult:
    """Merged site-map state after `run_planner_rounds` — same shape as
    the crawl-state fields graph.py's ScanState carries, so a caller can
    hand this straight back out as node state without reshaping it.
    """

    discovered_endpoints: list[str]
    discovered_parameters: list[DiscoveredParameter]
    discovered_forms: list[FormInfo]
    discovered_responses: dict[str, httpx.Response] = field(default_factory=dict)
    discovered_websocket_endpoints: list[str] = field(default_factory=list)
    rounds_run: int = 0
    endpoints_suggested_and_confirmed: int = 0
    endpoints_discovered_from_suggestions: int = 0
    last_planner: ReconPlannerAgent | None = None

    @property
    def budget_exceeded(self) -> bool:
        return self.last_planner is not None and self.last_planner.budget_exceeded

    @property
    def error(self) -> str | None:
        return budget_stop_error(self.last_planner) if self.last_planner is not None else None


async def run_planner_rounds(
    client: ScopedHttpClient,
    targets: list[Target],
    *,
    budget_guard: BudgetGuard,
    ai_model: str,
    session: AuthenticatedSession | None,
    max_rounds: int,
    discovered_endpoints: list[str],
    discovered_forms: list[FormInfo],
    discovered_parameters: list[DiscoveredParameter],
    discovered_responses: dict[str, httpx.Response],
    discovered_websocket_endpoints: list[str],
    tech_stack_fingerprint: dict[str, Any] | None,
) -> ReconPlannerRoundsResult:
    """The AI-driven crawl-coverage loop: up to `max_rounds`
    propose-then-crawl rounds instead of ReconPlannerAgent's single
    one-shot suggestion pass. Each round's LLM call proposes
    unlinked-but-plausible paths against the *current* site map, exactly
    as ReconPlannerAgent.run() already does; the part this function adds
    is that whatever actually resolves is then handed to a fresh
    ReconAgent as a crawl seed (the same extra_seed_urls mechanism
    app.agents.graph's recon_node/authenticated_recon_node already use
    for traffic-imported URLs) — so anything reachable *from* a
    confirmed AI-suggested page (an admin panel's own nav linking to
    /admin/users, /admin/settings, etc.) gets discovered too, not just
    the single suggested URL sitting alone as a leaf. Each round then
    hands the next round's LLM call a bigger site map to reason over —
    a suggestion that only makes sense once /admin/users is already on
    the map (e.g. /admin/users/export) gets a real chance in round 2.

    Stops early once a round confirms nothing (no seeds to crawl from,
    and nothing for another round to reason differently about) or the
    AI budget is exhausted; bounded by max_rounds either way so a
    chatty model can't turn one scan into an unbounded chain of LLM
    calls.
    """
    endpoints = discovered_endpoints
    forms = discovered_forms
    parameters = discovered_parameters
    responses = discovered_responses
    websocket_endpoints = discovered_websocket_endpoints

    rounds_run = 0
    total_confirmed = 0
    total_crawled_from_suggestions = 0
    planner: ReconPlannerAgent | None = None

    for _round in range(max_rounds):
        planner = ReconPlannerAgent(
            client, targets, budget_guard=budget_guard, ai_model=ai_model, session=session
        )
        confirmed = await planner.run(
            discovered_endpoints=endpoints,
            discovered_forms=forms,
            tech_stack_fingerprint=tech_stack_fingerprint,
        )
        rounds_run += 1
        parameters = parameters + planner.discovered_parameters
        total_confirmed += len(confirmed)

        if planner.budget_exceeded or not confirmed:
            break

        endpoints = list(dict.fromkeys(endpoints + confirmed))

        crawler = ReconAgent(client, targets, session=session, extra_seed_urls=confirmed)
        crawled = await crawler.run()
        total_crawled_from_suggestions += len(crawled)

        endpoints = list(dict.fromkeys(endpoints + crawled))
        forms = forms + crawler.discovered_forms
        parameters = parameters + crawler.discovered_parameters
        responses = {**responses, **crawler.discovered_responses}
        websocket_endpoints = list(
            dict.fromkeys(websocket_endpoints + crawler.discovered_websocket_endpoints)
        )

    return ReconPlannerRoundsResult(
        discovered_endpoints=endpoints,
        discovered_parameters=parameters,
        discovered_forms=forms,
        discovered_responses=responses,
        discovered_websocket_endpoints=websocket_endpoints,
        rounds_run=rounds_run,
        endpoints_suggested_and_confirmed=total_confirmed,
        endpoints_discovered_from_suggestions=total_crawled_from_suggestions,
        last_planner=planner,
    )
