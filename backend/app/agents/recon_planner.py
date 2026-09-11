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
from typing import Any
from urllib.parse import urljoin

import httpx

from app.agents.http_client import AuthenticatedSession, ScopedHttpClient, ScopeViolationError
from app.agents.recon import DiscoveredParameter, FormInfo, _extract_query_params
from app.ai.budget import BudgetExceededError, BudgetGuard, ProviderUnavailableError
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
