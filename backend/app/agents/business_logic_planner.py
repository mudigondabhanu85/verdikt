"""AI-generated business-logic test hypotheses — proposes BusinessRule
rows from the site map/tech-stack fingerprint instead of requiring an
analyst to hand-author every one (§3's questionnaire remains fully
supported; this is an additional, not a replacement, source of rules).

Ported from dast-automation's Business Logic specialist pattern (its
system prompt does the same endpoint-shape -> hypothesis-class mapping),
adapted to this app's simpler "analyst writes a BusinessRule row, a
deterministic detector tests it" pipeline instead of an agentic
tool-calling loop. The critical invariant carried over unmodified: the
LLM here proposes what to test and how, never whether something IS
vulnerable — every proposal is just a new BusinessRule row that flows
through the exact same deterministic-detector -> LLM-triage ->
adversarial-validation gate (app.agents.business_logic.BusinessLogicAgent)
as a rule an analyst typed in by hand. A malformed proposal (wrong
field, missing required key, unknown rule_type) is discarded outright,
never best-effort-repaired — same "never guess a Finding into
existence" discipline as app.ai.verdict.parse_verdict.
"""

import asyncio
import uuid
from typing import Any

from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.recon import DiscoveredParameter, FormInfo
from app.ai.budget import BudgetExceededError, BudgetGuard, ProviderUnavailableError
from app.ai.prompts.loader import render_prompt
from app.ai.verdict import extract_json_objects
from app.models.business_rule import BusinessRule
from app.schemas.business_rule import CONFIG_SCHEMAS_BY_RULE_TYPE

_MAX_ENDPOINTS_IN_PROMPT = 60
_MAX_FORMS_IN_PROMPT = 20
_MAX_HYPOTHESES = 8


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
    lines = []
    for form in shown:
        field_names = ", ".join(f.name for f in form.fields) or "(no fields)"
        lines.append(f"- {form.method} {form.action_url} [{field_names}]")
    if len(forms) > len(shown):
        lines.append(f"... and {len(forms) - len(shown)} more, omitted for length")
    return "\n".join(lines)


def _format_parameters(parameters: list[DiscoveredParameter]) -> str:
    if not parameters:
        return "(none discovered)"
    shown = parameters[:_MAX_ENDPOINTS_IN_PROMPT]
    lines = [f"- {p.name} on {p.method} {p.url}" for p in shown]
    if len(parameters) > len(shown):
        lines.append(f"... and {len(parameters) - len(shown)} more, omitted for length")
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


class BusinessLogicPlannerAgent:
    """One LLM call per scan (like ChainAnalysisAgent — a single
    reasoning pass over already-gathered context, not a per-endpoint
    loop), gated the same way every other LLM-calling agent is: budget
    permitting, and only when there's a non-trivial site map to reason
    about at all.
    """

    def __init__(
        self,
        *,
        version_id: uuid.UUID,
        db_session: AsyncSession,
        budget_guard: BudgetGuard,
        ai_model: str,
        session_lock: asyncio.Lock,
    ):
        self._version_id = version_id
        self._session = db_session
        self._budget_guard = budget_guard
        self._ai_model = ai_model
        # The one shared lock every other concurrent agent node's
        # session writes go through (see ScopedHttpClient.session_lock /
        # graph.py's _start_job/_finish_job) — this agent runs in the
        # same fan-out superstep as auth/dom_xss/injection/etc., all
        # sharing one AsyncSession, so an unlocked commit() here used to
        # race theirs and corrupt the shared transaction
        # (IllegalStateChangeError, discovered once app_id fixes let
        # this node's LLM call actually succeed instead of failing
        # before ever reaching this commit).
        self._session_lock = session_lock
        self.budget_exceeded = False
        self.budget_stop_reason: str | None = None

    async def run(
        self,
        *,
        discovered_endpoints: list[str],
        discovered_forms: list[FormInfo],
        discovered_parameters: list[DiscoveredParameter],
        tech_stack_fingerprint: dict[str, Any] | None,
    ) -> list[BusinessRule]:
        if not discovered_endpoints and not discovered_forms:
            # Nothing to reason about — don't spend a token on an empty
            # site map (same "deterministic pre-filter before any LLM
            # call" discipline as chain_analysis's len(findings) < 2 check).
            return []

        messages = render_prompt(
            "business_logic_hypotheses",
            endpoints=_format_endpoints(discovered_endpoints),
            forms=_format_forms(discovered_forms),
            parameters=_format_parameters(discovered_parameters),
            tech_stack=_format_tech_stack(tech_stack_fingerprint),
        )
        try:
            response = await self._budget_guard.guarded_complete(
                messages, model=self._ai_model, max_tokens=2048
            )
        except (BudgetExceededError, ProviderUnavailableError) as exc:
            self.budget_exceeded = True
            self.budget_stop_reason = (
                "provider_unavailable" if isinstance(exc, ProviderUnavailableError) else "budget_exceeded"
            )
            return []

        proposals = _parse_hypotheses(response.content)
        rules: list[BusinessRule] = []
        for proposal in proposals[:_MAX_HYPOTHESES]:
            rule = _materialize_rule(proposal, version_id=self._version_id)
            if rule is None:
                continue
            self._session.add(rule)
            rules.append(rule)

        if rules:
            async with self._session_lock:
                await self._session.commit()
                for rule in rules:
                    await self._session.refresh(rule)
        return rules


def _parse_hypotheses(raw_content: str) -> list[dict]:
    for data in extract_json_objects(raw_content):
        hypotheses = data.get("hypotheses")
        if isinstance(hypotheses, list):
            return [h for h in hypotheses if isinstance(h, dict)]
    return []


def _materialize_rule(proposal: dict, *, version_id: uuid.UUID) -> BusinessRule | None:
    rule_type = proposal.get("rule_type")
    title = proposal.get("title")
    config = proposal.get("config")
    if not isinstance(rule_type, str) or not isinstance(title, str) or not isinstance(config, dict):
        return None
    schema_cls = CONFIG_SCHEMAS_BY_RULE_TYPE.get(rule_type)
    if schema_cls is None:
        return None
    try:
        validated_config = schema_cls(**config).model_dump(mode="json")
    except ValidationError:
        # Malformed proposal — discarded outright, never best-effort
        # repaired. See app.schemas.business_rule.BusinessRuleCreate's
        # identical validator for the analyst-authored path this mirrors.
        return None
    return BusinessRule(
        version_id=version_id,
        rule_type=rule_type,
        title=title[:500],
        config=validated_config,
        created_by=None,
        source="ai_generated",
    )
