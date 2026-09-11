import json
import re
import uuid

from pydantic import BaseModel, ValidationError
from sqlalchemy import select

from app.ai.budget import BudgetExceededError, BudgetGuard, ProviderUnavailableError
from app.ai.prompts.loader import render_prompt
from app.ai.verdict import parse_verdict
from app.models.attack_chain import AttackChain, AttackChainEvidence
from app.models.finding import Evidence, Finding

_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

# Same code-fence tolerance as app.ai.verdict.parse_verdict (real model
# output routinely wraps JSON in a ```json ... ``` fence even when asked
# for raw JSON) — duplicated locally rather than importing verdict.py's
# private regex, since this parses a different top-level shape (a
# {"chains": [...]} object, not a single {"vulnerable": ...} verdict).
_CODE_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)\n?```", re.DOTALL)


class ChainProposal(BaseModel):
    finding_ids: list[str]
    title: str
    severity: str
    narrative: str
    steps_to_reproduce: list[str]
    plain_language_summary: str


def _parse_chain_proposals(raw_content: str) -> list[ChainProposal]:
    """Fail-safe like parse_verdict: unparseable or schema-mismatched
    output yields zero proposals rather than raising — never manufacture
    a chain from a malformed response."""
    candidates = _CODE_FENCE_RE.findall(raw_content) or [raw_content]
    for candidate in reversed(candidates):
        try:
            data = json.loads(candidate.strip())
        except json.JSONDecodeError:
            continue
        chains = data.get("chains") if isinstance(data, dict) else None
        if chains is None:
            continue
        proposals: list[ChainProposal] = []
        for raw in chains:
            try:
                proposals.append(ChainProposal(**raw))
            except ValidationError:
                continue
        return proposals
    return []


def _summarize_finding(finding: Finding) -> str:
    return (
        f"finding_id={finding.id} | severity={finding.severity} | "
        f"check_id={finding.check_id} | title={finding.title} | "
        f"affected_endpoints={finding.affected_endpoints} | "
        f"summary={finding.plain_language_summary}"
    )


def _full_finding_detail(finding: Finding) -> str:
    return (
        f"finding_id={finding.id}\n"
        f"title: {finding.title}\n"
        f"severity: {finding.severity}\n"
        f"check_id: {finding.check_id}\n"
        f"affected_endpoints: {finding.affected_endpoints}\n"
        f"plain_language_summary: {finding.plain_language_summary}\n"
        f"technical_description: {finding.technical_description}\n"
    )


class ChainAnalysisAgent:
    """§2's Chain Analysis Agent — runs after every other agent's findings
    are Confirmed, reviewing the full set together for compound exploits
    (docs/BUILD_SPEC.md §2 "Attack Chain Analysis"). Same two-pass
    discipline as every other agent in this pipeline: an AI triage pass
    proposes chains, then an independent adversarial AI validation pass
    tries to disprove each one before it's persisted — applied to the
    chain as a whole, not just its individual (already-Confirmed) links.
    """

    def __init__(
        self,
        *,
        scan_run_id: uuid.UUID,
        agent_job_id: uuid.UUID,
        db_session,
        budget_guard: BudgetGuard,
        ai_model: str,
    ):
        self._scan_run_id = scan_run_id
        self._agent_job_id = agent_job_id
        self._session = db_session
        self._budget_guard = budget_guard
        self._ai_model = ai_model
        self.budget_exceeded = False
        self.budget_stop_reason: str | None = None

    async def run(self, findings: list[Finding]) -> list[AttackChain]:
        # Deterministic pre-filter (§10) — a chain needs at least 2 links;
        # don't spend a single token when that's structurally impossible.
        if len(findings) < 2:
            return []

        findings_by_id = {str(f.id): f for f in findings}
        findings_summary = "\n".join(_summarize_finding(f) for f in findings)

        try:
            triage_response = await self._budget_guard.guarded_complete(
                render_prompt("chain_analysis_triage", findings_summary=findings_summary),
                model=self._ai_model,
            )
        except (BudgetExceededError, ProviderUnavailableError) as exc:
            self.budget_exceeded = True
            self.budget_stop_reason = (
                "provider_unavailable" if isinstance(exc, ProviderUnavailableError) else "budget_exceeded"
            )
            return []

        proposals = _parse_chain_proposals(triage_response.content)

        chains: list[AttackChain] = []
        for proposal in proposals:
            if self.budget_exceeded:
                break
            linked = [findings_by_id[fid] for fid in proposal.finding_ids if fid in findings_by_id]
            # A proposal referencing findings we weren't actually given
            # (hallucinated IDs) or fewer than 2 real links isn't a real
            # chain — discard without spending a validation call.
            if len(linked) < 2:
                continue

            chain = await self._validate_and_persist(proposal, linked)
            if chain is not None:
                chains.append(chain)

        return chains

    async def _validate_and_persist(
        self, proposal: ChainProposal, linked: list[Finding]
    ) -> AttackChain | None:
        linked_detail = "\n---\n".join(_full_finding_detail(f) for f in linked)
        try:
            validation_response = await self._budget_guard.guarded_complete(
                render_prompt(
                    "chain_analysis_validation",
                    chain_title=proposal.title,
                    chain_severity=proposal.severity,
                    chain_narrative=proposal.narrative,
                    chain_steps=" | ".join(proposal.steps_to_reproduce),
                    linked_findings_detail=linked_detail,
                ),
                model=self._ai_model,
            )
        except (BudgetExceededError, ProviderUnavailableError) as exc:
            self.budget_exceeded = True
            self.budget_stop_reason = (
                "provider_unavailable" if isinstance(exc, ProviderUnavailableError) else "budget_exceeded"
            )
            return None

        verdict = parse_verdict(validation_response.content)
        if verdict is None or not verdict.vulnerable or verdict.confidence == "low":
            return None

        severity = proposal.severity if proposal.severity in _SEVERITY_RANK else "High"

        chain = AttackChain(
            scan_run_id=self._scan_run_id,
            title=proposal.title,
            severity=severity,
            finding_ids=[str(f.id) for f in linked],
            plain_language_summary=proposal.plain_language_summary,
            narrative=(
                f"{proposal.narrative} An independent adversarial review attempted to "
                f"disprove this chain and could not: {verdict.reasoning}"
            ),
            steps_to_reproduce=proposal.steps_to_reproduce,
            references=[],
            confirmation_status="ai_confirmed",
        )

        finding_ids = [f.id for f in linked]
        evidence_rows = (
            (
                await self._session.execute(
                    select(Evidence).where(Evidence.finding_id.in_(finding_ids))
                )
            )
            .scalars()
            .all()
        )
        combined_request = "\n\n---\n\n".join(e.request_raw for e in evidence_rows)
        combined_response = "\n\n---\n\n".join(e.response_raw for e in evidence_rows)
        screenshot_refs = [ref for e in evidence_rows for ref in (e.screenshot_refs or [])]

        self._session.add(chain)
        await self._session.flush()
        self._session.add(
            AttackChainEvidence(
                attack_chain_id=chain.id,
                request_raw=combined_request,
                response_raw=combined_response,
                screenshot_refs=screenshot_refs,
                additional_notes=(
                    f"Combined evidence from {len(linked)} linked findings: "
                    f"{', '.join(str(f.id) for f in linked)}."
                ),
            )
        )
        await self._session.commit()
        return chain
