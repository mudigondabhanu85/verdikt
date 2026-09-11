"""Per-agent-role model selection (multi-agent §0/§10 follow-up — a
single Spark/Claude/OpenAI account can usually reach several model
sizes, e.g. Spark's gpt-4o family; before this module every agent in a
scan shared one hardcoded model string end to end, so an org paying for
a bigger reasoning model got no benefit from it on cheap mechanical
work, and couldn't opt a stronger model into hard reasoning tasks
without repointing the *whole* scan at it). Modeled directly on
dast-automation's AGENT_MODELS / resolve_model(agent_role) pattern.

Three tiers, cheapest to most capable:
- "classification": mechanical/pattern-matching triage — cheap and fast
  is fine here; nothing here benefits much from a bigger model.
- "specialist": the bulk of vulnerability-class agents (injection, XSS,
  access control) — the existing single-model behavior, kept as the
  default tier so a config that only sets `model` is unaffected.
- "reasoning": business-logic hypothesis generation, attack-chain
  analysis, and adversarial finding validation — the tasks that most
  benefit from (and most need) a stronger model to actually cut false
  positives rather than just paraphrasing a detector's output.
"""

from dataclasses import dataclass
from typing import Literal

ModelTier = Literal["classification", "specialist", "reasoning"]

# Which tier each agent role resolves to. New agents should be added
# here explicitly rather than falling through to a default, so a
# forgotten entry fails loudly (KeyError) instead of silently under- or
# over-spending on the wrong model.
AGENT_ROLE_TIER: dict[str, ModelTier] = {
    "access_control": "specialist",
    "injection": "specialist",
    "xss": "specialist",
    "business_logic": "reasoning",
    "business_logic_planner": "reasoning",
    "chain_analysis": "reasoning",
    "reporting": "reasoning",  # executive summary generation
    # Mechanical triage on a single deterministic signal (a byte-pattern
    # match / a timing delta) — never confirms a Finding on its own, so
    # cheap-and-fast is exactly right here, same rationale as the tier's
    # docstring above.
    "deserialization": "classification",
    "request_smuggling": "classification",
    # Suggesting plausible unlinked paths from naming conventions is
    # closer to pattern completion than deep reasoning.
    "recon_planner": "classification",
}


@dataclass(frozen=True)
class ModelRouter:
    """Resolved once per scan (see app.ai.provider.resolve_provider_and_model)
    and threaded down to wherever a model string is needed, instead of
    a single flat `ai_model: str`. `specialist` doubles as the
    catch-all default: a config that never set model_reasoning /
    model_classification behaves exactly as it did before this module
    existed — every tier just resolves to the same one model.
    """

    specialist: str
    reasoning: str
    classification: str

    @classmethod
    def single_model(cls, model: str) -> "ModelRouter":
        """Back-compat constructor for the deployment-wide `.env`
        fallback path (app.config.Settings has no per-tier model
        settings) — every tier resolves to the one configured model.
        """
        return cls(specialist=model, reasoning=model, classification=model)

    def for_role(self, agent_role: str) -> str:
        tier = AGENT_ROLE_TIER[agent_role]
        return getattr(self, tier)
