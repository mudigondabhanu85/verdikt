"""Automatic per-task model tiering.

This is a deliberately different shape from the prior attempt at this
same idea (app.ai.model_routing / AIProviderConfig.model_reasoning +
.model_classification, added in migration 0029, removed in 0032): that
version required an analyst to manually type in extra model names per
provider config, in an Account-page UI control — a second configuration
surface nobody was required to fill in correctly, and apparently few
did, since the whole feature was later removed rather than kept. This
version adds zero new user-facing configuration and zero new database
columns. An org still configures exactly one model, exactly as before
(Account -> AI Provider Configs, or the deployment-wide AI_MODEL
setting) — that single string is still "the model" for anything this
module doesn't recognize. Where it *does* recognize the configured
model as belonging to a known provider family, it silently substitutes
a same-family sibling for tasks that are either far higher-volume (many
calls per scan, so a cheaper model matters most here) or far more
complex/lower-volume (a handful of calls per scan, so a stronger model
is affordable) than the family's balanced "default" member — with zero
scan-to-scan configuration and nothing for an analyst to get wrong.

Model family membership below reflects what was verified current as of
this module's writing (September 2026) for each provider's own public
API docs — Claude's three names come directly from this deployment's
own system configuration (authoritative for this account); OpenAI's and
xAI's were confirmed against their current API docs. Gemini is
deliberately left out of the family table below: Google is actively
retiring the entire Gemini 2.5 line in October 2026 and the exact
current stable (non-preview) 3.x model id was not reliably confirmable
at the time this was written — rather than ship a guessed identifier
that could silently 404 an org's scans the moment it goes stale,
Gemini-configured orgs get exactly today's behavior (one model, every
task) until this table is deliberately extended once that naming
settles. An org on a model this table doesn't recognize at all (a
custom/self-hosted OpenAI-compatible gateway, a Gemini config, a future
model this hasn't been updated for) gets that same safe fallback,
automatically and silently — never an error, never a guessed model
name that might not exist on that org's account.
"""

from typing import Literal

Tier = Literal["fast", "default", "reasoning"]

# Each entry maps one provider model family's three tiers. "default" is
# listed explicitly (even though it's just the family's own balanced
# member) so an org whose *configured* model happens to be the "fast"
# or "reasoning" member of a family still resolves correctly to every
# tier, not just the ones above/below whatever they happened to type in.
_MODEL_FAMILIES: tuple[dict[Tier, str], ...] = (
    # Claude 5 family — authoritative for this deployment (see this
    # session's own system configuration).
    {
        "fast": "claude-haiku-4-5-20251001",
        "default": "claude-sonnet-5",
        "reasoning": "claude-opus-5",
    },
    # OpenAI GPT-5 family — confirmed current API model ids at
    # developers.openai.com/api/docs/models/{gpt-5-mini,gpt-5,gpt-5-pro}.
    {
        "fast": "gpt-5-mini",
        "default": "gpt-5",
        "reasoning": "gpt-5-pro",
    },
    # xAI Grok 4 family — grok-4 and grok-4-fast are xAI's own maintained
    # aliases (confirmed: retired dated snapshots like grok-4-0709
    # redirect to the current model server-side under these same alias
    # names), so these stay valid even as the model xAI serves behind
    # them changes. No separate confirmed premium-reasoning id above
    # "default" as of this writing, so reasoning intentionally matches
    # default here rather than guessing one.
    {
        "fast": "grok-4-fast",
        "default": "grok-4",
        "reasoning": "grok-4",
    },
)


def resolve_tiered_model(configured_model: str, tier: Tier) -> str:
    """Given the one model string an org actually configured, returns
    the right sibling for `tier`. Always returns `configured_model`
    unchanged for tier="default", and falls back to it unchanged for
    any tier when `configured_model` isn't recognized as belonging to
    a known family — the safe, silent, zero-configuration default that
    keeps this feature from ever being able to send a request to a
    model name an org's account doesn't actually have.
    """
    if tier == "default":
        return configured_model
    for family in _MODEL_FAMILIES:
        if configured_model in family.values():
            return family[tier]
    return configured_model
