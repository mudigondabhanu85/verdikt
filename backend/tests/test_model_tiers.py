from app.ai.model_tiers import resolve_tiered_model


def test_default_tier_always_returns_the_configured_model_unchanged():
    assert resolve_tiered_model("claude-sonnet-5", "default") == "claude-sonnet-5"
    assert resolve_tiered_model("some-custom-self-hosted-model", "default") == "some-custom-self-hosted-model"


def test_claude_family_resolves_fast_and_reasoning_siblings():
    assert resolve_tiered_model("claude-sonnet-5", "fast") == "claude-haiku-4-5-20251001"
    assert resolve_tiered_model("claude-sonnet-5", "reasoning") == "claude-opus-5"


def test_resolving_from_a_non_default_family_member_still_works():
    # An org that configured the family's *fast* or *reasoning* member
    # as their one baseline model still resolves every tier correctly,
    # not just "up" or "down" from whatever they happened to type in.
    assert resolve_tiered_model("claude-opus-5", "fast") == "claude-haiku-4-5-20251001"
    assert resolve_tiered_model("claude-haiku-4-5-20251001", "reasoning") == "claude-opus-5"


def test_openai_family_resolves_fast_and_reasoning_siblings():
    assert resolve_tiered_model("gpt-5", "fast") == "gpt-5-mini"
    assert resolve_tiered_model("gpt-5", "reasoning") == "gpt-5-pro"


def test_grok_family_resolves_fast_sibling_reasoning_matches_default():
    assert resolve_tiered_model("grok-4", "fast") == "grok-4-fast"
    # No confirmed premium tier above default for this family — reasoning
    # intentionally matches default rather than guessing an id.
    assert resolve_tiered_model("grok-4", "reasoning") == "grok-4"


def test_unrecognized_model_falls_back_unchanged_for_every_tier():
    # Gemini (deliberately not in the family table — see module
    # docstring) and any custom/self-hosted gateway model both hit this
    # same safe path: never guess a sibling model name that might not
    # exist on the org's account.
    for tier in ("fast", "default", "reasoning"):
        assert resolve_tiered_model("gemini-2.5-pro", tier) == "gemini-2.5-pro"
        assert resolve_tiered_model("my-internal-llama-gateway", tier) == "my-internal-llama-gateway"
