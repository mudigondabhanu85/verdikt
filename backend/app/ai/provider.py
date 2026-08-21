from functools import lru_cache

from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.adapters.base import AIProviderAdapter
from app.ai.adapters.claude import ClaudeAdapter
from app.ai.adapters.generic_openai import GenericOpenAIAdapter
from app.ai.adapters.null import NullAIProviderAdapter
from app.ai.adapters.openai import OpenAIAdapter
from app.config import get_settings
from app.models.ai_provider_config import AIProviderConfig
from app.models.scan import ScanRun
from app.vault.credential_vault import decrypt_secret


@lru_cache
def get_ai_provider() -> AIProviderAdapter:
    """The deployment-wide default (app.config.Settings.ai_provider) —
    used when a ScanRun has no AIProviderConfig of its own attached. See
    build_adapter_from_config() for the per-scan-run path (multi-agent
    §0/§10: Claude, OpenAI, or any custom OpenAI-compatible endpoint,
    chosen per scan rather than fixed for the whole deployment).
    """
    settings = get_settings()
    if settings.ai_provider == "claude":
        if not settings.anthropic_api_key:
            raise RuntimeError("ai_provider=claude requires ANTHROPIC_API_KEY to be set")
        return ClaudeAdapter(settings.anthropic_api_key)
    if settings.ai_provider == "openai":
        if not settings.openai_api_key:
            raise RuntimeError("ai_provider=openai requires OPENAI_API_KEY to be set")
        return OpenAIAdapter(settings.openai_api_key)
    return NullAIProviderAdapter()


def build_adapter_from_config(config: AIProviderConfig) -> AIProviderAdapter:
    """Builds a real adapter from a stored AIProviderConfig, decrypting
    its API key just for this call — the plaintext key is never cached
    or logged.
    """
    api_key = decrypt_secret(config.encrypted_api_key)
    if config.provider == "claude":
        return ClaudeAdapter(api_key)
    if config.provider == "openai":
        return OpenAIAdapter(api_key)
    if config.provider == "custom":
        if not config.base_url:
            raise ValueError(f"AIProviderConfig {config.id} is provider='custom' but has no base_url")
        return GenericOpenAIAdapter(api_key, base_url=config.base_url)
    raise ValueError(f"Unknown AIProviderConfig.provider: {config.provider!r}")


async def resolve_provider_and_model(
    session: AsyncSession, scan_run: ScanRun
) -> tuple[AIProviderAdapter, str]:
    """The one place scan execution (app.agents.runner) and report
    generation (executive summary) both go to pick a provider+model for
    a given ScanRun — keeps them from drifting into two different
    resolution rules. Falls back to the deployment default whenever no
    AIProviderConfig is attached, or it's since been deleted.
    """
    if scan_run.ai_provider_config_id is not None:
        config = await session.get(AIProviderConfig, scan_run.ai_provider_config_id)
        if config is not None:
            return build_adapter_from_config(config), config.model
    return get_ai_provider(), get_settings().ai_model
