import logging
from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.adapters.base import AIProviderAdapter
from app.ai.adapters.claude import ClaudeAdapter
from app.ai.adapters.gemini import GeminiAdapter
from app.ai.adapters.generic_openai import GenericOpenAIAdapter
from app.ai.adapters.grok import GrokAdapter
from app.ai.adapters.null import NullAIProviderAdapter
from app.ai.adapters.openai import OpenAIAdapter
from app.config import get_settings
from app.models.ai_provider_config import AIProviderConfig
from app.models.project import Project, Version
from app.models.scan import ScanRun
from app.vault.credential_vault import decrypt_secret

logger = logging.getLogger(__name__)


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
    if settings.ai_provider == "custom":
        if not settings.custom_llm_base_url:
            raise RuntimeError("ai_provider=custom requires CUSTOM_LLM_BASE_URL to be set")
        return GenericOpenAIAdapter(
            settings.custom_llm_api_key or "unused",
            base_url=settings.custom_llm_base_url,
            auth_type=settings.custom_llm_auth_type,
        )
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
    if config.provider == "gemini":
        return GeminiAdapter(api_key, base_url=config.base_url or "https://generativelanguage.googleapis.com")
    if config.provider == "grok":
        return GrokAdapter(api_key)
    if config.provider == "custom":
        if not config.base_url:
            raise ValueError(f"AIProviderConfig {config.id} is provider='custom' but has no base_url")
        return GenericOpenAIAdapter(api_key, base_url=config.base_url, auth_type=config.auth_type)
    raise ValueError(f"Unknown AIProviderConfig.provider: {config.provider!r}")


async def resolve_provider_and_model(
    session: AsyncSession, scan_run: ScanRun
) -> tuple[AIProviderAdapter, str]:
    """The one place scan execution (app.agents.runner) and report
    generation (executive summary) both go to pick a provider+model for
    a given ScanRun — keeps them from drifting into two different
    resolution rules. Resolution order:

    1. The ScanRun's own explicitly-attached AIProviderConfig, if any
       (and it hasn't since been deleted).
    2. The org's default AIProviderConfig, if one has been set (Account
       page -> AI Provider Configs -> "Set as default") — the UI-only
       path: an org registers its own LLM (Claude, OpenAI, or any
       in-house OpenAI-compatible gateway) once, with no .env editing.
    3. The deployment-wide AI_PROVIDER .env setting — the final
       fallback for an org that hasn't configured one of its own.

    This is still the one model an org configures — no per-task manual
    model routing to set up or maintain. app.agents.graph and
    app.api.routes.scans automatically substitute a same-family
    sibling of this model (app.ai.model_tiers) for a small number of
    specific tasks that are either much higher-volume/simpler or much
    more complex/lower-volume than everything else, but that happens
    entirely on the backend — this function itself always returns
    exactly the model the org configured, unchanged.
    """
    if scan_run.ai_provider_config_id is not None:
        config = await session.get(AIProviderConfig, scan_run.ai_provider_config_id)
        if config is not None:
            logger.info(
                "ai_provider_resolved via=scan_run_explicit_config scan_run_id=%s config_id=%s "
                "provider=%s label=%r",
                scan_run.id, config.id, config.provider, config.label,
            )
            return build_adapter_from_config(config), config.model
        logger.warning(
            "ai_provider_config_id=%s attached to scan_run_id=%s no longer exists — "
            "falling through to org default / deployment .env",
            scan_run.ai_provider_config_id, scan_run.id,
        )

    org_id_result = await session.execute(
        select(Project.org_id).join(Version, Version.project_id == Project.id).where(
            Version.id == scan_run.version_id
        )
    )
    org_id = org_id_result.scalar_one_or_none()
    if org_id is None:
        logger.warning(
            "ai_provider_resolved via=deployment_env_fallback scan_run_id=%s reason=no_org_found_for_version "
            "version_id=%s ai_provider=%s",
            scan_run.id, scan_run.version_id, get_settings().ai_provider,
        )
    if org_id is not None:
        default_result = await session.execute(
            select(AIProviderConfig).where(
                AIProviderConfig.org_id == org_id, AIProviderConfig.is_default.is_(True)
            )
        )
        default_config = default_result.scalar_one_or_none()
        if default_config is not None:
            logger.info(
                "ai_provider_resolved via=org_default_config scan_run_id=%s org_id=%s config_id=%s "
                "provider=%s label=%r",
                scan_run.id, org_id, default_config.id, default_config.provider, default_config.label,
            )
            return build_adapter_from_config(default_config), default_config.model
        logger.warning(
            "ai_provider_resolved via=deployment_env_fallback scan_run_id=%s org_id=%s "
            "reason=no_default_config_for_org ai_provider=%s",
            scan_run.id, org_id, get_settings().ai_provider,
        )

    return get_ai_provider(), get_settings().ai_model
