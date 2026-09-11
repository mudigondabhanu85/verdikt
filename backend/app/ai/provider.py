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
from app.ai.adapters.spark import SparkAdapter
from app.ai.model_routing import ModelRouter
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
    if settings.ai_provider == "spark":
        if settings.spark_environment == "uat":
            base_url = settings.spark_uat_base_url
            api_version = settings.spark_uat_api_version or settings.spark_api_version
            app_id = settings.spark_uat_app_id or settings.spark_app_id
            auth_mode = settings.spark_uat_auth_mode or settings.spark_auth_mode
            bearer_token = settings.spark_uat_bearer_token
            api_key = settings.spark_uat_api_key
            api_key_secondary = settings.spark_uat_api_key_secondary
        else:
            base_url = settings.spark_base_url
            api_version = settings.spark_api_version
            app_id = settings.spark_app_id
            auth_mode = settings.spark_auth_mode
            bearer_token = settings.spark_bearer_token
            api_key = settings.spark_api_key
            api_key_secondary = settings.spark_api_key_secondary

        token = bearer_token if auth_mode == "bearer_token" else api_key
        if not token:
            env_prefix = "SPARK_UAT_" if settings.spark_environment == "uat" else "SPARK_"
            raise RuntimeError(
                f"ai_provider=spark (environment={settings.spark_environment!r}) requires "
                f"{env_prefix}BEARER_TOKEN (auth_mode=bearer_token, the default) or "
                f"{env_prefix}API_KEY (auth_mode=api_key) to be set"
            )
        # App ID is required for EVERY Spark request, bearer or api_key
        # (empirically re-confirmed 2026-09 — a prior version of this
        # comment claimed bearer tokens didn't need one; that was wrong).
        # SparkAdapter builds its endpoint as base_url/v1/{app_id} via
        # AsyncAzureOpenAI, which then appends its own hardcoded
        # /openai/deployments/{model}/... suffix on top. Omit app_id and
        # that endpoint becomes base_url/v1 — Spark's gateway then reads
        # the SDK's own literal "openai" path segment as if it were the
        # app_id and rejects it ("app_id: openai is not valid"), which is
        # exactly the incident that got this fixed for good: a raw curl
        # against Spark's bare /v1/chat/completions got the same
        # treatment ("app_id: chat is not valid") — proving the gateway
        # always reads *something* out of that path slot, app_id or not.
        if not app_id:
            env_prefix = "SPARK_UAT_" if settings.spark_environment == "uat" else "SPARK_"
            raise RuntimeError(
                f"ai_provider=spark (environment={settings.spark_environment!r}) requires "
                f"{env_prefix}APP_ID to be set — Spark's gateway needs it for every request, "
                "bearer token or API key alike."
            )
        return SparkAdapter(
            token,
            base_url=base_url,
            api_version=api_version,
            app_id=app_id,
            fallback_token=(api_key_secondary if auth_mode == "api_key" else None),
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
    if config.provider == "spark":
        # api_key here is whatever the analyst pasted in — a bearer token
        # or a long-lived (primary) API key. base_url/api_version/app_id
        # are all deployment-wide constants unless this row overrides
        # them for an org on a different Spark tenant — mirrors
        # dast-automation's SparkConfig, where app_id ("default_app_id")
        # is registered once for the whole deployment (this app calling
        # Spark), not something an individual analyst's bearer token
        # carries. A per-config app_id override still wins when set (an
        # org on its own Spark tenant), but most orgs will never set
        # one — they just get the deployment's SPARK_APP_ID.
        settings = get_settings()
        return SparkAdapter(
            api_key,
            base_url=config.base_url or settings.spark_base_url,
            api_version=settings.spark_api_version,
            app_id=config.app_id or settings.spark_app_id,
            fallback_token=(
                decrypt_secret(config.encrypted_secondary_api_key)
                if config.encrypted_secondary_api_key
                else None
            ),
        )
    raise ValueError(f"Unknown AIProviderConfig.provider: {config.provider!r}")


async def resolve_provider_and_model(
    session: AsyncSession, scan_run: ScanRun
) -> tuple[AIProviderAdapter, ModelRouter]:
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
    """
    if scan_run.ai_provider_config_id is not None:
        config = await session.get(AIProviderConfig, scan_run.ai_provider_config_id)
        if config is not None:
            logger.info(
                "ai_provider_resolved via=scan_run_explicit_config scan_run_id=%s config_id=%s "
                "provider=%s label=%r",
                scan_run.id, config.id, config.provider, config.label,
            )
            return build_adapter_from_config(config), _model_router_from_config(config)
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
            return build_adapter_from_config(default_config), _model_router_from_config(default_config)
        logger.warning(
            "ai_provider_resolved via=deployment_env_fallback scan_run_id=%s org_id=%s "
            "reason=no_default_config_for_org ai_provider=%s",
            scan_run.id, org_id, get_settings().ai_provider,
        )

    return get_ai_provider(), ModelRouter.single_model(get_settings().ai_model)


def _model_router_from_config(config: AIProviderConfig) -> ModelRouter:
    """A config only has to set `model`; the two tier overrides are
    optional, so an org that never touches them keeps the pre-routing
    behavior of one model for every task.
    """
    return ModelRouter(
        specialist=config.model,
        reasoning=config.model_reasoning or config.model,
        classification=config.model_classification or config.model,
    )
