from functools import lru_cache

from app.ai.adapters.base import AIProviderAdapter
from app.ai.adapters.claude import ClaudeAdapter
from app.ai.adapters.null import NullAIProviderAdapter
from app.ai.adapters.openai import OpenAIAdapter
from app.config import get_settings


@lru_cache
def get_ai_provider() -> AIProviderAdapter:
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
