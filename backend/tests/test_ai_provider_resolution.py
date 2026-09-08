import uuid

import pytest

from app.ai.adapters.claude import ClaudeAdapter
from app.ai.adapters.gemini import GeminiAdapter
from app.ai.adapters.generic_openai import GenericOpenAIAdapter
from app.ai.adapters.grok import GrokAdapter
from app.ai.adapters.null import NullAIProviderAdapter
from app.ai.adapters.openai import OpenAIAdapter
from app.ai.provider import build_adapter_from_config, get_ai_provider, resolve_provider_and_model
from app.config import get_settings
from app.models.ai_provider_config import AIProviderConfig
from app.models.scan import ScanRun
from app.vault.credential_vault import encrypt_secret
from tests.conftest import session_scope


async def test_resolve_falls_back_to_global_default_when_no_config_attached(db_adapter, monkeypatch):
    # get_ai_provider() (the fallback this test exercises) reads the real
    # deployment-wide AI_PROVIDER setting — this dev environment has that
    # set to "claude" for actual live scanning against DVWA, not the
    # fresh-checkout "fake" default, so asserting on its real return type
    # here would be asserting on ambient environment config rather than on
    # resolve_provider_and_model's own fallback logic. Patch the one
    # dependency actually under test instead of assuming env state.
    import app.ai.provider as provider_module

    monkeypatch.setattr(provider_module, "get_ai_provider", lambda: NullAIProviderAdapter())

    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(version_id=uuid.uuid4(), status="pending", requested_by=uuid.uuid4())
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        provider, model = await resolve_provider_and_model(session, scan_run)
        assert isinstance(provider, NullAIProviderAdapter)
        assert model  # global default ai_model string


async def test_resolve_uses_attached_custom_provider_config(db_adapter):
    async with session_scope(db_adapter) as session:
        config = AIProviderConfig(
            org_id=uuid.uuid4(),
            label="In-house",
            provider="custom",
            model="llama3.1:8b",
            base_url="http://localhost:11434/v1",
            encrypted_api_key=encrypt_secret("sk-abc"),
            masked_reference="****abc",
        )
        session.add(config)
        await session.commit()
        await session.refresh(config)

        scan_run = ScanRun(
            version_id=uuid.uuid4(),
            status="pending",
            requested_by=uuid.uuid4(),
            ai_provider_config_id=config.id,
        )
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        provider, model = await resolve_provider_and_model(session, scan_run)
        assert isinstance(provider, GenericOpenAIAdapter)
        assert model == "llama3.1:8b"


async def test_resolve_falls_back_when_attached_config_was_deleted(db_adapter, monkeypatch):
    # Same reasoning as test_resolve_falls_back_to_global_default_when_no_config_attached
    # above — isolate from this environment's real AI_PROVIDER setting.
    import app.ai.provider as provider_module

    monkeypatch.setattr(provider_module, "get_ai_provider", lambda: NullAIProviderAdapter())

    async with session_scope(db_adapter) as session:
        scan_run = ScanRun(
            version_id=uuid.uuid4(),
            status="pending",
            requested_by=uuid.uuid4(),
            ai_provider_config_id=uuid.uuid4(),  # no such config
        )
        session.add(scan_run)
        await session.commit()
        await session.refresh(scan_run)

        provider, _model = await resolve_provider_and_model(session, scan_run)
        assert isinstance(provider, NullAIProviderAdapter)


def test_get_ai_provider_builds_generic_openai_adapter_for_custom(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "ai_provider", "custom")
    monkeypatch.setattr(settings, "custom_llm_base_url", "http://localhost:11434/v1")
    monkeypatch.setattr(settings, "custom_llm_api_key", "sk-internal")
    monkeypatch.setattr(settings, "custom_llm_auth_type", "bearer_token")
    get_ai_provider.cache_clear()
    try:
        assert isinstance(get_ai_provider(), GenericOpenAIAdapter)
    finally:
        get_ai_provider.cache_clear()


def test_get_ai_provider_custom_requires_base_url(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "ai_provider", "custom")
    monkeypatch.setattr(settings, "custom_llm_base_url", None)
    get_ai_provider.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="CUSTOM_LLM_BASE_URL"):
            get_ai_provider()
    finally:
        get_ai_provider.cache_clear()


def test_build_adapter_from_config_maps_claude():
    config = AIProviderConfig(
        org_id=uuid.uuid4(),
        label="Claude",
        provider="claude",
        model="claude-haiku-4-5",
        base_url=None,
        encrypted_api_key=encrypt_secret("sk-ant-abc"),
        masked_reference="****",
    )
    adapter = build_adapter_from_config(config)
    assert isinstance(adapter, ClaudeAdapter)


def test_build_adapter_from_config_maps_openai():
    config = AIProviderConfig(
        org_id=uuid.uuid4(),
        label="OpenAI",
        provider="openai",
        model="gpt-4o-mini",
        base_url=None,
        encrypted_api_key=encrypt_secret("sk-oai-abc"),
        masked_reference="****",
    )
    assert isinstance(build_adapter_from_config(config), OpenAIAdapter)


def test_build_adapter_from_config_maps_gemini():
    config = AIProviderConfig(
        org_id=uuid.uuid4(),
        label="Gemini",
        provider="gemini",
        model="gemini-2.0-flash",
        base_url=None,
        encrypted_api_key=encrypt_secret("g-key"),
        masked_reference="****",
    )
    assert isinstance(build_adapter_from_config(config), GeminiAdapter)


def test_build_adapter_from_config_maps_grok():
    config = AIProviderConfig(
        org_id=uuid.uuid4(),
        label="Grok",
        provider="grok",
        model="grok-2",
        base_url=None,
        encrypted_api_key=encrypt_secret("xai-key"),
        masked_reference="****",
    )
    assert isinstance(build_adapter_from_config(config), GrokAdapter)


def test_build_adapter_from_config_honors_bearer_token_auth_type_for_custom():
    config = AIProviderConfig(
        org_id=uuid.uuid4(),
        label="In-house bearer",
        provider="custom",
        model="llama3.1:8b",
        base_url="http://localhost:11434/v1",
        auth_type="bearer_token",
        encrypted_api_key=encrypt_secret("sk-abc"),
        masked_reference="****abc",
    )
    adapter = build_adapter_from_config(config)
    assert isinstance(adapter, GenericOpenAIAdapter)


def test_build_adapter_from_config_honors_api_key_auth_type_for_custom():
    config = AIProviderConfig(
        org_id=uuid.uuid4(),
        label="In-house api-key header",
        provider="custom",
        model="llama3.1:8b",
        base_url="http://localhost:11434/v1",
        auth_type="api_key",
        encrypted_api_key=encrypt_secret("sk-abc"),
        masked_reference="****abc",
    )
    adapter = build_adapter_from_config(config)
    assert isinstance(adapter, GenericOpenAIAdapter)
