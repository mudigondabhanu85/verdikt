import uuid

from app.ai.adapters.claude import ClaudeAdapter
from app.ai.adapters.generic_openai import GenericOpenAIAdapter
from app.ai.adapters.null import NullAIProviderAdapter
from app.ai.provider import build_adapter_from_config, resolve_provider_and_model
from app.models.ai_provider_config import AIProviderConfig
from app.models.scan import ScanRun
from app.vault.credential_vault import encrypt_secret
from tests.conftest import session_scope


async def test_resolve_falls_back_to_global_default_when_no_config_attached(db_adapter):
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


async def test_resolve_falls_back_when_attached_config_was_deleted(db_adapter):
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
