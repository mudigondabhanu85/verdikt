from decimal import Decimal
from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Postgres is the documented default (docker-compose); tests may point this at
    # SQLite since the DB layer stays ORM/dialect-agnostic (see app/db).
    database_url: str = "postgresql+psycopg://verdikt:verdikt@localhost:5432/verdikt"

    jwt_secret: str = "dev-only-change-me-to-something-random-and-32-bytes-plus"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 12

    # Dev-only symmetric key for LocalKMSAdapter (Fernet). Production must swap in a
    # real KMSAdapter (AWS KMS / Azure Key Vault) — see app/vault/kms_adapter.py.
    vault_master_key: str = "dev-only-insecure-fernet-key-000000000000="

    object_storage_root: str = "./data/objects"

    # AI provider selection (§0/§10). Defaults to "fake" — a fresh checkout
    # with no API keys runs LLM-dependent agents (injection/xss/access-control
    # triage+validation) against a no-op adapter that finds nothing, rather
    # than crashing. Set to "claude"/"openai" + the matching API key for
    # real reasoning.
    ai_provider: Literal["claude", "openai", "fake"] = "fake"
    ai_model: str = "claude-haiku-4-5"
    anthropic_api_key: str | None = None
    openai_api_key: str | None = None

    # §10.5 visible budget guardrail — per-scan-run cap on estimated LLM
    # spend. Once exceeded, remaining LLM-dependent agent nodes are skipped
    # (recorded on their AgentJob), not silently truncated.
    max_llm_cost_usd_per_scan: Decimal = Decimal("2.00")


@lru_cache
def get_settings() -> Settings:
    return Settings()
