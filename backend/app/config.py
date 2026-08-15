from functools import lru_cache

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


@lru_cache
def get_settings() -> Settings:
    return Settings()
