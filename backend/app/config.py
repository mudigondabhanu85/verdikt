from decimal import Decimal
from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Postgres is the documented default (docker-compose); tests may point this at
    # SQLite since the DB layer stays ORM/dialect-agnostic (see app/db).
    database_url: str = "postgresql+psycopg://verdikt:verdikt@localhost:5432/verdikt"

    # §7 frontend — the Vite dev server (and, in production, wherever the
    # built frontend is actually served from) runs on a different origin
    # than the API, so the browser needs an explicit CORS allow-list.
    # Bearer-token auth (never cookies) means allow_credentials=False is
    # correct in app/main.py — no credentialed-CORS complexity needed.
    frontend_origin: str = "http://localhost:5173"

    jwt_secret: str = "dev-only-change-me-to-something-random-and-32-bytes-plus"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 12

    # Dev-only symmetric key for LocalKMSAdapter (Fernet). Production must swap in a
    # real KMSAdapter (AWS KMS / Azure Key Vault) — see app/vault/kms_adapter.py.
    vault_master_key: str = "dev-only-insecure-fernet-key-000000000000="

    # §9 enterprise hardening: swap in AwsKmsAdapter for real key custody.
    # "local" (LocalKMSAdapter, Fernet) remains the default so a fresh
    # checkout with no AWS credentials still runs.
    kms_provider: Literal["local", "aws"] = "local"
    aws_kms_key_id: str | None = None

    object_storage_root: str = "./data/objects"

    # §9 enterprise hardening: swap in S3ObjectStorage for a real,
    # multi-instance-safe object store. "local" (LocalDiskObjectStorage)
    # remains the default for a fresh checkout with no AWS credentials.
    object_storage_provider: Literal["local", "s3"] = "local"
    aws_s3_bucket: str | None = None
    aws_region: str = "us-east-1"

    # AI provider selection (§0/§10). Defaults to "fake" — a fresh checkout
    # with no API keys runs LLM-dependent agents (injection/xss/access-control
    # triage+validation) against a no-op adapter that finds nothing, rather
    # than crashing. Set to "claude"/"openai" + the matching API key for
    # real reasoning, or "custom" for any self-hosted/in-house
    # OpenAI-chat-completions-compatible endpoint (the same GenericOpenAIAdapter
    # an org's own AIProviderConfig rows already use per-scan — this is just
    # the deployment-wide default, for when nothing overrides it per scan run).
    ai_provider: Literal["claude", "openai", "custom", "spark", "fake"] = "fake"
    ai_model: str = "claude-haiku-4-5"
    anthropic_api_key: str | None = None
    openai_api_key: str | None = None
    custom_llm_base_url: str | None = None
    custom_llm_api_key: str | None = None
    # "bearer_token" (default): sends "Authorization: Bearer <key>" — what
    # most self-hosted/in-house OpenAI-compatible servers (vLLM, Ollama,
    # LM Studio, TGI) and most internal LLM gateways expect. "api_key":
    # sends the key in a raw "api-key" header instead, for gateways that
    # use that convention. See GenericOpenAIAdapter.
    custom_llm_auth_type: Literal["bearer_token", "api_key"] = "bearer_token"

    # Spark — S&P Global's internal Azure-OpenAI-compatible LLM gateway
    # (ported from the dast-automation reference implementation's
    # SparkProvider). Set ai_provider="spark" plus one of
    # spark_bearer_token/spark_api_key below to use it as the
    # deployment-wide default. See app.ai.adapters.spark.SparkAdapter for
    # why both auth modes are sent as the same "api-key"+"app_id" header
    # pair rather than a real Authorization header.
    spark_base_url: str = "https://sparkapi.spglobal.com"
    spark_api_version: str = "2024-02-01"
    # Required for every Spark request, bearer token or API key alike
    # (see SparkAdapter's docstring — re-confirmed 2026-09 directly
    # against the gateway). "sparkassist" is dast-automation's own
    # confirmed-working deployment-wide default (its config.py's
    # hardcoded default AND its README's documented current value) —
    # copied here rather than guessed. A prior version of this comment
    # removed that default on a mistaken theory that it was the actual
    # root cause of an unrelated app_id incident (that incident was a
    # per-org api_key-mode app_id being wrong for its Spark tenant, not
    # this deployment-wide bearer-mode default being wrong).
    spark_app_id: str | None = "sparkassist"
    # Selects which field below get_ai_provider() reads the token from —
    # does not change the header shape sent to Spark (see SparkAdapter).
    spark_auth_mode: Literal["bearer_token", "api_key"] = "bearer_token"
    spark_bearer_token: str | None = None
    spark_api_key: str | None = None
    # api_key mode only — a second, independent Spark API key SparkAdapter
    # retries with once if the primary key gets a 401 (see SparkAdapter's
    # fallback_token). None means "no fallback configured", the same as
    # today's behavior.
    spark_api_key_secondary: str | None = None

    # Spark has two separate tenants (PROD/UAT), each with its own
    # app_id/key registrations — an app_id valid on one gets Spark's own
    # "The provided app_id: ... is not valid" 401 on the other. Mirrors
    # dast-automation's SparkConfig.for_environment: one provider, one
    # "spark" key, just a second base_url/credential set to pick between,
    # never a second registered provider. Empty api_version/app_id below
    # means "inherit the prod value" (S&P's own UAT tenant uses the same
    # ones in practice unless told otherwise).
    spark_environment: Literal["prod", "uat"] = "prod"
    spark_uat_base_url: str = "https://sparkuatapi.spglobal.com"
    spark_uat_api_version: str | None = None
    spark_uat_app_id: str | None = None
    spark_uat_auth_mode: Literal["bearer_token", "api_key"] | None = None
    spark_uat_bearer_token: str | None = None
    spark_uat_api_key: str | None = None
    spark_uat_api_key_secondary: str | None = None

    # §10.5 visible budget guardrail — per-scan-run cap on estimated LLM
    # spend. Once exceeded, remaining LLM-dependent agent nodes are skipped
    # (recorded on their AgentJob), not silently truncated.
    max_llm_cost_usd_per_scan: Decimal = Decimal("2.00")

    # §3 SSRF detection (app/agents/ssrf.py) needs a hostname/IP the
    # *target* can route back to for its out-of-band callback proof —
    # this only works when the scanner is reachable from the target
    # (same Docker network, same LAN, or a scanner with a public
    # hostname). None means "best-effort auto-detect the local machine's
    # own address", which is enough for same-network targets like a
    # local Juice Shop instance but not for an internet-hosted target.
    ssrf_callback_host: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
