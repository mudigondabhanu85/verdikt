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
    ai_provider: Literal["claude", "openai", "custom", "fake"] = "fake"
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

    # Crawl bounds (app.agents.recon.ReconAgent) — deliberately
    # configurable rather than hardcoded, since 300 pages at depth 6 is a
    # substantial jump from this project's original 40/2 and can run
    # meaningfully longer/heavier against a large or rate-limited target
    # than an analyst may expect by default. Override per-deployment
    # (e.g. dial back for a smaller/rate-sensitive target) without a
    # code change.
    crawl_max_pages: int = 300
    crawl_max_depth: int = 6

    # Filesystem path to the standalone login-macro-recorder browser
    # extension's source (browser-extension/ at the repo root — a
    # sibling of backend/, not a package inside it), zipped on demand by
    # app.api.routes.browser_extension for the "Download extension"
    # button next to Record macro (§ MacroSection.tsx). Relative paths
    # resolve against the backend process's own working directory: "cd
    # backend && uv run uvicorn ..." (the documented local-dev command)
    # makes "../browser-extension" correct without any override: In
    # Docker the backend container only bind-mounts ./backend (see
    # docker-compose.yml), so browser-extension/ needs its own mount —
    # done there at /browser-extension, with this setting overridden to
    # match via BROWSER_EXTENSION_SOURCE_DIR.
    browser_extension_source_dir: str = "../browser-extension"


@lru_cache
def get_settings() -> Settings:
    return Settings()
