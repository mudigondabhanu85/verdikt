import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# "custom" covers Cursor-style/in-house LLMs and any other server that
# speaks the OpenAI chat-completions protocol — see
# app.ai.adapters.generic_openai.GenericOpenAIAdapter. "gemini" and "grok"
# are named presets with their own pricing tables (app.ai.adapters.gemini /
# .grok); grok's API is itself OpenAI-compatible under the hood, but gets
# a named adapter for UX clarity and correct xAI pricing rather than
# making the analyst configure it as an anonymous "custom" endpoint.
AI_PROVIDER_TYPES = ("claude", "openai", "gemini", "grok", "custom", "spark")
AI_PROVIDER_AUTH_TYPES = ("api_key", "bearer_token")


class AIProviderConfig(Base):
    """A named, reusable LLM provider configuration (multi-agent §0/§10 —
    lets an org register Claude, OpenAI, and/or any number of custom
    OpenAI-compatible endpoints, then pick one per scan run instead of
    being locked to a single global env-var setting). The API key is
    always envelope-encrypted, same discipline as CredentialSet
    (app.vault) — never persisted or returned as plaintext.
    """

    __tablename__ = "ai_provider_configs"

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    label: Mapped[str] = mapped_column(String(100))
    provider: Mapped[str] = mapped_column(String(20))
    # The specialist-tier model (injection/XSS/access-control-style
    # agents) — also the fallback for the two tiers below when an org
    # hasn't bothered picking distinct models, so a config keeps working
    # exactly as before if it only ever sets this one field.
    model: Mapped[str] = mapped_column(String(100))
    # Optional per-tier overrides — a single provider account (e.g. one
    # Spark app_id) can usually reach several model sizes, so route
    # heavy reasoning (business-logic hypothesis generation, attack-chain
    # analysis, adversarial finding validation) to a stronger/costlier
    # model and cheap mechanical classification to a smaller/faster one,
    # instead of paying reasoning-model prices for every single call.
    # See app.ai.model_routing.ModelRouter / AGENT_ROLE_TIER.
    model_reasoning: Mapped[str | None] = mapped_column(String(100))
    model_classification: Mapped[str | None] = mapped_column(String(100))
    # Required (and only meaningful) when provider == "custom" — a
    # self-hosted/in-house model's base URL (vLLM, Ollama, LM Studio, TGI,
    # etc.), or an override base URL for a named provider.
    base_url: Mapped[str | None] = mapped_column(String(500))
    # Which header shape the secret below is sent as — an "api_key"-style
    # provider header (e.g. Claude's x-api-key, Gemini's ?key=) vs. a
    # standard "Authorization: Bearer <token>" header, which is what most
    # self-hosted/in-house endpoints expect. Analyst picks explicitly
    # rather than the tool guessing from the provider name.
    auth_type: Mapped[str] = mapped_column(String(20), default="api_key")
    encrypted_api_key: Mapped[bytes] = mapped_column(LargeBinary)
    masked_reference: Mapped[str] = mapped_column(String(255))
    # Set whenever the secret is created/rotated — lets the UI show a
    # real "expires at HH:MM" for Spark's ~60-minute bearer tokens
    # instead of the token silently going stale mid-scan with no
    # visible warning (a real incident: a scan resolved its provider
    # once at start using a token that had already expired by the time
    # LLM-dependent nodes ran, silently skipping every one of them —
    # zero tokens/cost recorded, no obvious error). Meaningless for
    # non-expiring secrets (a real API key), so the UI only surfaces an
    # expiry countdown for provider="spark" auth_type="bearer_token".
    secret_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Spark-only (both nullable — every other provider leaves them unset).
    # app_id overrides the deployment-wide SPARK_APP_ID setting for this
    # org's Spark tenant. encrypted_secondary_api_key, if set, lets
    # SparkAdapter retry once on a 401 with a second key before failing
    # the call outright — same rationale as dast-automation's
    # primary/secondary key rotation, without that reference's full
    # admin-rotation UI.
    app_id: Mapped[str | None] = mapped_column(String(100))
    encrypted_secondary_api_key: Mapped[bytes | None] = mapped_column(LargeBinary)
    # The org-wide fallback used by resolve_provider_and_model whenever a
    # scan doesn't specify its own AIProviderConfig — lets an org
    # configure "any LLM can be patched in" entirely from this UI, no
    # .env editing needed. At most one per org (enforced by a partial
    # unique index — see the migration); setting a new default atomically
    # unsets whichever one was previously default.
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)

    @property
    def has_secondary_api_key(self) -> bool:
        # AIProviderConfigOut.from_attributes reads this like any other
        # column — never expose the secondary key's ciphertext itself,
        # only whether one is configured.
        return self.encrypted_secondary_api_key is not None
