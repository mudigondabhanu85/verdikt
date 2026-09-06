import uuid

from sqlalchemy import ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# "custom" covers Cursor-style/in-house LLMs and any other server that
# speaks the OpenAI chat-completions protocol — see
# app.ai.adapters.generic_openai.GenericOpenAIAdapter. "gemini" and "grok"
# are named presets with their own pricing tables (app.ai.adapters.gemini /
# .grok); grok's API is itself OpenAI-compatible under the hood, but gets
# a named adapter for UX clarity and correct xAI pricing rather than
# making the analyst configure it as an anonymous "custom" endpoint.
AI_PROVIDER_TYPES = ("claude", "openai", "gemini", "grok", "custom")
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
    model: Mapped[str] = mapped_column(String(100))
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
