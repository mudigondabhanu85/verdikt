import uuid

from sqlalchemy import ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# "custom" covers Cursor-style/in-house LLMs and any other server that
# speaks the OpenAI chat-completions protocol — see
# app.ai.adapters.generic_openai.GenericOpenAIAdapter.
AI_PROVIDER_TYPES = ("claude", "openai", "custom")


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
    # Required (and only meaningful) when provider == "custom".
    base_url: Mapped[str | None] = mapped_column(String(500))
    encrypted_api_key: Mapped[bytes] = mapped_column(LargeBinary)
    masked_reference: Mapped[str] = mapped_column(String(255))
