import uuid

from sqlalchemy import ForeignKey, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ChatbotTarget(Base):
    """A conversational endpoint an analyst has explicitly configured for
    chatbot/LLM pentesting (Phase 1 of the OWASP LLM Top 10 checklist —
    see app.agents.chatbot_injection). No auto-discovery is possible for
    "this endpoint is a chat interface", so unlike Target/scope this is
    always hand-authored, the same reason CredentialSet and BusinessRule
    are hand-authored.
    """

    __tablename__ = "chatbot_targets"

    version_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("versions.id"))
    label: Mapped[str] = mapped_column(String(200))
    endpoint_url: Mapped[str] = mapped_column(String(500))
    http_method: Mapped[str] = mapped_column(String(10), default="POST")
    # Must contain a literal "{message}" placeholder — the same
    # {placeholder} string-substitution convention CredentialSet.
    # login_body_template already uses elsewhere in this codebase.
    # Validated at the API layer (app.schemas.chatbot_target).
    request_body_template: Mapped[str] = mapped_column(Text)
    content_type: Mapped[str] = mapped_column(String(100), default="application/json")
    # Dot-path into the JSON response naming where the reply text lives
    # (e.g. "reply", "choices.0.message.content") — walked by
    # app.integrations.cmdb.client._read_json_path, reused as-is.
    response_text_path: Mapped[str] = mapped_column(String(200))
    # Auth is optional — a public chat widget needs none. Envelope-
    # encrypted the same way every other integration's secret is
    # (app.vault.credential_vault) when present.
    auth_header_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    encrypted_auth_header_value: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    masked_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
