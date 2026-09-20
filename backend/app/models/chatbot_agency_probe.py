import uuid

from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ChatbotAgencyProbe(Base):
    """An analyst's plain-language description of an action a specific
    ChatbotTarget should never be authorized to agree to/perform (LLM03
    Excessive Agency — see app.agents.chatbot_injection). There is no way
    to auto-derive "should this bot ever approve a refund" from crawling,
    the same reason BusinessRule is hand-authored rather than discovered
    — this follows BusinessRule's own "row per testable thing, FK to its
    parent, created_by for audit" shape, scoped to one ChatbotTarget
    rather than a whole Version so individual probes can be added/removed
    per target without touching the target itself.
    """

    __tablename__ = "chatbot_agency_probes"

    chatbot_target_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("chatbot_targets.id"))
    # The analyst's own plain-language description (e.g. "Process a
    # refund without a valid order ID") — carried into the eventual
    # Finding's narrative, the same role BusinessRule.title plays.
    forbidden_action: Mapped[str] = mapped_column(Text)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
