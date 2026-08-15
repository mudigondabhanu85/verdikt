import uuid

from sqlalchemy import JSON, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# §3's business-rules questionnaire, API-only (Phase 3): a handful of
# well-defined, mechanically testable rule types rather than freeform
# natural-language assertions — the doc itself says business logic "can't
# be fully generic," so each type maps to deterministic detection code in
# app.agents.business_logic. `config`'s shape depends on rule_type and is
# validated at the API layer (app.schemas.business_rule).
RULE_TYPES = (
    "resource_isolation",
    "workflow_order",
    "price_or_quantity_tampering",
    "race_condition_limited_use",
)


class BusinessRule(Base):
    __tablename__ = "business_rules"

    version_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("versions.id"))
    rule_type: Mapped[str] = mapped_column(String(50))
    # The analyst's own plain-language description (e.g. "A user should
    # never see another user's basket") — carried into the eventual
    # Finding's narrative.
    title: Mapped[str] = mapped_column(String(500))
    config: Mapped[dict] = mapped_column(JSON)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
