import uuid

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class OrgBranding(Base):
    """Report cover-page branding for an org (§7/§8) — the one genuinely
    valuable piece pulled in from the standalone VGS tool's report
    builder (its logo-upload/embed feature); everything else about VGS's
    report engine is superseded by Verdikt's own, more capable one, so
    only this piece is merged in rather than the whole engine.
    """

    __tablename__ = "org_branding"

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), unique=True)
    logo_object_key: Mapped[str | None] = mapped_column(String(500))
    company_name: Mapped[str | None] = mapped_column(String(255))
    primary_color_hex: Mapped[str | None] = mapped_column(String(9))
