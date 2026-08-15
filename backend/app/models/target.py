import uuid

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Target(Base):
    __tablename__ = "targets"

    version_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("versions.id"))
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int | None] = mapped_column(Integer)
    base_url: Mapped[str | None] = mapped_column(String(500))

    version = relationship("Version")
