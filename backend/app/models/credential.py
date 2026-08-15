import uuid

from sqlalchemy import ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class CredentialSet(Base):
    """A named credential (e.g. "Admin", "User A", "Guest") used to build
    the horizontal/vertical privilege test matrix (§5). The secret is
    always stored envelope-encrypted via app.vault.credential_vault — this
    column never holds plaintext. masked_reference is safe to return from
    the API (e.g. "user_a@example.com / ****1234").
    """

    __tablename__ = "credential_sets"

    version_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("versions.id"))
    label: Mapped[str] = mapped_column(String(100))
    credential_type: Mapped[str] = mapped_column(String(50))
    encrypted_secret: Mapped[bytes] = mapped_column(LargeBinary)
    masked_reference: Mapped[str] = mapped_column(String(255))

    version = relationship("Version")
