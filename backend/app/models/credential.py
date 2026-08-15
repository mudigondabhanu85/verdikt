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

    # Optional explicit login config (Phase 2's lightweight precursor to
    # the Phase 4 Playwright macro recorder) — needed for JSON/REST login
    # endpoints that auto-discovery from a server-rendered <form> can't
    # find (e.g. an Angular/React SPA's login API call). All nullable:
    # when absent, app.agents.login falls back to <form> auto-discovery.
    login_endpoint: Mapped[str | None] = mapped_column(String(500))
    login_method: Mapped[str | None] = mapped_column(String(10))
    # JSON body template with {username}/{password} placeholders, e.g.
    # '{"email": "{username}", "password": "{password}"}'.
    login_body_template: Mapped[str | None] = mapped_column(String(1000))
    login_content_type: Mapped[str | None] = mapped_column(String(100))
    # Dotted path to pull a bearer token out of a JSON login response,
    # e.g. "authentication.token".
    token_response_path: Mapped[str | None] = mapped_column(String(200))

    version = relationship("Version")
