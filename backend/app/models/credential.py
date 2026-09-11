import uuid

from sqlalchemy import ForeignKey, Integer, JSON, LargeBinary, String
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

    # Static cookies sent on every authenticated request for this
    # credential, merged in alongside whatever cookies the login response
    # itself sets. Real, concrete need found live: some targets gate
    # behavior behind a stateless preference/feature-flag cookie that's
    # never set by the login response itself (e.g. DVWA's `security`
    # cookie choosing low/medium/high/impossible difficulty per-request,
    # independent of session/auth state) — without this, such a target
    # can only ever be scanned at whatever its cookie-absent default is.
    extra_cookies: Mapped[dict[str, str] | None] = mapped_column(JSON)

    # Optional, analyst-set — higher number means more privileged. NULL
    # (the default) means "not ranked", which excludes this credential
    # from app.agents.access_control's role-vs-role vertical escalation
    # check entirely: without an explicit ranking there's no ground
    # truth for which of two authenticated identities is "supposed" to
    # have more access, so nothing can safely be called an escalation.
    # Set this on at least two credentials with different values (e.g.
    # "Standard User"=1, "Admin"=10) to enable that check for this
    # version — comparing every pair where one out-ranks the other.
    privilege_rank: Mapped[int | None] = mapped_column(Integer)

    version = relationship("Version")
