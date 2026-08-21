import uuid

from sqlalchemy import ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

DEFAULT_OIDC_ROLE = "viewer"


class OidcProviderConfig(Base):
    """A registered enterprise identity provider (§9 enterprise hardening)
    — generic OIDC (Authorization Code flow), so it works with any
    standard-compliant IdP (Okta, Azure AD, Google Workspace, Auth0, ...)
    via OIDC discovery rather than a provider-specific SDK. The client
    secret is always envelope-encrypted, same discipline as CredentialSet/
    AIProviderConfig — never persisted or returned as plaintext.
    """

    __tablename__ = "oidc_provider_configs"

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    label: Mapped[str] = mapped_column(String(100))
    # e.g. "https://your-org.okta.com/oauth2/default" — discovery document
    # is fetched from f"{issuer}/.well-known/openid-configuration".
    issuer: Mapped[str] = mapped_column(String(500))
    client_id: Mapped[str] = mapped_column(String(255))
    encrypted_client_secret: Mapped[bytes] = mapped_column(LargeBinary)
    redirect_uri: Mapped[str] = mapped_column(String(500))
    # Role newly-provisioned OIDC users get (§9: there's still no "invite
    # teammate" / role-management endpoint in this build — see
    # tests/conftest.py's create_user_with_role note — so this is the
    # only lever available for what a fresh SSO login is allowed to do
    # until that's built). Defaults to the least-privilege role.
    default_role: Mapped[str] = mapped_column(String(32), default=DEFAULT_OIDC_ROLE)
