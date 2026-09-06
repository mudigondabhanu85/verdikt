import uuid

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class SamlConfig(Base):
    """A registered enterprise SAML identity provider (§9), configured
    once per organization — mirrors OidcProviderConfig's structure/
    conventions but for the SAML metadata-exchange flow instead of OIDC
    discovery. An org admin downloads this Verdikt org's SP metadata XML
    (generated on the fly from entity_id/acs_url — see app.auth.saml)
    to hand to their Okta admin, then uploads Okta's IdP metadata (or
    the three individual fields Okta sometimes hands out separately)
    back here to complete the trust relationship.
    """

    __tablename__ = "saml_configs"

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    label: Mapped[str] = mapped_column(String(100))

    # Either the full IdP metadata XML, or the three fields below
    # individually — both nullable since neither is known until the org
    # admin completes the Okta-side setup and uploads one or the other.
    idp_metadata_xml: Mapped[str | None] = mapped_column(Text, nullable=True)
    idp_sso_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    idp_entity_id: Mapped[str | None] = mapped_column(String(500), nullable=True)
    idp_x509_cert: Mapped[str | None] = mapped_column(Text, nullable=True)
