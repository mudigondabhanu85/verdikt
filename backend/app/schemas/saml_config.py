import uuid

from pydantic import BaseModel


class SamlConfigCreate(BaseModel):
    label: str


class SamlIdpMetadataUpload(BaseModel):
    """Either the full IdP metadata XML, or the three individual fields
    Okta sometimes hands out separately instead of one file — at least
    one path must be provided."""

    idp_metadata_xml: str | None = None
    idp_sso_url: str | None = None
    idp_entity_id: str | None = None
    idp_x509_cert: str | None = None


class SamlConfigOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    label: str
    idp_sso_url: str | None
    idp_entity_id: str | None
    has_idp_metadata: bool

    model_config = {"from_attributes": True}
