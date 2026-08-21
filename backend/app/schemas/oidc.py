import uuid

from pydantic import BaseModel, model_validator

from app.models.oidc_provider_config import DEFAULT_OIDC_ROLE
from app.models.organization import BASELINE_ROLES


class OidcProviderConfigCreate(BaseModel):
    label: str
    issuer: str
    client_id: str
    client_secret: str
    redirect_uri: str
    default_role: str = DEFAULT_OIDC_ROLE

    @model_validator(mode="after")
    def _validate_role(self) -> "OidcProviderConfigCreate":
        if self.default_role not in BASELINE_ROLES:
            raise ValueError(f"default_role must be one of {BASELINE_ROLES}, got {self.default_role!r}")
        return self


class OidcProviderConfigOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    label: str
    issuer: str
    client_id: str
    redirect_uri: str
    default_role: str

    model_config = {"from_attributes": True}
