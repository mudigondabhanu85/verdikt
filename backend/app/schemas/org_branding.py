import uuid

from pydantic import BaseModel


class OrgBrandingUpdate(BaseModel):
    company_name: str | None = None
    primary_color_hex: str | None = None


class OrgBrandingOut(BaseModel):
    org_id: uuid.UUID
    logo_object_key: str | None
    company_name: str | None
    primary_color_hex: str | None

    model_config = {"from_attributes": True}
