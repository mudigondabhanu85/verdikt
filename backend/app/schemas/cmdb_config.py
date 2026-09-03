import uuid
from typing import Any

from pydantic import BaseModel, model_validator

from app.models.cmdb_config import CMDB_PROVIDER_TYPES


class CMDBConfigCreate(BaseModel):
    label: str
    provider: str
    lookup_url_template: str
    auth_header_name: str = "Authorization"
    auth_header_value: str
    owner_json_path: str
    criticality_json_path: str

    @model_validator(mode="after")
    def _validate_provider(self) -> "CMDBConfigCreate":
        if self.provider not in CMDB_PROVIDER_TYPES:
            raise ValueError(f"provider must be one of {CMDB_PROVIDER_TYPES}, got {self.provider!r}")
        return self


class CMDBConfigOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    label: str
    provider: str
    lookup_url_template: str
    auth_header_name: str
    masked_reference: str
    owner_json_path: str
    criticality_json_path: str

    model_config = {"from_attributes": True}


class CMDBAssetLookupRequest(BaseModel):
    identifier: str


class AssetMetadataOut(BaseModel):
    identifier: str
    owner: str | None
    criticality: str | None
    raw: dict[str, Any]
