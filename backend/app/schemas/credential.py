import uuid

from pydantic import BaseModel


class CredentialSetCreate(BaseModel):
    label: str
    credential_type: str = "username_password"
    username: str
    secret: str  # password / token / etc. — encrypted before storage, never echoed back


class CredentialSetOut(BaseModel):
    id: uuid.UUID
    version_id: uuid.UUID
    label: str
    credential_type: str
    masked_reference: str

    model_config = {"from_attributes": True}
