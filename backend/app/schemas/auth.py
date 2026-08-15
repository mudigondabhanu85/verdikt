import uuid

from pydantic import BaseModel, EmailStr


class UserRegister(BaseModel):
    org_name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    email: EmailStr
    role: str
    is_active: bool

    model_config = {"from_attributes": True}
