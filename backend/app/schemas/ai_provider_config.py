import uuid

from pydantic import BaseModel, model_validator

from app.models.ai_provider_config import AI_PROVIDER_AUTH_TYPES, AI_PROVIDER_TYPES


class AIProviderConfigCreate(BaseModel):
    label: str
    provider: str  # "claude" | "openai" | "gemini" | "grok" | "custom"
    model: str
    api_key: str
    base_url: str | None = None  # required (and only meaningful) for "custom"; optional override for "gemini"
    auth_type: str = "api_key"  # "api_key" | "bearer_token" — see AIProviderConfig.auth_type

    @model_validator(mode="after")
    def _validate_provider(self) -> "AIProviderConfigCreate":
        if self.provider not in AI_PROVIDER_TYPES:
            raise ValueError(f"provider must be one of {AI_PROVIDER_TYPES}, got {self.provider!r}")
        if self.provider == "custom" and not self.base_url:
            raise ValueError('base_url is required when provider="custom"')
        if self.auth_type not in AI_PROVIDER_AUTH_TYPES:
            raise ValueError(f"auth_type must be one of {AI_PROVIDER_AUTH_TYPES}, got {self.auth_type!r}")
        return self


class AIProviderConfigOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    label: str
    provider: str
    model: str
    base_url: str | None
    auth_type: str
    masked_reference: str

    model_config = {"from_attributes": True}
