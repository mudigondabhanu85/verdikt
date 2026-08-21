import uuid

from pydantic import BaseModel, model_validator

from app.models.ai_provider_config import AI_PROVIDER_TYPES


class AIProviderConfigCreate(BaseModel):
    label: str
    provider: str  # "claude" | "openai" | "custom"
    model: str
    api_key: str
    base_url: str | None = None  # required (and only meaningful) for "custom"

    @model_validator(mode="after")
    def _validate_provider(self) -> "AIProviderConfigCreate":
        if self.provider not in AI_PROVIDER_TYPES:
            raise ValueError(f"provider must be one of {AI_PROVIDER_TYPES}, got {self.provider!r}")
        if self.provider == "custom" and not self.base_url:
            raise ValueError('base_url is required when provider="custom"')
        return self


class AIProviderConfigOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    label: str
    provider: str
    model: str
    base_url: str | None
    masked_reference: str

    model_config = {"from_attributes": True}
