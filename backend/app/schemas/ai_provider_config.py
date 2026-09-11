import uuid
from datetime import datetime

from pydantic import BaseModel, model_validator

from app.models.ai_provider_config import AI_PROVIDER_AUTH_TYPES, AI_PROVIDER_TYPES


class AIProviderConfigCreate(BaseModel):
    label: str
    provider: str  # "claude" | "openai" | "gemini" | "grok" | "custom"
    model: str
    # Optional per-task overrides — see app.ai.model_routing.ModelRouter.
    # Leave unset and every agent role just uses `model`, same as before
    # this existed. Set them to route heavier reasoning (business-logic
    # hypothesis generation, attack-chain analysis) to a stronger model
    # and cheap mechanical classification to a smaller/faster one on the
    # same provider account.
    model_reasoning: str | None = None
    model_classification: str | None = None
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


class AIProviderConfigRotateSecret(BaseModel):
    """Body for PATCH .../{config_id}/rotate-secret — updates just the
    secret on an existing config (label/provider/model/is_default all
    stay as they were). Exists because bearer-token auth (most
    self-hosted/in-house gateways use short-lived session tokens) means
    "give it a new token" is a routine, frequent action — forcing a
    delete-and-recreate (and re-picking "set default") every time would
    make that needlessly disruptive.
    """

    api_key: str | None = None


class AIProviderConfigUpdateModels(BaseModel):
    """Body for PATCH .../{config_id}/models — lets an org route
    different agent roles to different models on the same provider
    account after the fact, without touching the secret/app_id (that's
    rotate-secret's job) or re-picking "set default". See
    app.ai.model_routing.ModelRouter. Any field left unset (None)
    clears that tier override, falling back to `model`.
    """

    model: str | None = None
    model_reasoning: str | None = None
    model_classification: str | None = None


class AIProviderConfigOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    label: str
    provider: str
    model: str
    model_reasoning: str | None
    model_classification: str | None
    base_url: str | None
    auth_type: str
    masked_reference: str
    is_default: bool
    # When the secret was last created/rotated — shown in the UI so an
    # analyst can see at a glance how stale a stored key/token is.
    secret_rotated_at: datetime | None

    model_config = {"from_attributes": True}
