import uuid
from datetime import datetime

from pydantic import BaseModel, model_validator

from app.models.ai_provider_config import AI_PROVIDER_AUTH_TYPES, AI_PROVIDER_TYPES


class AIProviderConfigCreate(BaseModel):
    label: str
    provider: str  # "claude" | "openai" | "gemini" | "grok" | "custom" | "spark"
    model: str
    # Optional per-task overrides — see app.ai.model_routing.ModelRouter.
    # Leave unset and every agent role just uses `model`, same as before
    # this existed. Set them to route heavier reasoning (business-logic
    # hypothesis generation, attack-chain analysis) to a stronger model
    # and cheap mechanical classification to a smaller/faster one on the
    # same provider account.
    model_reasoning: str | None = None
    model_classification: str | None = None
    api_key: str  # for provider="spark": the bearer token, or the primary API key
    base_url: str | None = None  # required (and only meaningful) for "custom"; optional override for "gemini"/"spark"
    auth_type: str = "api_key"  # "api_key" | "bearer_token" — see AIProviderConfig.auth_type
    # Spark-only — ignored for every other provider.
    app_id: str | None = None
    secondary_api_key: str | None = None  # api_key mode's optional fallback key (see SparkAdapter)

    @model_validator(mode="after")
    def _validate_provider(self) -> "AIProviderConfigCreate":
        if self.provider not in AI_PROVIDER_TYPES:
            raise ValueError(f"provider must be one of {AI_PROVIDER_TYPES}, got {self.provider!r}")
        if self.provider == "custom" and not self.base_url:
            raise ValueError('base_url is required when provider="custom"')
        if self.auth_type not in AI_PROVIDER_AUTH_TYPES:
            raise ValueError(f"auth_type must be one of {AI_PROVIDER_AUTH_TYPES}, got {self.auth_type!r}")
        # No app_id requirement here — every Spark request needs one
        # (see SparkAdapter's docstring), but it's a deployment-wide
        # constant (SPARK_APP_ID) an org falls back to automatically,
        # same pattern as base_url falling back to SPARK_BASE_URL. This
        # field only matters for an org on its own distinct Spark
        # tenant/app registration.
        return self


class AIProviderConfigRotateSecret(BaseModel):
    """Body for PATCH .../{config_id}/rotate-secret — updates just the
    secret(s)/app_id on an existing config (label/provider/model/
    is_default all stay as they were). Exists because bearer-token auth
    (Spark's 60-minute expiry, most self-hosted gateways' session
    tokens, ...) means "give it a new token" is a routine, frequent
    action — forcing a delete-and-recreate (and re-picking "set
    default") every time would make that needlessly disruptive. app_id
    is included here too since it's the other field that turned out to
    need fixing without a full recreate — e.g. a typo (a real incident:
    "openai" typed in instead of the actual Spark App ID).
    """

    api_key: str | None = None
    secondary_api_key: str | None = None
    app_id: str | None = None


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
    app_id: str | None
    has_secondary_api_key: bool
    masked_reference: str
    is_default: bool
    # When the secret was last created/rotated — only meaningful (shown
    # in the UI as an expiry countdown) for provider="spark"
    # auth_type="bearer_token", since that's the one auth shape with a
    # real, short (~60min) expiry; every other provider/mode's secret
    # doesn't expire on its own.
    secret_rotated_at: datetime | None

    model_config = {"from_attributes": True}
