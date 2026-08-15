import uuid

from pydantic import BaseModel, model_validator

from app.models.business_rule import RULE_TYPES


class HttpCallConfig(BaseModel):
    method: str = "GET"
    url: str
    body: str | None = None
    content_type: str | None = None


class ResourceIsolationConfig(BaseModel):
    """A real endpoint with a real numeric resource ID in the path (e.g.
    "/rest/basket/6") — recon can't discover this on SPA-heavy apps, so
    the analyst points at it directly."""

    url: str
    method: str = "GET"


class WorkflowOrderConfig(BaseModel):
    precondition: HttpCallConfig
    guarded_action: HttpCallConfig
    credential_set_id: uuid.UUID | None = None


class PriceOrQuantityTamperingConfig(BaseModel):
    method: str = "POST"
    url: str
    body_template: str  # must contain a {value} placeholder
    content_type: str = "application/json"
    baseline_value: str = "1"
    tamper_values: list[str] | None = None
    credential_set_id: uuid.UUID | None = None


class RaceConditionConfig(BaseModel):
    method: str = "POST"
    url: str
    body: str | None = None
    content_type: str = "application/json"
    concurrency: int = 10
    max_allowed_successes: int = 1
    credential_set_id: uuid.UUID | None = None


_CONFIG_SCHEMAS: dict[str, type[BaseModel]] = {
    "resource_isolation": ResourceIsolationConfig,
    "workflow_order": WorkflowOrderConfig,
    "price_or_quantity_tampering": PriceOrQuantityTamperingConfig,
    "race_condition_limited_use": RaceConditionConfig,
}


class BusinessRuleCreate(BaseModel):
    rule_type: str
    title: str
    config: dict

    @model_validator(mode="after")
    def validate_config_shape(self) -> "BusinessRuleCreate":
        if self.rule_type not in _CONFIG_SCHEMAS:
            raise ValueError(f"Unknown rule_type {self.rule_type!r}; must be one of {sorted(RULE_TYPES)}")
        schema_cls = _CONFIG_SCHEMAS[self.rule_type]
        validated = schema_cls(**self.config)
        self.config = validated.model_dump(mode="json")
        return self


class BusinessRuleOut(BaseModel):
    id: uuid.UUID
    version_id: uuid.UUID
    rule_type: str
    title: str
    config: dict

    model_config = {"from_attributes": True}
