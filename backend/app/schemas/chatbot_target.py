import uuid

from pydantic import BaseModel, model_validator


class ChatbotTargetCreate(BaseModel):
    label: str
    endpoint_url: str
    http_method: str = "POST"
    request_body_template: str
    content_type: str = "application/json"
    response_text_path: str
    auth_header_name: str | None = None
    # Plaintext in, encrypted before storage, never echoed back — see
    # ChatbotTargetOut, which has no secret field at all.
    auth_header_value: str | None = None

    @model_validator(mode="after")
    def _validate_message_placeholder(self) -> "ChatbotTargetCreate":
        if "{message}" not in self.request_body_template:
            raise ValueError("request_body_template must contain a literal {message} placeholder")
        return self


class ChatbotTargetOut(BaseModel):
    id: uuid.UUID
    version_id: uuid.UUID
    label: str
    endpoint_url: str
    http_method: str
    content_type: str
    response_text_path: str
    auth_header_name: str | None
    masked_reference: str | None

    model_config = {"from_attributes": True}
