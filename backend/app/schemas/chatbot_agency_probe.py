import uuid

from pydantic import BaseModel


class ChatbotAgencyProbeCreate(BaseModel):
    forbidden_action: str


class ChatbotAgencyProbeOut(BaseModel):
    id: uuid.UUID
    chatbot_target_id: uuid.UUID
    forbidden_action: str

    model_config = {"from_attributes": True}
