import uuid

from pydantic import BaseModel


class FindingTicketCreate(BaseModel):
    ticketing_config_id: uuid.UUID


class FindingTicketOut(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    ticketing_config_id: uuid.UUID
    external_key: str
    external_url: str

    model_config = {"from_attributes": True}
