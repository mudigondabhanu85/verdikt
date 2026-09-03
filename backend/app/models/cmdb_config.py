import uuid

from sqlalchemy import ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# Only one provider so far — a generic, org-configured REST lookup (see
# app.integrations.cmdb.client's module docstring for why there's no
# single named-vendor provider the way Jira/Slack have). Kept
# provider-tagged like every other config table so a future named
# vendor integration is a client + a string, not a new table.
CMDB_PROVIDER_TYPES = ("generic_rest",)


class CMDBConfig(Base):
    """A named, org-scoped CMDB lookup target (§9). The auth header value
    is envelope-encrypted the same way every other integration's secret
    is (app.vault.credential_vault) — it's typically a bearer token or
    API key, not a public identifier.
    """

    __tablename__ = "cmdb_configs"

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    label: Mapped[str] = mapped_column(String(100))
    provider: Mapped[str] = mapped_column(String(20))
    lookup_url_template: Mapped[str] = mapped_column(String(500))
    auth_header_name: Mapped[str] = mapped_column(String(100), default="Authorization")
    encrypted_auth_header_value: Mapped[bytes] = mapped_column(LargeBinary)
    masked_reference: Mapped[str] = mapped_column(String(255))
    owner_json_path: Mapped[str] = mapped_column(String(200))
    criticality_json_path: Mapped[str] = mapped_column(String(200))
