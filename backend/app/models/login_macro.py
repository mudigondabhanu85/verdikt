import uuid

from sqlalchemy import JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class LoginMacro(Base):
    """A recorded login action sequence (§4/§5), tied to a CredentialSet.
    `steps` is a JSON list of MacroStep dicts (app.agents.macro) — never
    contains a plaintext username/password value, only which selector
    plays the username/password *role*, so the same macro replays with
    any CredentialSet's decrypted secret at replay time (§1.5).
    """

    __tablename__ = "login_macros"

    version_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("versions.id"))
    credential_set_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("credential_sets.id"))
    steps: Mapped[list] = mapped_column(JSON)
