"""credential extra headers

Adds CredentialSet.extra_headers — the header-shaped equivalent of
extra_cookies (0013): static headers sent on every authenticated
request for a credential, e.g. a custom "X-API-Key" header an imported
Postman/API collection uses instead of the standard "Authorization:
Bearer" the api_token credential_type already handles. See
app.models.credential.CredentialSet.extra_headers.

Revision ID: 0038_credential_extra_headers
Revises: 0037_chatbot_agency_probes
Create Date: 2026-09-19 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0038_credential_extra_headers'
down_revision: Union[str, None] = '0037_chatbot_agency_probes'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('credential_sets', sa.Column('extra_headers', sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column('credential_sets', 'extra_headers')
