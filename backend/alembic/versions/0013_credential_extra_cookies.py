"""credential extra cookies

Revision ID: 0013_credential_extra_cookies
Revises: 0012_phase10_cmdb_and_vgs
Create Date: 2026-09-03 01:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0013_credential_extra_cookies'
down_revision: Union[str, None] = '0012_phase10_cmdb_and_vgs'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('credential_sets', sa.Column('extra_cookies', sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column('credential_sets', 'extra_cookies')
