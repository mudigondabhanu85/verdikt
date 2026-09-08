"""widen alembic_version column

Alembic creates its own bookkeeping `alembic_version.version_num` column
as VARCHAR(32) by default. This project's revision IDs are descriptive
slugs (e.g. "0002_scan_findings_and_permissions", 35 chars) rather than
Alembic's usual short random hex, so a truly fresh database hit
`StringDataRightTruncation` the moment migration 0002 tried to record
itself — confirmed live running `docker compose up` against a brand-new
Postgres volume. The real dev database never hit this because someone
widened this column on it directly, once, outside of any migration —
never actually captured anywhere in version control until now, which is
exactly why a fresh database (Docker, CI, a new teammate) broke on it.

128 matches the width already in place on that real database.

Revision ID: 0001b_widen_alembic_version_column
Revises: 0001_initial_schema
Create Date: 2026-09-07 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0001b_widen_alembic_version_column'
down_revision: Union[str, None] = '0001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "alembic_version", "version_num", existing_type=sa.String(length=32), type_=sa.String(length=128)
    )


def downgrade() -> None:
    op.alter_column(
        "alembic_version", "version_num", existing_type=sa.String(length=128), type_=sa.String(length=32)
    )
