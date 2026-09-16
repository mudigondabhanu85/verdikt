"""evidence payload

Adds evidence.payload (nullable text) — the exact substring that proves
a finding (a forged Origin value, an executed XSS marker, an unescaped
"={marker}" formula-injection string, ...), stored separately from the
full raw request/response text so every report surface can highlight it
rather than making a reader hunt for the one line that actually matters
inside a wall of raw HTTP text.

Revision ID: 0035_evidence_payload
Revises: 0034_scope_entry_purpose
Create Date: 2026-09-15 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0035_evidence_payload'
down_revision: Union[str, None] = '0034_scope_entry_purpose'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("evidence", sa.Column("payload", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("evidence", "payload")
