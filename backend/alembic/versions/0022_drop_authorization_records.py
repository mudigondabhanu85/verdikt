"""drop authorization_records

Removes the §1 authorization-gate feature entirely, per explicit user
request: the pre-scan enforcement was already dropped from
create_scan_run/retest_scan_run and the Burp-import path in an earlier
migration/change this same round of work — this finishes the removal by
dropping the now-unused authorization_records table and its model,
schemas, routes, and frontend tab.

Revision ID: 0022_drop_authorization_records
Revises: 0021_credential_set_delete_cascade
Create Date: 2026-09-07 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0022_drop_authorization_records'
down_revision: Union[str, None] = '0021_credential_set_delete_cascade'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_table('authorization_records')


def downgrade() -> None:
    op.create_table(
        'authorization_records',
        sa.Column('version_id', sa.Uuid(), nullable=False),
        sa.Column('approver_name', sa.String(length=255), nullable=False),
        sa.Column('attestation_text', sa.Text(), nullable=True),
        sa.Column('letter_object_key', sa.String(length=500), nullable=True),
        sa.Column('attested_by', sa.Uuid(), nullable=False),
        sa.Column('attested_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['attested_by'], ['users.id']),
        sa.ForeignKeyConstraint(['version_id'], ['versions.id']),
        sa.PrimaryKeyConstraint('id'),
    )
