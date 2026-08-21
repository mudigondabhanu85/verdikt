"""phase 8 per-finding retest jobs

Revision ID: 0010_phase8_retest_jobs
Revises: 0009_phase6c_api_keys
Create Date: 2026-08-21 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0010_phase8_retest_jobs'
down_revision: Union[str, None] = '0009_phase6c_api_keys'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('retest_jobs',
    sa.Column('finding_id', sa.Uuid(), nullable=False),
    sa.Column('requested_by', sa.Uuid(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('result', sa.String(length=30), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('request_raw', sa.Text(), nullable=True),
    sa.Column('response_raw', sa.Text(), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ),
    sa.ForeignKeyConstraint(['requested_by'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('retest_jobs')
