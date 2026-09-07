"""scan run warning

Adds scan_runs.warning — set when a run reached status="completed"
having crawled effectively nothing (recon + authenticated_recon both
discovered 0 endpoints), which otherwise looked identical to a real,
thorough scan with a clean result. Distinct from the existing `error`
column: this scan didn't fail, it's very likely misconfigured (a
Target/Scope host mismatch, or a login the crawler couldn't complete).

Revision ID: 0020_scan_run_warning
Revises: 0019_vgs_evidence_cascade_and_auto_seed
Create Date: 2026-09-07 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0020_scan_run_warning'
down_revision: Union[str, None] = '0019_vgs_evidence_cascade_and_auto_seed'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scan_runs", sa.Column("warning", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_runs", "warning")
