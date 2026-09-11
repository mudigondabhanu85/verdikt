"""vgs auto seed finding memory

Adds vgs_report_drafts.auto_seeded_finding_ids (JSON list of Finding.id
strings, default empty list) — the persistent memory that makes it safe
for auto-seed (app.api.routes.vgs_vulnerabilities._auto_seed_findings_
into_draft) to run on every Vulnerability Picker load instead of just
the first: it tracks every Finding ever offered to a draft, kept even
after the resulting VgsReportVulnerability is deleted, so a
deliberately-removed vulnerability isn't resurrected on the next reload
while a scan run's newly-confirmed vulnerability classes still get
auto-added without an analyst having to notice and add them by hand.

Revision ID: 0033_vgs_auto_seed_finding_memory
Revises: 0032_drop_ai_provider_model_tiers
Create Date: 2026-09-11 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0033_vgs_auto_seed_finding_memory'
down_revision: Union[str, None] = '0032_drop_ai_provider_model_tiers'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "vgs_report_drafts",
        sa.Column("auto_seeded_finding_ids", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.alter_column("vgs_report_drafts", "auto_seeded_finding_ids", server_default=None)


def downgrade() -> None:
    op.drop_column("vgs_report_drafts", "auto_seeded_finding_ids")
