"""vgs evidence cascade and auto-seed flag

Two fixes bundled together from the same round of VGS report-builder
feedback:

1. Adds ON DELETE CASCADE to vgs_report_vulnerabilities.report_draft_id
   and vgs_evidence_steps.report_vulnerability_id — neither had one
   before (Postgres default: NO ACTION), so deleting a selected
   vulnerability that had any evidence steps attached always failed with
   a ForeignKeyViolation (the "delete doesn't work in Selected for this
   report" bug). Same fix shape as 0018's scan/finding subtree.
2. Adds vgs_report_drafts.findings_auto_seeded (default false) — backs
   the new "every scan finding is auto-added to a brand-new report draft"
   behavior, so it only ever runs once per draft.

Revision ID: 0019_vgs_evidence_cascade_and_auto_seed
Revises: 0018_scan_delete_cascade_and_vgs_finding_link
Create Date: 2026-09-07 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0019_vgs_evidence_cascade_and_auto_seed'
down_revision: Union[str, None] = '0018_scan_delete_cascade_and_vgs_finding_link'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_CASCADE_FKS = [
    (
        "vgs_report_vulnerabilities",
        "vgs_report_vulnerabilities_report_draft_id_fkey",
        "report_draft_id",
        "vgs_report_drafts",
    ),
    (
        "vgs_evidence_steps",
        "vgs_evidence_steps_report_vulnerability_id_fkey",
        "report_vulnerability_id",
        "vgs_report_vulnerabilities",
    ),
]


def upgrade() -> None:
    for table, constraint, column, referenced_table in _CASCADE_FKS:
        op.drop_constraint(constraint, table, type_="foreignkey")
        op.create_foreign_key(
            constraint, table, referenced_table, [column], ["id"], ondelete="CASCADE"
        )

    op.add_column(
        "vgs_report_drafts",
        sa.Column("findings_auto_seeded", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.alter_column("vgs_report_drafts", "findings_auto_seeded", server_default=None)


def downgrade() -> None:
    op.drop_column("vgs_report_drafts", "findings_auto_seeded")

    for table, constraint, column, referenced_table in _CASCADE_FKS:
        op.drop_constraint(constraint, table, type_="foreignkey")
        op.create_foreign_key(constraint, table, referenced_table, [column], ["id"])
