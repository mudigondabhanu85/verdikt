"""scan delete cascade and vgs finding link

Two independent, additive changes bundled together since both were
needed for the same "scan pause/delete + pull real findings into VGS
reports" round of work:

1. Adds ON DELETE CASCADE to every FK that (transitively) hangs off
   scan_runs.id or findings.id, so a scan run can actually be deleted
   in one statement instead of the caller having to know and manually
   delete every dependent table in the right order. None of these had
   any explicit ON DELETE behavior before (Postgres default: NO ACTION),
   so deleting a ScanRun with any findings/agent jobs/etc. attached —
   which is every real scan run — would otherwise always fail with a
   ForeignKeyViolation.
2. Adds vgs_report_vulnerabilities.source_finding_id (ON DELETE SET
   NULL, not CASCADE — this row's fields are an independent copy, same
   contract as library_entry_id, so a scan/finding being deleted later
   must not take an already-built report down with it).

Revision ID: 0018_scan_delete_cascade_and_vgs_finding_link
Revises: 0017_vgs_report_builder
Create Date: 2026-09-07 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0018_scan_delete_cascade_and_vgs_finding_link'
down_revision: Union[str, None] = '0017_vgs_report_builder'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# (table, constraint_name, column, referenced_table)
_CASCADE_FKS = [
    ("agent_jobs", "agent_jobs_scan_run_id_fkey", "scan_run_id", "scan_runs"),
    ("findings", "findings_scan_run_id_fkey", "scan_run_id", "scan_runs"),
    ("findings", "findings_agent_job_id_fkey", "agent_job_id", "agent_jobs"),
    ("evidence", "evidence_finding_id_fkey", "finding_id", "findings"),
    ("finding_tickets", "finding_tickets_finding_id_fkey", "finding_id", "findings"),
    ("retest_jobs", "retest_jobs_finding_id_fkey", "finding_id", "findings"),
    ("review_candidates", "review_candidates_scan_run_id_fkey", "scan_run_id", "scan_runs"),
    ("review_candidates", "review_candidates_agent_job_id_fkey", "agent_job_id", "agent_jobs"),
    ("attack_chains", "attack_chains_scan_run_id_fkey", "scan_run_id", "scan_runs"),
    (
        "attack_chain_evidence",
        "attack_chain_evidence_attack_chain_id_fkey",
        "attack_chain_id",
        "attack_chains",
    ),
]


def upgrade() -> None:
    for table, constraint, column, referenced_table in _CASCADE_FKS:
        op.drop_constraint(constraint, table, type_="foreignkey")
        op.create_foreign_key(
            constraint, table, referenced_table, [column], ["id"], ondelete="CASCADE"
        )

    op.add_column(
        "vgs_report_vulnerabilities", sa.Column("source_finding_id", sa.Uuid(), nullable=True)
    )
    op.create_foreign_key(
        "vgs_report_vulnerabilities_source_finding_id_fkey",
        "vgs_report_vulnerabilities",
        "findings",
        ["source_finding_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "vgs_report_vulnerabilities_source_finding_id_fkey",
        "vgs_report_vulnerabilities",
        type_="foreignkey",
    )
    op.drop_column("vgs_report_vulnerabilities", "source_finding_id")

    for table, constraint, column, referenced_table in _CASCADE_FKS:
        op.drop_constraint(constraint, table, type_="foreignkey")
        op.create_foreign_key(constraint, table, referenced_table, [column], ["id"])
