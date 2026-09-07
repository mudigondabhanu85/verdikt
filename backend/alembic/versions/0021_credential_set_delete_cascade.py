"""credential set delete cascade

Fixes the same missing-cascade bug class as 0018/0019, this time for
CredentialSet: neither FK pointing at credential_sets.id had an
ON DELETE behavior, so deleting a credential that had ever recorded a
login macro or any traffic (which any real scan run does) always failed
with a ForeignKeyViolation.

- login_macros.credential_set_id -> ON DELETE CASCADE (a login macro
  recorded for a credential is meaningless without it).
- traffic_interactions.credential_set_id -> ON DELETE SET NULL (recorded
  traffic history should survive the credential that produced it being
  deleted later, same contract as vgs_report_vulnerabilities.source_finding_id).

Revision ID: 0021_credential_set_delete_cascade
Revises: 0020_scan_run_warning
Create Date: 2026-09-07 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '0021_credential_set_delete_cascade'
down_revision: Union[str, None] = '0020_scan_run_warning'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("login_macros_credential_set_id_fkey", "login_macros", type_="foreignkey")
    op.create_foreign_key(
        "login_macros_credential_set_id_fkey",
        "login_macros",
        "credential_sets",
        ["credential_set_id"],
        ["id"],
        ondelete="CASCADE",
    )

    op.drop_constraint(
        "traffic_interactions_credential_set_id_fkey", "traffic_interactions", type_="foreignkey"
    )
    op.create_foreign_key(
        "traffic_interactions_credential_set_id_fkey",
        "traffic_interactions",
        "credential_sets",
        ["credential_set_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "traffic_interactions_credential_set_id_fkey", "traffic_interactions", type_="foreignkey"
    )
    op.create_foreign_key(
        "traffic_interactions_credential_set_id_fkey",
        "traffic_interactions",
        "credential_sets",
        ["credential_set_id"],
        ["id"],
    )

    op.drop_constraint("login_macros_credential_set_id_fkey", "login_macros", type_="foreignkey")
    op.create_foreign_key(
        "login_macros_credential_set_id_fkey",
        "login_macros",
        "credential_sets",
        ["credential_set_id"],
        ["id"],
    )
