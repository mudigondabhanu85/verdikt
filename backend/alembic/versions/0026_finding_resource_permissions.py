"""finding resource permissions

Seeds the "finding" RBAC resource (§9) — previously Findings had no
dedicated resource/permission of their own at all (only readable as a
side effect of "scan" read access), and no route existed for an analyst
to mark one a false positive / risk-accepted, or delete it outright.
org_admin/project_lead get full CRUD; analyst gets read + update (mark
false-positive/risk-accepted/reopen) but not delete — same "analyst can
act, deletion stays lead/admin-only" pattern as credential/target;
viewer stays read-only. See app/api/routes/findings.py.

Revision ID: 0026_finding_resource_permissions
Revises: 0025_scan_run_token_usage
Create Date: 2026-09-09 00:00:00.000000

"""
import uuid
from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from app.auth.rbac_seed import finding_resource_grants


# revision identifiers, used by Alembic.
revision: str = '0026_finding_resource_permissions'
down_revision: Union[str, None] = '0025_scan_run_token_usage'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _seed_finding_permissions() -> None:
    role_permissions = sa.table(
        "role_permissions",
        sa.column("id", sa.Uuid()),
        sa.column("role", sa.String()),
        sa.column("resource", sa.String()),
        sa.column("action", sa.String()),
        sa.column("allowed", sa.Boolean()),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    now = datetime.now(timezone.utc)
    rows = [
        {
            "id": uuid.uuid4(),
            "role": role,
            "resource": resource,
            "action": action,
            "allowed": True,
            "created_at": now,
        }
        for role, resource, action in finding_resource_grants()
    ]
    op.bulk_insert(role_permissions, rows)


def upgrade() -> None:
    _seed_finding_permissions()


def downgrade() -> None:
    role_permissions = sa.table("role_permissions", sa.column("resource", sa.String()))
    op.execute(role_permissions.delete().where(role_permissions.c.resource == "finding"))
