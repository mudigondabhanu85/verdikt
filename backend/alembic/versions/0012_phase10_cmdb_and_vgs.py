"""phase 10 cmdb and vgs integrations

Revision ID: 0012_phase10_cmdb_and_vgs
Revises: 0011_phase9_ticketing_and_notifications
Create Date: 2026-09-03 00:00:00.000000

"""
import uuid
from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from app.auth.rbac_seed import cmdb_config_resource_grants, vgs_config_resource_grants


# revision identifiers, used by Alembic.
revision: str = '0012_phase10_cmdb_and_vgs'
down_revision: Union[str, None] = '0011_phase9_ticketing_and_notifications'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _seed_cmdb_and_vgs_permissions() -> None:
    """Incremental grants for the new "cmdb_config" and "vgs_config"
    resources (§9/§11), same reasoning as 0002-0011's incremental seeds:
    0001-0011 already seeded every other resource, so this inserts only
    the new rows."""
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
        for role, resource, action in (cmdb_config_resource_grants() + vgs_config_resource_grants())
    ]
    op.bulk_insert(role_permissions, rows)


def upgrade() -> None:
    op.create_table('cmdb_configs',
    sa.Column('org_id', sa.Uuid(), nullable=False),
    sa.Column('label', sa.String(length=100), nullable=False),
    sa.Column('provider', sa.String(length=20), nullable=False),
    sa.Column('lookup_url_template', sa.String(length=500), nullable=False),
    sa.Column('auth_header_name', sa.String(length=100), nullable=False),
    sa.Column('encrypted_auth_header_value', sa.LargeBinary(), nullable=False),
    sa.Column('masked_reference', sa.String(length=255), nullable=False),
    sa.Column('owner_json_path', sa.String(length=200), nullable=False),
    sa.Column('criticality_json_path', sa.String(length=200), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )

    op.create_table('vgs_configs',
    sa.Column('org_id', sa.Uuid(), nullable=False),
    sa.Column('label', sa.String(length=100), nullable=False),
    sa.Column('encrypted_webhook_url', sa.LargeBinary(), nullable=False),
    sa.Column('masked_reference', sa.String(length=255), nullable=False),
    sa.Column('push_on_scan_completed', sa.Boolean(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )

    _seed_cmdb_and_vgs_permissions()


def downgrade() -> None:
    role_permissions = sa.table("role_permissions", sa.column("resource", sa.String()))
    op.execute(
        role_permissions.delete().where(
            role_permissions.c.resource.in_(["cmdb_config", "vgs_config"])
        )
    )
    op.drop_table('vgs_configs')
    op.drop_table('cmdb_configs')
