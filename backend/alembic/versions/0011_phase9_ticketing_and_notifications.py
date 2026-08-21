"""phase 9 ticketing and notification adapters

Revision ID: 0011_phase9_ticketing_and_notifications
Revises: 0010_phase8_retest_jobs
Create Date: 2026-08-21 18:00:00.000000

"""
import uuid
from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from app.auth.rbac_seed import notification_config_resource_grants, ticketing_config_resource_grants


# revision identifiers, used by Alembic.
revision: str = '0011_phase9_ticketing_and_notifications'
down_revision: Union[str, None] = '0010_phase8_retest_jobs'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _seed_ticketing_and_notification_permissions() -> None:
    """Incremental grants for the new "notification_config" and
    "ticketing_config" resources (§9), same reasoning as 0002-0008's
    incremental seeds: 0001-0010 already seeded every other resource, so
    this inserts only the new rows."""
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
        for role, resource, action in (
            notification_config_resource_grants() + ticketing_config_resource_grants()
        )
    ]
    op.bulk_insert(role_permissions, rows)


def upgrade() -> None:
    op.create_table('notification_configs',
    sa.Column('org_id', sa.Uuid(), nullable=False),
    sa.Column('label', sa.String(length=100), nullable=False),
    sa.Column('provider', sa.String(length=20), nullable=False),
    sa.Column('encrypted_webhook_url', sa.LargeBinary(), nullable=False),
    sa.Column('masked_reference', sa.String(length=255), nullable=False),
    sa.Column('notify_on_scan_completed', sa.Boolean(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )

    op.create_table('ticketing_configs',
    sa.Column('org_id', sa.Uuid(), nullable=False),
    sa.Column('label', sa.String(length=100), nullable=False),
    sa.Column('provider', sa.String(length=20), nullable=False),
    sa.Column('base_url', sa.String(length=500), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('encrypted_api_token', sa.LargeBinary(), nullable=False),
    sa.Column('masked_reference', sa.String(length=255), nullable=False),
    sa.Column('project_key', sa.String(length=50), nullable=False),
    sa.Column('issue_type', sa.String(length=50), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )

    op.create_table('finding_tickets',
    sa.Column('finding_id', sa.Uuid(), nullable=False),
    sa.Column('ticketing_config_id', sa.Uuid(), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=False),
    sa.Column('external_key', sa.String(length=50), nullable=False),
    sa.Column('external_url', sa.String(length=500), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ),
    sa.ForeignKeyConstraint(['ticketing_config_id'], ['ticketing_configs.id'], ),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )

    _seed_ticketing_and_notification_permissions()


def downgrade() -> None:
    role_permissions = sa.table("role_permissions", sa.column("resource", sa.String()))
    op.execute(
        role_permissions.delete().where(
            role_permissions.c.resource.in_(["notification_config", "ticketing_config"])
        )
    )
    op.drop_table('finding_tickets')
    op.drop_table('ticketing_configs')
    op.drop_table('notification_configs')
