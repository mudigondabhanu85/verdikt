"""org branding

Revision ID: 0016_org_branding
Revises: 0015_saml_org_config
Create Date: 2026-09-03 07:00:00.000000

"""
import uuid
from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from app.auth.rbac_seed import org_branding_resource_grants


# revision identifiers, used by Alembic.
revision: str = '0016_org_branding'
down_revision: Union[str, None] = '0015_saml_org_config'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _seed_org_branding_permissions() -> None:
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
        for role, resource, action in org_branding_resource_grants()
    ]
    op.bulk_insert(role_permissions, rows)


def upgrade() -> None:
    op.create_table(
        'org_branding',
        sa.Column('org_id', sa.Uuid(), nullable=False),
        sa.Column('logo_object_key', sa.String(length=500), nullable=True),
        sa.Column('company_name', sa.String(length=255), nullable=True),
        sa.Column('primary_color_hex', sa.String(length=9), nullable=True),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('org_id'),
    )
    _seed_org_branding_permissions()


def downgrade() -> None:
    role_permissions = sa.table("role_permissions", sa.column("resource", sa.String()))
    op.execute(role_permissions.delete().where(role_permissions.c.resource == "org_branding"))
    op.drop_table('org_branding')
