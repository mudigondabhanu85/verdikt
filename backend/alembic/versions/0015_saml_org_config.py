"""saml org config

Adds the saml_configs table (§9 — org-level Okta/SAML metadata exchange)
and its "saml_config" RBAC resource.

Revision ID: 0015_saml_org_config
Revises: 0014_phase11_extensibility_and_lifecycle
Create Date: 2026-09-03 07:00:00.000000

"""
import uuid
from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from app.auth.rbac_seed import saml_config_resource_grants


# revision identifiers, used by Alembic.
revision: str = '0015_saml_org_config'
down_revision: Union[str, None] = '0014_phase11_extensibility_and_lifecycle'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _seed_saml_config_permissions() -> None:
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
        for role, resource, action in saml_config_resource_grants()
    ]
    op.bulk_insert(role_permissions, rows)


def upgrade() -> None:
    op.create_table(
        'saml_configs',
        sa.Column('org_id', sa.Uuid(), nullable=False),
        sa.Column('label', sa.String(length=100), nullable=False),
        sa.Column('idp_metadata_xml', sa.Text(), nullable=True),
        sa.Column('idp_sso_url', sa.String(length=500), nullable=True),
        sa.Column('idp_entity_id', sa.String(length=500), nullable=True),
        sa.Column('idp_x509_cert', sa.Text(), nullable=True),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )

    _seed_saml_config_permissions()


def downgrade() -> None:
    role_permissions = sa.table("role_permissions", sa.column("resource", sa.String()))
    op.execute(role_permissions.delete().where(role_permissions.c.resource == "saml_config"))
    op.drop_table('saml_configs')
