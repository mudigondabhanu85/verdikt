"""vgs report builder

Ports VGS's real manual-report-builder workflow (curated vulnerability
library, per-Version report drafts with independently-editable selected
vulnerabilities and evidence steps) into Verdikt as native tables,
distinct from the existing decoupled-webhook vgs_configs integration.

Revision ID: 0017_vgs_report_builder
Revises: 0016_org_branding
Create Date: 2026-09-04 00:00:00.000000

"""
import uuid
from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from app.auth.rbac_seed import vgs_vulnerability_resource_grants


# revision identifiers, used by Alembic.
revision: str = '0017_vgs_report_builder'
down_revision: Union[str, None] = '0016_org_branding'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _seed_vgs_vulnerability_permissions() -> None:
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
        for role, resource, action in vgs_vulnerability_resource_grants()
    ]
    op.bulk_insert(role_permissions, rows)


def upgrade() -> None:
    op.create_table(
        'vgs_vulnerability_library',
        sa.Column('org_id', sa.Uuid(), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('cvss_score', sa.String(length=20), nullable=False),
        sa.Column('cvss_vector', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('recommendation', sa.Text(), nullable=False),
        sa.Column('reference', sa.Text(), nullable=False),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'vgs_report_drafts',
        sa.Column('version_id', sa.Uuid(), nullable=False),
        sa.Column('app_title', sa.String(length=500), nullable=False),
        sa.Column('scope', sa.Text(), nullable=False),
        sa.Column('urls', sa.Text(), nullable=False),
        sa.Column('analyst_name', sa.String(length=255), nullable=False),
        sa.Column('requester_name', sa.String(length=255), nullable=False),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['version_id'], ['versions.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('version_id'),
    )

    op.create_table(
        'vgs_report_vulnerabilities',
        sa.Column('report_draft_id', sa.Uuid(), nullable=False),
        sa.Column('library_entry_id', sa.Uuid(), nullable=True),
        sa.Column('order_index', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('cvss_score', sa.String(length=20), nullable=False),
        sa.Column('cvss_vector', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('recommendation', sa.Text(), nullable=False),
        sa.Column('reference', sa.Text(), nullable=False),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['report_draft_id'], ['vgs_report_drafts.id'], ),
        sa.ForeignKeyConstraint(['library_entry_id'], ['vgs_vulnerability_library.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'vgs_evidence_steps',
        sa.Column('report_vulnerability_id', sa.Uuid(), nullable=False),
        sa.Column('step_order', sa.Integer(), nullable=False),
        sa.Column('comment', sa.Text(), nullable=False),
        sa.Column('screenshot_object_keys', sa.JSON(), nullable=False),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['report_vulnerability_id'], ['vgs_report_vulnerabilities.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )

    _seed_vgs_vulnerability_permissions()


def downgrade() -> None:
    role_permissions = sa.table("role_permissions", sa.column("resource", sa.String()))
    op.execute(role_permissions.delete().where(role_permissions.c.resource == "vgs_vulnerability"))
    op.drop_table('vgs_evidence_steps')
    op.drop_table('vgs_report_vulnerabilities')
    op.drop_table('vgs_report_drafts')
    op.drop_table('vgs_vulnerability_library')
